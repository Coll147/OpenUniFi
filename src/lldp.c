/* openuf - lldp.c — Envío LLDP raw (AF_PACKET) + lectura vecinos (lldpctl) */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <json-c/json.h>
#include "lldp.h"
#include "debug.h"

#define DBG_TAG "lldp"
static const uint8_t LLDP_DST[6]={0x01,0x80,0xc2,0x00,0x00,0x0e};
#define LLDP_ETHERTYPE 0x88cc
#define CAP_WLAN_AP    0x0040

static int tlv_write(uint8_t *buf, int pos, int max, int type, const uint8_t *val, int vlen) {
    if (pos+2+vlen>max){LOG_WARN("TLV tipo=%d no cabe (pos=%d)",type,pos);return pos;}
    uint16_t hdr=(uint16_t)((type<<9)|(vlen&0x1ff));
    buf[pos++]=(hdr>>8)&0xff; buf[pos++]=hdr&0xff;
    if (val&&vlen>0){memcpy(buf+pos,val,vlen);pos+=vlen;}
    LOG_TRACE("  TLV tipo=%-2d len=%-3d",type,vlen);
    return pos;
}
static int tlv_str(uint8_t *b,int p,int m,int t,const char *s){
    return tlv_write(b,p,m,t,(const uint8_t*)s,(int)strlen(s));
}
static void parse_mac(const char *s, uint8_t o[6]) {
    unsigned int b[6]={0};
    sscanf(s,"%x:%x:%x:%x:%x:%x",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
    for(int i=0;i<6;i++) o[i]=(uint8_t)b[i];
}

int lldp_send_frame(const char *ifname, const char *mac_str,
                    const char *hostname, const char *model_desc, int ttl) {
    LOG_DBG("enviando LLDP en %s (hostname='%s' ttl=%d)...", ifname, hostname, ttl);
    int fd=socket(AF_PACKET,SOCK_RAW,htons(LLDP_ETHERTYPE));
    if (fd<0){LOG_TRACE("AF_PACKET en %s: %m (sin CAP_NET_RAW — normal sin root)",ifname);return -1;}
    struct ifreq ifr; memset(&ifr,0,sizeof(ifr)); strncpy(ifr.ifr_name,ifname,IFNAMSIZ-1);
    if (ioctl(fd,SIOCGIFINDEX,&ifr)<0){LOG_ERR("SIOCGIFINDEX(%s): %m",ifname);close(fd);return -1;}
    LOG_TRACE("ifindex(%s)=%d", ifname, ifr.ifr_ifindex);
    uint8_t src[6]; parse_mac(mac_str,src);
    uint8_t frame[1518]; int pos=0;
    memcpy(frame,LLDP_DST,6);pos+=6; memcpy(frame+6,src,6);pos+=6;
    frame[pos++]=0x88; frame[pos++]=0xcc;
    LOG_TRACE("eth header: dst=01:80:c2:00:00:0e src=%s etype=0x88cc", mac_str);
    {uint8_t v[7];v[0]=4;memcpy(v+1,src,6);pos=tlv_write(frame,pos,sizeof(frame),1,v,7);}
    {size_t nl=strlen(ifname);uint8_t v[64];v[0]=5;memcpy(v+1,ifname,nl);pos=tlv_write(frame,pos,sizeof(frame),2,v,(int)nl+1);}
    {uint8_t v[2]={(uint8_t)(ttl>>8),(uint8_t)(ttl&0xff)};pos=tlv_write(frame,pos,sizeof(frame),3,v,2);}
    if (hostname&&hostname[0]){LOG_TRACE("  SysName: '%s'",hostname);pos=tlv_str(frame,pos,sizeof(frame),5,hostname);}
    if (model_desc&&model_desc[0]){LOG_TRACE("  SysDesc: '%s'",model_desc);pos=tlv_str(frame,pos,sizeof(frame),6,model_desc);}
    {uint16_t cap=CAP_WLAN_AP;uint8_t v[4]={(cap>>8)&0xff,cap&0xff,(cap>>8)&0xff,cap&0xff};
     LOG_TRACE("  Capabilities: 0x%04x (WLAN-AP)",cap);
     pos=tlv_write(frame,pos,sizeof(frame),7,v,4);}
    pos=tlv_write(frame,pos,sizeof(frame),0,NULL,0);
    LOG_DBG("frame LLDP: %d bytes totales", pos);
    DBG_HEX("frame LLDP completo", frame, pos);
    struct sockaddr_ll sa; memset(&sa,0,sizeof(sa));
    sa.sll_family=AF_PACKET; sa.sll_ifindex=ifr.ifr_ifindex;
    sa.sll_halen=ETH_ALEN; memcpy(sa.sll_addr,LLDP_DST,6);
    ssize_t sent=sendto(fd,frame,pos,0,(struct sockaddr*)&sa,sizeof(sa));
    close(fd);
    if (sent<0){LOG_ERR("sendto LLDP en %s: %m",ifname);return -1;}
    LOG_DBG("LLDP enviado en %s: %zd bytes", ifname, sent);
    return 0;
}

bool lldp_available(void) {
    bool ok=(access("/usr/sbin/lldpctl",X_OK)==0||access("/usr/bin/lldpctl",X_OK)==0);
    LOG_TRACE("lldpctl: %s", ok?"disponible":"no encontrado");
    return ok;
}

struct json_object *lldp_read_neighbors(void) {
    struct json_object *result=json_object_new_array();
    if (!lldp_available()){LOG_TRACE("lldpctl no disponible — lldp_table vacía");return result;}
    LOG_DBG("ejecutando lldpctl -f json ...");
    FILE *p=popen("lldpctl -f json 2>/dev/null","r");
    if (!p){LOG_WARN("popen(lldpctl): %m");return result;}
    char buf[16384]={0}; size_t total=0,n; char tmp[1024];
    while ((n=fread(tmp,1,sizeof(tmp),p))>0&&total+n<sizeof(buf)-1){memcpy(buf+total,tmp,n);total+=n;}
    pclose(p);
    if (!total){LOG_DBG("lldpctl: sin datos (no hay vecinos)");return result;}
    LOG_DBG("lldpctl: %zu bytes JSON", total);
    LOG_TRACE("lldpctl output:\n%s", buf);
    struct json_object *root=json_tokener_parse(buf);
    if (!root){LOG_ERR("lldpctl: JSON inválido");return result;}
    struct json_object *lo,*ia;
    if (!json_object_object_get_ex(root,"lldp",&lo)) goto done;
    if (!json_object_object_get_ex(lo,"interface",&ia)) goto done;
    if (!json_object_is_type(ia,json_type_array)) goto done;
    int ni=json_object_array_length(ia);
    LOG_DBG("lldp: %d interfaces con vecinos", ni);
    for (int i=0;i<ni;i++) {
        struct json_object *iface=json_object_array_get_idx(ia,i); if(!iface)continue;
        struct json_object *t;
        const char *lp="",*cid="",*sn="",*sd="",*pid="",*pd="";
        if (json_object_object_get_ex(iface,"name",&t)) lp=json_object_get_string(t);
        struct json_object *ch;
        if (json_object_object_get_ex(iface,"chassis",&ch)){
            struct json_object *v;
            if (json_object_object_get_ex(ch,"id",&v)&&json_object_object_get_ex(v,"value",&t))   cid=json_object_get_string(t);
            if (json_object_object_get_ex(ch,"name",&v)&&json_object_object_get_ex(v,"value",&t)) sn =json_object_get_string(t);
            if (json_object_object_get_ex(ch,"descr",&v)&&json_object_object_get_ex(v,"value",&t))sd =json_object_get_string(t);
        }
        struct json_object *po;
        if (json_object_object_get_ex(iface,"port",&po)){
            struct json_object *v;
            if (json_object_object_get_ex(po,"id",&v)&&json_object_object_get_ex(v,"value",&t))    pid=json_object_get_string(t);
            if (json_object_object_get_ex(po,"descr",&v)&&json_object_object_get_ex(v,"value",&t)) pd =json_object_get_string(t);
        }
        LOG_DBG("  vecino[%d] puerto=%-6s chassis=%s sys='%s' port=%s",i,lp,cid,sn,pid);
        struct json_object *e=json_object_new_object();
        json_object_object_add(e,"local_port",json_object_new_string(lp));
        json_object_object_add(e,"chassis_id",json_object_new_string(cid));
        json_object_object_add(e,"port_id",   json_object_new_string(pid));
        json_object_object_add(e,"sys_name",  json_object_new_string(sn));
        json_object_object_add(e,"sys_desc",  json_object_new_string(sd));
        json_object_object_add(e,"port_desc", json_object_new_string(pd));
        json_object_object_add(e,"port_table",json_object_new_array());
        json_object_array_add(result,e);
    }
done:
    json_object_put(root);
    LOG_DBG("lldp_table: %d vecinos",json_object_array_length(result));
    return result;
}
