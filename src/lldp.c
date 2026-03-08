/*
 * openuf - lldp.c
 * LLDP: envio de frames raw + lectura de vecinos via lldpctl.
 */
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

static const uint8_t LLDP_DST[6] = {0x01,0x80,0xc2,0x00,0x00,0x0e};
#define LLDP_ETHERTYPE 0x88cc
#define CAP_WLAN_AP    0x0040

static int tlv_write(uint8_t *buf, int pos, int maxlen,
                     int type, const uint8_t *val, int vlen)
{
    if (pos+2+vlen > maxlen) { DLOG("lldp: TLV desbordamiento type=%d", type); return pos; }
    uint16_t hdr = (uint16_t)((type<<9)|(vlen&0x1ff));
    buf[pos++] = (hdr>>8)&0xff;
    buf[pos++] =  hdr    &0xff;
    if (val && vlen>0) { memcpy(buf+pos,val,vlen); pos+=vlen; }
    DLOG("lldp: TLV type=%d len=%d escrito", type, vlen);
    return pos;
}

static int tlv_str(uint8_t *buf, int pos, int maxlen, int type, const char *str)
{
    return tlv_write(buf, pos, maxlen, type, (const uint8_t*)str, (int)strlen(str));
}

static void parse_mac(const char *s, uint8_t out[6])
{
    unsigned int b[6]={0};
    sscanf(s,"%x:%x:%x:%x:%x:%x",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
    for(int i=0;i<6;i++) out[i]=(uint8_t)b[i];
}

int lldp_send_frame(const char *ifname, const char *mac_str,
                    const char *hostname, const char *model_desc, int ttl)
{
    DLOG("lldp: enviando frame en %s (mac=%s hostname=%s ttl=%d)",
         ifname, mac_str, hostname, ttl);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(LLDP_ETHERTYPE));
    if (fd < 0) {
        DLOG("lldp: socket AF_PACKET FALLO errno=%d (%s) — se necesita root/CAP_NET_RAW",
             errno, strerror(errno));
        return -1;
    }
    DLOG("lldp: socket raw abierto fd=%d", fd);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        DLOG("lldp: SIOCGIFINDEX FALLO en %s errno=%d", ifname, errno);
        close(fd); return -1;
    }
    int ifindex = ifr.ifr_ifindex;
    DLOG("lldp: ifindex de %s = %d", ifname, ifindex);

    uint8_t src[6];
    parse_mac(mac_str, src);
    DLOG("lldp: src MAC %02x:%02x:%02x:%02x:%02x:%02x",
         src[0],src[1],src[2],src[3],src[4],src[5]);

    uint8_t frame[1518];
    int pos = 0;

    /* Ethernet header */
    memcpy(frame,   LLDP_DST, 6); pos+=6;
    memcpy(frame+6, src,      6); pos+=6;
    frame[pos++]=0x88; frame[pos++]=0xcc;
    DLOG("lldp: cabecera Ethernet escrita (dst=01:80:c2:00:00:0e type=0x88cc)");

    /* TLV Chassis ID: subtype=4(MAC) */
    { uint8_t v[7]; v[0]=4; memcpy(v+1,src,6); pos=tlv_write(frame,pos,sizeof(frame),1,v,7); }
    /* TLV Port ID: subtype=5(ifname) */
    { size_t nl=strlen(ifname); uint8_t v[64]; v[0]=5; memcpy(v+1,ifname,nl); pos=tlv_write(frame,pos,sizeof(frame),2,v,(int)nl+1); }
    /* TLV TTL */
    { uint8_t v[2]={(uint8_t)(ttl>>8),(uint8_t)(ttl&0xff)}; pos=tlv_write(frame,pos,sizeof(frame),3,v,2); }
    /* TLV System Name */
    if (hostname && hostname[0]) { pos=tlv_str(frame,pos,sizeof(frame),5,hostname); DLOG("lldp: System Name = '%s'", hostname); }
    /* TLV System Description */
    if (model_desc && model_desc[0]) { pos=tlv_str(frame,pos,sizeof(frame),6,model_desc); DLOG("lldp: System Desc = '%s'", model_desc); }
    /* TLV Capabilities: WLAN-AP=0x0040 */
    {
        uint16_t cap = CAP_WLAN_AP;
        uint8_t v[4] = {(uint8_t)(cap>>8),(uint8_t)(cap&0xff),(uint8_t)(cap>>8),(uint8_t)(cap&0xff)};
        pos = tlv_write(frame,pos,sizeof(frame),7,v,4);
        DLOG("lldp: Capabilities WLAN-AP=0x%04x", CAP_WLAN_AP);
    }
    /* TLV End */
    pos = tlv_write(frame,pos,sizeof(frame),0,NULL,0);

    DLOG("lldp: frame construido — %d bytes totales", pos);
    DLOG_HEX("lldp frame", frame, pos < 48 ? pos : 48);

    struct sockaddr_ll sa;
    memset(&sa,0,sizeof(sa));
    sa.sll_family  = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen   = ETH_ALEN;
    memcpy(sa.sll_addr, LLDP_DST, 6);

    ssize_t sent = sendto(fd, frame, pos, 0, (struct sockaddr*)&sa, sizeof(sa));
    close(fd);

    if (sent > 0) DLOG("lldp: frame enviado OK — %zd bytes por %s", sent, ifname);
    else          DLOG("lldp: sendto FALLO en %s errno=%d (%s)", ifname, errno, strerror(errno));

    return (sent > 0) ? 0 : -1;
}

bool lldp_available(void)
{
    bool ok = (access("/usr/sbin/lldpctl", X_OK)==0 ||
               access("/usr/bin/lldpctl",  X_OK)==0);
    DLOG("lldp: lldpctl disponible: %s", ok ? "si" : "no");
    return ok;
}

struct json_object *lldp_read_neighbors(void)
{
    struct json_object *result = json_object_new_array();

    if (!lldp_available()) {
        DLOG("lldp: lldpctl no disponible — retornando tabla vacia");
        return result;
    }

    DLOG("lldp: ejecutando 'lldpctl -f json'");
    FILE *p = popen("lldpctl -f json 2>/dev/null", "r");
    if (!p) { DLOG("lldp: popen FALLO"); return result; }

    char buf[16384]={0};
    size_t total=0, n;
    char tmp[1024];
    while ((n=fread(tmp,1,sizeof(tmp),p))>0 && total+n<sizeof(buf)-1) {
        memcpy(buf+total,tmp,n); total+=n;
    }
    pclose(p);
    DLOG("lldp: lldpctl retorno %zu bytes", total);
    if (!total) { DLOG("lldp: salida vacia"); return result; }

    struct json_object *root = json_tokener_parse(buf);
    if (!root) { DLOG("lldp: JSON de lldpctl invalido"); return result; }

    struct json_object *lldp_o, *iface_arr;
    if (!json_object_object_get_ex(root,"lldp",&lldp_o) ||
        !json_object_object_get_ex(lldp_o,"interface",&iface_arr) ||
        !json_object_is_type(iface_arr,json_type_array)) {
        DLOG("lldp: estructura JSON inesperada en lldpctl");
        goto done;
    }

    int ni = json_object_array_length(iface_arr);
    DLOG("lldp: %d interfaces con vecinos LLDP encontrados", ni);

    for (int i=0; i<ni; i++) {
        struct json_object *iface = json_object_array_get_idx(iface_arr,i);
        if (!iface) continue;

        struct json_object *tmp_o;
        const char *local_port="",*chassis_id="",*sys_name="",*sys_desc="",*port_id="",*port_desc="";

        if (json_object_object_get_ex(iface,"name",&tmp_o)) local_port=json_object_get_string(tmp_o);

        struct json_object *chassis;
        if (json_object_object_get_ex(iface,"chassis",&chassis)) {
            struct json_object *cid,*cname,*cdescr;
            if (json_object_object_get_ex(chassis,"id",&cid)) {
                struct json_object *cv; if (json_object_object_get_ex(cid,"value",&cv)) chassis_id=json_object_get_string(cv);
            }
            if (json_object_object_get_ex(chassis,"name",&cname)) {
                struct json_object *cv; if (json_object_object_get_ex(cname,"value",&cv)) sys_name=json_object_get_string(cv);
            }
            if (json_object_object_get_ex(chassis,"descr",&cdescr)) {
                struct json_object *cv; if (json_object_object_get_ex(cdescr,"value",&cv)) sys_desc=json_object_get_string(cv);
            }
        }

        struct json_object *port;
        if (json_object_object_get_ex(iface,"port",&port)) {
            struct json_object *pid,*pdesc;
            if (json_object_object_get_ex(port,"id",&pid)) {
                struct json_object *pv; if (json_object_object_get_ex(pid,"value",&pv)) port_id=json_object_get_string(pv);
            }
            if (json_object_object_get_ex(port,"descr",&pdesc)) {
                struct json_object *pv; if (json_object_object_get_ex(pdesc,"value",&pv)) port_desc=json_object_get_string(pv);
            }
        }

        DLOG("lldp: vecino[%d] puerto_local=%s chassis=%s sys_name='%s' port_id=%s",
             i, local_port, chassis_id, sys_name, port_id);

        struct json_object *e = json_object_new_object();
        json_object_object_add(e,"local_port", json_object_new_string(local_port));
        json_object_object_add(e,"chassis_id", json_object_new_string(chassis_id));
        json_object_object_add(e,"port_id",    json_object_new_string(port_id));
        json_object_object_add(e,"sys_name",   json_object_new_string(sys_name));
        json_object_object_add(e,"sys_desc",   json_object_new_string(sys_desc));
        json_object_object_add(e,"port_desc",  json_object_new_string(port_desc));
        json_object_object_add(e,"port_table", json_object_new_array());
        json_object_array_add(result, e);
    }

done:
    json_object_put(root);
    DLOG("lldp: tabla de vecinos construida — %d entradas",
         json_object_array_length(result));
    return result;
}
