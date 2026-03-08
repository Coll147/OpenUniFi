/* openuf - clients.c — iw station dump, /proc/net/arp, /tmp/dhcp.leases */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <json-c/json.h>
#include "clients.h"
#include "debug.h"

#define DBG_TAG "clients"

static void mac_lower(const char *src, char *dst, size_t sz) {
    for (size_t i=0; src[i]&&i<sz-1; i++) dst[i]=tolower((unsigned char)src[i]);
    dst[strlen(src)<sz?strlen(src):sz-1]='\0';
}

int clients_mac_to_ip(const char *mac, char *ip_out, size_t sz) {
    ip_out[0]='\0';
    LOG_TRACE("ARP lookup: %s", mac);
    FILE *f=fopen("/proc/net/arp","r");
    if (!f) { LOG_ERR("no se pudo abrir /proc/net/arp"); return -1; }
    char line[256]; fgets(line,sizeof(line),f);
    char ml[32]={0}; mac_lower(mac,ml,sizeof(ml));
    int found=0;
    while (fgets(line,sizeof(line),f)) {
        char ip[64],hwt[16],flags[16],hw[32],mask[16],dev[32];
        if (sscanf(line,"%63s %15s %15s %31s %15s %31s",ip,hwt,flags,hw,mask,dev)!=6) continue;
        if (strcmp(flags,"0x2")!=0) { LOG_TRACE("  ARP %s flags=%s (incompleta)",hw,flags); continue; }
        char hl[32]={0}; mac_lower(hw,hl,sizeof(hl));
        if (strcmp(ml,hl)==0) {
            strncpy(ip_out,ip,sz-1);
            LOG_TRACE("  ARP: %s → %s (dev=%s)", mac, ip, dev);
            found=1; break;
        }
    }
    fclose(f);
    if (!found) LOG_TRACE("  ARP: %s no encontrado", mac);
    return found?0:-1;
}

int clients_mac_to_hostname(const char *mac, char *out, size_t sz) {
    out[0]='\0';
    static const char *files[]={"/tmp/dhcp.leases","/var/lib/misc/dnsmasq.leases",NULL};
    char ml[32]={0}; mac_lower(mac,ml,sizeof(ml));
    for (int fi=0; files[fi]; fi++) {
        FILE *f=fopen(files[fi],"r");
        if (!f) { LOG_TRACE("lease %s: no existe",files[fi]); continue; }
        LOG_TRACE("buscando hostname de %s en %s...", mac, files[fi]);
        char line[256];
        while (fgets(line,sizeof(line),f)) {
            long ts; char lm[32],lip[64],lh[64],lcid[64];
            if (sscanf(line,"%ld %31s %63s %63s %63s",&ts,lm,lip,lh,lcid)<4) continue;
            char ll[32]={0}; mac_lower(lm,ll,sizeof(ll));
            if (strcmp(ml,ll)==0&&strcmp(lh,"*")!=0) {
                strncpy(out,lh,sz-1);
                LOG_TRACE("  lease: %s → %s (IP=%s)", mac, lh, lip);
                fclose(f); return 0;
            }
        }
        fclose(f);
    }
    LOG_TRACE("hostname de %s no encontrado", mac);
    return -1;
}

static long parse_rate_kbps(const char *s) {
    float r=0; sscanf(s,"%f MBit/s",&r); return (long)(r*1000.0f);
}

int clients_read_wifi(const char *wlan_iface, const char *radio_band,
                      int channel, sta_info_t *out, int max_out) {
    char cmd[128];
    snprintf(cmd,sizeof(cmd),"iw dev %s station dump 2>/dev/null",wlan_iface);
    LOG_DBG("ejecutando: %s", cmd);
    FILE *p=popen(cmd,"r"); if(!p){LOG_ERR("popen falló: '%s'",cmd);return 0;}
    int count=0; sta_info_t *cur=NULL; char line[256];
    while (fgets(line,sizeof(line),p)) {
        line[strcspn(line,"\r\n")]='\0';
        char mac[32],on[32];
        if (sscanf(line,"Station %31s (on %31[^)])",mac,on)==2) {
            if (count>=max_out){LOG_WARN("límite MAX_STA=%d alcanzado",max_out);break;}
            cur=&out[count++]; memset(cur,0,sizeof(*cur));
            strncpy(cur->mac,mac,sizeof(cur->mac)-1);
            strncpy(cur->vap_name,wlan_iface,sizeof(cur->vap_name)-1);
            strncpy(cur->radio,radio_band,sizeof(cur->radio)-1);
            cur->channel=channel; cur->noise=-95;
            LOG_TRACE("  sta[%d]: MAC=%s (en %s)", count-1, mac, on);
            continue;
        }
        if (!cur) continue;
        long long llv; int sig,upt; char rest[128];
        if (sscanf(line," rx bytes: %lld",&llv)==1) cur->rx_bytes=llv;
        if (sscanf(line," tx bytes: %lld",&llv)==1) cur->tx_bytes=llv;
        if (sscanf(line," rx packets: %lld",&llv)==1) cur->rx_packets=llv;
        if (sscanf(line," tx packets: %lld",&llv)==1) cur->tx_packets=llv;
        if (sscanf(line," signal: %d",&sig)==1) cur->signal=sig;
        if (sscanf(line," tx bitrate: %127[^\n]",rest)==1) cur->tx_rate=parse_rate_kbps(rest);
        if (sscanf(line," rx bitrate: %127[^\n]",rest)==1) cur->rx_rate=parse_rate_kbps(rest);
        if (sscanf(line," connected time: %d seconds",&upt)==1) cur->uptime=upt;
    }
    pclose(p);
    LOG_DBG("%s: %d clientes (banda=%s ch=%d)", wlan_iface, count, radio_band, channel);
    for (int i=0; i<count; i++) {
        sta_info_t *s=&out[i];
        clients_mac_to_ip(s->mac,s->ip,sizeof(s->ip));
        clients_mac_to_hostname(s->mac,s->hostname,sizeof(s->hostname));
        if (!s->hostname[0]) strncpy(s->hostname,s->mac,sizeof(s->hostname)-1);
        s->rssi=s->signal-s->noise; if(s->rssi<0)s->rssi=0;
        int ccq=(s->signal+90)*25; s->ccq=(ccq<0)?0:(ccq>1000)?1000:ccq;
        LOG_DBG("  [%d] %-17s %-15s %-20s sig=%-4d rssi=%2d tx=%ldkbps rx=%ldkbps ccq=%d up=%ds",
                i, s->mac, s->ip[0]?s->ip:"(sin IP)",
                s->hostname, s->signal, s->rssi,
                s->tx_rate, s->rx_rate, s->ccq, s->uptime);
    }
    return count;
}

struct json_object *clients_build_sta_table(const char *wlan_iface,
                                            const char *radio_band,
                                            int channel, const char *vap_name) {
    LOG_DBG("sta_table para VAP='%s' iface=%s banda=%s ch=%d",
            vap_name?vap_name:wlan_iface, wlan_iface, radio_band, channel);
    sta_info_t stas[MAX_STA];
    int n=clients_read_wifi(wlan_iface,radio_band,channel,stas,MAX_STA);
    struct json_object *arr=json_object_new_array();
    for (int i=0; i<n; i++) {
        sta_info_t *s=&stas[i];
        struct json_object *o=json_object_new_object();
        json_object_object_add(o,"mac",        json_object_new_string(s->mac));
        json_object_object_add(o,"ip",         json_object_new_string(s->ip));
        json_object_object_add(o,"hostname",   json_object_new_string(s->hostname));
        json_object_object_add(o,"signal",     json_object_new_int(s->signal));
        json_object_object_add(o,"rssi",       json_object_new_int(s->rssi));
        json_object_object_add(o,"noise",      json_object_new_int(s->noise));
        json_object_object_add(o,"tx_rate",    json_object_new_int64(s->tx_rate));
        json_object_object_add(o,"rx_rate",    json_object_new_int64(s->rx_rate));
        json_object_object_add(o,"tx_bytes",   json_object_new_int64(s->tx_bytes));
        json_object_object_add(o,"rx_bytes",   json_object_new_int64(s->rx_bytes));
        json_object_object_add(o,"tx_packets", json_object_new_int64(s->tx_packets));
        json_object_object_add(o,"rx_packets", json_object_new_int64(s->rx_packets));
        json_object_object_add(o,"uptime",     json_object_new_int(s->uptime));
        json_object_object_add(o,"radio",      json_object_new_string(s->radio));
        json_object_object_add(o,"channel",    json_object_new_int(s->channel));
        json_object_object_add(o,"vap_name",   json_object_new_string(vap_name?vap_name:wlan_iface));
        json_object_object_add(o,"is_11r",     json_object_new_boolean(s->is_11r));
        json_object_object_add(o,"ccq",        json_object_new_int(s->ccq));
        json_object_object_add(o,"idletime",   json_object_new_int(0));
        json_object_array_add(arr,o);
    }
    LOG_DBG("sta_table: %d entradas JSON", n);
    return arr;
}
