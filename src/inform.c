/*
 * openuf - inform.c
 * Protocolo Inform UniFi — cifrado AES-128-CBC, JSON, HTTP POST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <json-c/json.h>

#include "inform.h"
#include "crypto.h"
#include "http.h"
#include "wlan.h"
#include "state.h"
#include "config.h"
#include "sysinfo.h"
#include "clients.h"
#include "lldp.h"
#include "debug.h"

/* ─── Big-endian helpers ─────────────────────────────────────────── */
static void put32be(unsigned char *p, uint32_t v)
{ p[0]=(v>>24)&0xff;p[1]=(v>>16)&0xff;p[2]=(v>>8)&0xff;p[3]=v&0xff; }
static void put16be(unsigned char *p, uint16_t v)
{ p[0]=(v>>8)&0xff;p[1]=v&0xff; }
static uint32_t get32be(const unsigned char *p)
{ return((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3]; }
static uint16_t get16be(const unsigned char *p)
{ return((uint16_t)p[0]<<8)|(uint16_t)p[1]; }

/* ═══ sys_stats ═══════════════════════════════════════════════════ */
static struct json_object *build_sys_stats(void)
{
    DLOG("inform: construyendo sys_stats");
    struct json_object *o = json_object_new_object();

    mem_stats_t mem;
    if (sysinfo_mem(&mem) == 0) {
        long used_kb = mem.total_kb - mem.free_kb - mem.buffer_kb - mem.cached_kb;
        if (used_kb < 0) used_kb = 0;
        DLOG("inform: sys_stats mem total=%ldkB used=%ldkB", mem.total_kb, used_kb);
        json_object_object_add(o,"mem_total",  json_object_new_int64(mem.total_kb*1024LL));
        json_object_object_add(o,"mem_used",   json_object_new_int64(used_kb*1024LL));
        json_object_object_add(o,"mem_buffer", json_object_new_int64(mem.buffer_kb*1024LL));
    } else {
        DLOG("inform: sys_stats mem FALLO — usando ceros");
        json_object_object_add(o,"mem_total",  json_object_new_int(0));
        json_object_object_add(o,"mem_used",   json_object_new_int(0));
        json_object_object_add(o,"mem_buffer", json_object_new_int(0));
    }

    int cpu = sysinfo_cpu_percent();
    DLOG("inform: sys_stats cpu=%d%%", cpu);
    json_object_object_add(o,"cpu", json_object_new_int(cpu));
    return o;
}

/* ═══ if_table ════════════════════════════════════════════════════ */
static struct json_object *build_if_table(const uf_model_t *m, const openuf_state_t *st)
{
    DLOG("inform: construyendo if_table (%d interfaces)", m->port_table_len);
    struct json_object *arr = json_object_new_array();

    for (int i=0; i<m->port_table_len; i++) {
        const char *ifname = m->port_table[i].ifname;
        DLOG("inform: if_table[%d] ifname=%s", i, ifname);
        iface_stats_t stats;
        sysinfo_iface(ifname, &stats);

        DLOG("inform:   up=%d speed=%dMbps rx=%lldB tx=%lldB",
             stats.up, stats.speed, stats.rx_bytes, stats.tx_bytes);

        struct json_object *o = json_object_new_object();
        json_object_object_add(o,"name",        json_object_new_string(ifname));
        json_object_object_add(o,"mac",         json_object_new_string(stats.mac[0]?stats.mac:st->mac));
        json_object_object_add(o,"ip",          json_object_new_string(stats.ip[0]?stats.ip:st->ip));
        json_object_object_add(o,"up",          json_object_new_boolean(stats.up));
        json_object_object_add(o,"speed",       json_object_new_int(stats.speed>0?stats.speed:1000));
        json_object_object_add(o,"full_duplex", json_object_new_boolean(stats.full_duplex));
        json_object_object_add(o,"num_port",    json_object_new_int(1));
        json_object_object_add(o,"rx_bytes",    json_object_new_int64(stats.rx_bytes));
        json_object_object_add(o,"tx_bytes",    json_object_new_int64(stats.tx_bytes));
        json_object_object_add(o,"rx_packets",  json_object_new_int64(stats.rx_packets));
        json_object_object_add(o,"tx_packets",  json_object_new_int64(stats.tx_packets));
        json_object_object_add(o,"rx_errors",   json_object_new_int64(stats.rx_errors));
        json_object_object_add(o,"tx_errors",   json_object_new_int64(stats.tx_errors));
        json_object_object_add(o,"rx_dropped",  json_object_new_int64(stats.rx_dropped));
        json_object_object_add(o,"tx_dropped",  json_object_new_int64(stats.tx_dropped));
        json_object_object_add(o,"rx_multicast",json_object_new_int64(stats.rx_multicast));
        json_object_array_add(arr, o);
    }
    return arr;
}

/* ═══ radio_table (estatico) ══════════════════════════════════════ */
static void build_radio_table(struct json_object *root, const uf_model_t *m)
{
    DLOG("inform: construyendo radio_table (%d radios)", m->radio_table_len);
    struct json_object *arr = json_object_new_array();
    for (int i=0; i<m->radio_table_len; i++) {
        const uf_radio_t *r = &m->radio_table[i];
        DLOG("inform: radio_table[%d] name=%s radio=%s ch=%d ht=%s pwr=%d he=%d",
             i, r->name, r->radio, r->channel, r->ht, r->tx_power, r->he_enabled);
        struct json_object *o = json_object_new_object();
        json_object_object_add(o,"name",           json_object_new_string(r->name));
        json_object_object_add(o,"radio",          json_object_new_string(r->radio));
        json_object_object_add(o,"channel",        json_object_new_int(r->channel));
        json_object_object_add(o,"ht",             json_object_new_string(r->ht));
        json_object_object_add(o,"min_txpower",    json_object_new_int(r->min_txpower));
        json_object_object_add(o,"max_txpower",    json_object_new_int(r->max_txpower));
        json_object_object_add(o,"nss",            json_object_new_int(r->nss));
        json_object_object_add(o,"tx_power",       json_object_new_int(r->tx_power));
        json_object_object_add(o,"radio_caps",     json_object_new_int(r->radio_caps));
        json_object_object_add(o,"antenna_gain",   json_object_new_int(r->antenna_gain));
        json_object_object_add(o,"he_enabled",     json_object_new_boolean(r->he_enabled));
        json_object_object_add(o,"builtin_antenna",json_object_new_boolean(true));
        json_object_object_add(o,"builtin_ant_gain",json_object_new_int(0));
        json_object_array_add(arr, o);
    }
    json_object_object_add(root, "radio_table", arr);
}

/* ═══ radio_table_stats (dinamico) ═══════════════════════════════ */
static struct json_object *build_radio_table_stats(const uf_model_t *m)
{
    DLOG("inform: construyendo radio_table_stats (%d radios)", m->radio_map_len);
    struct json_object *arr = json_object_new_array();

    for (int i=0; i<m->radio_map_len; i++) {
        const uf_radio_map_t *rm = &m->radio_map[i];
        char wlan_iface[32];
        int ridx=0;
        sscanf(rm->device,"radio%d",&ridx);
        snprintf(wlan_iface,sizeof(wlan_iface),"wlan%d",ridx);

        const char *radio_name = (i<m->radio_table_len)?m->radio_table[i].name:wlan_iface;
        int def_ch  = (i<m->radio_table_len)?m->radio_table[i].channel:6;
        int def_pwr = (i<m->radio_table_len)?m->radio_table[i].tx_power:20;

        DLOG("inform: radio_stats[%d] device=%s wlan=%s name=%s",
             i, rm->device, wlan_iface, radio_name);

        radio_stats_t rs;
        if (sysinfo_radio(wlan_iface,&rs)!=0) {
            DLOG("inform: sysinfo_radio FALLO en %s — usando defaults", wlan_iface);
            memset(&rs,0,sizeof(rs)); rs.noise=-95;
        }
        DLOG("inform: radio_stats[%d] ch=%d pwr=%d cu=%d%% tx=%d%% rx=%d%% num_sta=%d noise=%d",
             i, rs.channel?rs.channel:def_ch, rs.tx_power?rs.tx_power:def_pwr,
             rs.cu_total, rs.cu_self_tx, rs.cu_self_rx, rs.num_sta, rs.noise);

        struct json_object *o = json_object_new_object();
        json_object_object_add(o,"name",      json_object_new_string(radio_name));
        json_object_object_add(o,"channel",   json_object_new_int(rs.channel?rs.channel:def_ch));
        json_object_object_add(o,"tx_power",  json_object_new_int(rs.tx_power?rs.tx_power:def_pwr));
        json_object_object_add(o,"cu_self_tx",json_object_new_int(rs.cu_self_tx));
        json_object_object_add(o,"cu_self_rx",json_object_new_int(rs.cu_self_rx));
        json_object_object_add(o,"cu_total",  json_object_new_int(rs.cu_total));
        json_object_object_add(o,"num_sta",   json_object_new_int(rs.num_sta));
        json_object_object_add(o,"noise",     json_object_new_int(rs.noise));
        json_object_array_add(arr,o);
    }
    return arr;
}

/* ═══ port_table ══════════════════════════════════════════════════ */
static void build_port_table(struct json_object *root, const uf_model_t *m)
{
    DLOG("inform: construyendo port_table (%d puertos)", m->port_table_len);
    struct json_object *arr = json_object_new_array();
    for (int i=0; i<m->port_table_len; i++) {
        const uf_port_t *pt = &m->port_table[i];
        iface_stats_t stats;
        sysinfo_iface(pt->ifname, &stats);
        DLOG("inform: port[%d] %s up=%d speed=%d poe=%d",
             i, pt->ifname, stats.up, stats.speed>0?stats.speed:pt->speed, pt->poe_caps);

        struct json_object *o = json_object_new_object();
        json_object_object_add(o,"ifname",      json_object_new_string(pt->ifname));
        json_object_object_add(o,"name",        json_object_new_string(pt->name));
        json_object_object_add(o,"port_idx",    json_object_new_int(pt->port_idx));
        json_object_object_add(o,"poe_caps",    json_object_new_int(pt->poe_caps));
        json_object_object_add(o,"media",       json_object_new_string(pt->media));
        json_object_object_add(o,"speed",       json_object_new_int(stats.speed>0?stats.speed:pt->speed));
        json_object_object_add(o,"up",          json_object_new_boolean(stats.up));
        json_object_object_add(o,"is_uplink",   json_object_new_boolean(pt->is_uplink));
        json_object_object_add(o,"full_duplex", json_object_new_boolean(stats.full_duplex));
        json_object_object_add(o,"rx_bytes",    json_object_new_int64(stats.rx_bytes));
        json_object_object_add(o,"tx_bytes",    json_object_new_int64(stats.tx_bytes));
        json_object_array_add(arr,o);
    }
    json_object_object_add(root,"port_table",arr);
}

static void build_eth_table(struct json_object *root, const uf_model_t *m)
{
    DLOG("inform: construyendo eth_table (%d entradas)", m->ethernet_table_len);
    struct json_object *arr = json_object_new_array();
    for (int i=0; i<m->ethernet_table_len; i++) {
        const uf_eth_entry_t *e=&m->ethernet_table[i];
        DLOG("inform: eth[%d] name=%s num_port=%d", i, e->name, e->num_port);
        struct json_object *o=json_object_new_object();
        json_object_object_add(o,"name",     json_object_new_string(e->name));
        json_object_object_add(o,"num_port", json_object_new_int(e->num_port));
        json_object_array_add(arr,o);
    }
    json_object_object_add(root,"ethernet_table",arr);
}

/* ═══ vap_table con sta_table anidado ════════════════════════════ */
static struct json_object *build_vap_table(const uf_model_t *m)
{
    DLOG("inform: construyendo vap_table");
    struct json_object *uci_vaps = wlan_get_vap_table(m);
    int nvaps = json_object_array_length(uci_vaps);
    DLOG("inform: %d VAPs en UCI", nvaps);

    struct json_object *arr = json_object_new_array();

    for (int i=0; i<nvaps; i++) {
        struct json_object *vap = json_object_array_get_idx(uci_vaps,i);
        struct json_object *v;

        const char *essid="", *vap_name="", *radio="ng", *bssid="00:00:00:00:00:00";
        if (json_object_object_get_ex(vap,"essid", &v)) essid    = json_object_get_string(v);
        if (json_object_object_get_ex(vap,"name",  &v)) vap_name = json_object_get_string(v);
        if (json_object_object_get_ex(vap,"radio", &v)) radio    = json_object_get_string(v);
        if (json_object_object_get_ex(vap,"bssid", &v)) bssid    = json_object_get_string(v);

        DLOG("inform: vap[%d] essid='%s' bssid=%s radio=%s name=%s",
             i, essid, bssid, radio, vap_name);

        /* Mapear banda → interfaz wlan */
        char wlan_iface[32]="wlan0";
        int channel=6;
        for (int j=0; j<m->radio_map_len; j++) {
            if (strcmp(m->radio_map[j].band,radio)==0) {
                int idx=0; sscanf(m->radio_map[j].device,"radio%d",&idx);
                snprintf(wlan_iface,sizeof(wlan_iface),"wlan%d",idx);
                radio_stats_t rs;
                if (sysinfo_radio(wlan_iface,&rs)==0 && rs.channel) channel=rs.channel;
                else if (idx<m->radio_table_len) channel=m->radio_table[idx].channel;
                DLOG("inform: vap[%d] mapeado a device=%s wlan=%s canal=%d",
                     i, m->radio_map[j].device, wlan_iface, channel);
                break;
            }
        }

        iface_stats_t iface_st;
        sysinfo_iface(wlan_iface,&iface_st);

        DLOG("inform: vap[%d] leyendo clientes en %s (band=%s ch=%d)",
             i, wlan_iface, radio, channel);
        struct json_object *sta_tbl = clients_build_sta_table(wlan_iface,radio,channel,vap_name);
        int num_sta = json_object_array_length(sta_tbl);
        DLOG("inform: vap[%d] '%s' — %d clientes, rx=%lldB tx=%lldB",
             i, essid, num_sta, iface_st.rx_bytes, iface_st.tx_bytes);

        int tx_pwr=20;
        radio_stats_t rs2;
        if (sysinfo_radio(wlan_iface,&rs2)==0 && rs2.tx_power) tx_pwr=rs2.tx_power;

        struct json_object *o=json_object_new_object();
        json_object_object_add(o,"essid",      json_object_new_string(essid));
        json_object_object_add(o,"bssid",      json_object_new_string(bssid));
        json_object_object_add(o,"name",       json_object_new_string(vap_name));
        json_object_object_add(o,"radio",      json_object_new_string(radio));
        json_object_object_add(o,"up",         json_object_new_boolean(iface_st.up));
        json_object_object_add(o,"channel",    json_object_new_int(channel));
        json_object_object_add(o,"tx_power",   json_object_new_int(tx_pwr));
        json_object_object_add(o,"num_sta",    json_object_new_int(num_sta));
        json_object_object_add(o,"rx_bytes",   json_object_new_int64(iface_st.rx_bytes));
        json_object_object_add(o,"tx_bytes",   json_object_new_int64(iface_st.tx_bytes));
        json_object_object_add(o,"rx_packets", json_object_new_int64(iface_st.rx_packets));
        json_object_object_add(o,"tx_packets", json_object_new_int64(iface_st.tx_packets));
        json_object_object_add(o,"rx_errors",  json_object_new_int64(iface_st.rx_errors));
        json_object_object_add(o,"tx_errors",  json_object_new_int64(iface_st.tx_errors));
        json_object_object_add(o,"rx_dropped", json_object_new_int64(iface_st.rx_dropped));
        json_object_object_add(o,"tx_dropped", json_object_new_int64(iface_st.tx_dropped));
        json_object_object_add(o,"id",         json_object_new_string("user"));
        json_object_object_add(o,"usage",      json_object_new_string("user"));
        json_object_object_add(o,"ccq",        json_object_new_int(0));
        json_object_object_add(o,"sta_table",  sta_tbl);
        json_object_array_add(arr,o);
    }
    json_object_put(uci_vaps);
    return arr;
}

/* ═══ build_payload ═══════════════════════════════════════════════ */
static char *build_payload(const openuf_state_t *st, const uf_model_t *m, long uptime)
{
    DLOG("inform: build_payload — modelo=%s mac=%s ip=%s uptime=%lds adopted=%s",
         m->model, st->mac, st->ip, uptime, st->adopted?"SI":"NO");

    /* MAC sin colones → serial uppercase */
    char mac_clean[32]={0};
    {
        const char *s=st->mac; int j=0;
        for(int i=0;s[i]&&j<12;i++) if(s[i]!=':'){
            char c=s[i]; if(c>='a'&&c<='f') c-=32; mac_clean[j++]=c;
        }
    }
    DLOG("inform: serial = %s", mac_clean);

    char fw_version[64];
    snprintf(fw_version,sizeof(fw_version),"%s%s",m->fw_pre,m->fw_ver);
    DLOG("inform: fw_version = %s", fw_version);

    char inform_url_buf[256];
    if (st->inform_url[0]) strncpy(inform_url_buf,st->inform_url,sizeof(inform_url_buf)-1);
    else snprintf(inform_url_buf,sizeof(inform_url_buf),"http://unifi:%d%s",INFORM_PORT,INFORM_PATH);
    DLOG("inform: inform_url = %s", inform_url_buf);

    struct json_object *root = json_object_new_object();

    /* Identidad */
    json_object_object_add(root,"mac",           json_object_new_string(st->mac));
    json_object_object_add(root,"serial",        json_object_new_string(mac_clean));
    json_object_object_add(root,"model",         json_object_new_string(m->model));
    json_object_object_add(root,"model_display", json_object_new_string(m->model_display));
    json_object_object_add(root,"display_name",  json_object_new_string(m->display_name));
    json_object_object_add(root,"board_rev",     json_object_new_int(m->board_rev));
    json_object_object_add(root,"version",       json_object_new_string(fw_version));
    json_object_object_add(root,"bootrom_version",json_object_new_string("openuf-v0.4"));
    json_object_object_add(root,"required_version",json_object_new_string("2.4.4"));
    json_object_object_add(root,"ip",            json_object_new_string(st->ip));
    json_object_object_add(root,"hostname",      json_object_new_string(st->hostname[0]?st->hostname:m->display_name));
    json_object_object_add(root,"inform_url",    json_object_new_string(inform_url_buf));
    json_object_object_add(root,"uptime",        json_object_new_int64(uptime));
    json_object_object_add(root,"time",          json_object_new_int64((long long)uptime));
    json_object_object_add(root,"state",         json_object_new_int(st->adopted?4:1));
    json_object_object_add(root,"default",       json_object_new_boolean(!st->adopted));
    json_object_object_add(root,"cfgversion",    json_object_new_string(st->cfgversion));
    json_object_object_add(root,"x_authkey",     json_object_new_string(st->adopted?st->authkey:DEFAULT_AUTH_KEY));
    json_object_object_add(root,"_default_key",  json_object_new_boolean(!st->adopted));
    json_object_object_add(root,"has_eth1",      json_object_new_boolean(m->has_eth1));
    json_object_object_add(root,"isolated",      json_object_new_boolean(false));
    json_object_object_add(root,"locating",      json_object_new_boolean(false));
    json_object_object_add(root,"uplink",        json_object_new_string("eth0"));
    json_object_object_add(root,"country_code",  json_object_new_int(0));
    DLOG("inform: campos de identidad escritos");

    /* Telemetria */
    DLOG("inform: construyendo sys_stats...");
    json_object_object_add(root,"sys_stats",       build_sys_stats());
    DLOG("inform: construyendo if_table...");
    json_object_object_add(root,"if_table",        build_if_table(m,st));
    DLOG("inform: construyendo radio_table...");
    build_radio_table(root,m);
    DLOG("inform: construyendo radio_table_stats...");
    json_object_object_add(root,"radio_table_stats",build_radio_table_stats(m));
    DLOG("inform: construyendo port_table...");
    build_port_table(root,m);
    build_eth_table(root,m);
    DLOG("inform: construyendo vap_table...");
    json_object_object_add(root,"vap_table",       build_vap_table(m));
    DLOG("inform: construyendo lldp_table...");
    json_object_object_add(root,"lldp_table",      lldp_read_neighbors());
    json_object_object_add(root,"bytes_r",   json_object_new_int(0));
    json_object_object_add(root,"bytes_d",   json_object_new_int(0));
    json_object_object_add(root,"num_sta",   json_object_new_int(0));

    const char *s = json_object_to_json_string(root);
    size_t json_len = strlen(s);
    DLOG("inform: payload JSON listo — %zu bytes", json_len);
    DLOG("inform: payload (primeros 200 chars): %.200s", s);
    char *copy = strdup(s);
    json_object_put(root);
    return copy;
}

/* ═══ Paquete binario TNBU ════════════════════════════════════════ */
static unsigned char *build_packet(const char *mac_hex, const char *key_hex,
                                   const char *payload, size_t *out_len)
{
    DLOG("inform: build_packet — mac=%.12s key=%.8s...", mac_hex, key_hex);

    unsigned char iv_hex[33]={0};
    if (crypto_random_hex(iv_hex,16)!=0) { DLOG("inform: random IV FALLO"); return NULL; }
    DLOG("inform: IV generado: %s", iv_hex);

    size_t pl_len=strlen(payload);
    unsigned char *enc=malloc(pl_len+32);
    if (!enc) { DLOG("inform: build_packet OOM"); return NULL; }

    DLOG("inform: cifrando %zu bytes de payload...", pl_len);
    int enc_len=crypto_encrypt(key_hex,(char*)iv_hex,(const unsigned char*)payload,pl_len,enc);
    if (enc_len<0) { DLOG("inform: cifrado FALLO"); free(enc); return NULL; }
    DLOG("inform: cifrado OK — enc_len=%d bytes", enc_len);

    unsigned char mac_bin[6];
    crypto_hex2bin(mac_hex,mac_bin,6);

    size_t pkt_len=4+4+6+2+16+4+4+enc_len;
    DLOG("inform: construccion paquete TNBU — total=%zu bytes (4+4+6+2+16+4+4+%d)",
         pkt_len, enc_len);
    unsigned char *pkt=malloc(pkt_len);
    if (!pkt) { DLOG("inform: pkt malloc FALLO"); free(enc); return NULL; }

    unsigned char *p=pkt;
    memcpy(p,INFORM_MAGIC,4);           p+=4;  DLOG("inform: magic='TNBU' escrito");
    put32be(p,INFORM_PKT_VERSION);      p+=4;  DLOG("inform: pkt_ver=%u", INFORM_PKT_VERSION);
    memcpy(p,mac_bin,6);                p+=6;  DLOG("inform: MAC escrita en cabecera");
    put16be(p,INFORM_FLAG_ENCRYPTED);   p+=2;  DLOG("inform: flags=0x%04x (cifrado)", INFORM_FLAG_ENCRYPTED);
    unsigned char iv_bin[16];
    crypto_hex2bin((char*)iv_hex,iv_bin,16);
    memcpy(p,iv_bin,16);                p+=16; DLOG("inform: IV (16 bytes) escrito");
    put32be(p,INFORM_DATA_VERSION);     p+=4;  DLOG("inform: data_ver=%u", INFORM_DATA_VERSION);
    put32be(p,(uint32_t)enc_len);       p+=4;  DLOG("inform: payload_len=%d escrito", enc_len);
    memcpy(p,enc,enc_len);
    free(enc);

    DLOG_HEX("TNBU cabecera (40 bytes)", pkt, 40);
    *out_len=pkt_len;
    return pkt;
}

/* ═══ Parsear respuesta binaria ═══════════════════════════════════ */
static char *parse_packet(const unsigned char *data, size_t data_len, const char *key_hex)
{
    DLOG("inform: parse_packet — data_len=%zu", data_len);
    if (data_len<40) { DLOG("inform: respuesta demasiado corta (%zu bytes)", data_len); return NULL; }

    if (memcmp(data,INFORM_MAGIC,4)!=0) {
        DLOG("inform: magic TNBU no encontrado en respuesta (primeros 4: %02x%02x%02x%02x)",
             data[0],data[1],data[2],data[3]);
        return NULL;
    }
    DLOG("inform: magic TNBU OK");

    uint16_t flags    = get16be(data+14);
    uint32_t body_len = get32be(data+36);
    DLOG("inform: respuesta flags=0x%04x body_len=%u", flags, body_len);

    if (40+body_len>data_len) { DLOG("inform: body_len=%u supera data_len=%zu", body_len,(size_t)data_len); return NULL; }

    const unsigned char *iv_bin  = data+16;
    const unsigned char *body    = data+40;

    if (flags & INFORM_FLAG_ENCRYPTED) {
        DLOG("inform: respuesta cifrada — descifrando con key=%.8s...", key_hex);
        char iv_hex[33];
        crypto_bin2hex(iv_bin,16,iv_hex);
        DLOG("inform: IV de respuesta: %s", iv_hex);
        unsigned char *plain=malloc(body_len+1);
        if (!plain) { DLOG("inform: OOM al descifrar"); return NULL; }
        int pl=crypto_decrypt(key_hex,iv_hex,body,body_len,plain);
        if (pl<0) { DLOG("inform: descifrado FALLO"); free(plain); return NULL; }
        plain[pl]='\0';
        DLOG("inform: descifrado OK — plain_len=%d bytes: %.200s", pl, (char*)plain);
        return (char*)plain;
    }

    DLOG("inform: respuesta sin cifrar (flags=0x%04x)", flags);
    char *copy=malloc(body_len+1);
    if (!copy) return NULL;
    memcpy(copy,body,body_len); copy[body_len]='\0';
    DLOG("inform: respuesta plana: %.200s", copy);
    return copy;
}

/* ═══ Procesar comando JSON del controlador ══════════════════════ */
static void handle_response(openuf_state_t *st, const uf_model_t *model,
                             struct json_object *resp, char *action_out)
{
    struct json_object *v;
    const char *type="noop";
    if (json_object_object_get_ex(resp,"_type",&v)) type=json_object_get_string(v);
    DLOG("inform: handle_response _type='%s'", type);

    /* Volcar JSON completo de la respuesta */
    DLOG("inform: JSON del controlador: %s", json_object_to_json_string(resp));

    if (!strcmp(type,"noop")) { strcpy(action_out,"noop"); DLOG("inform: noop recibido"); return; }

    if (!strcmp(type,"setparam")) {
        DLOG("inform: setparam recibido");
        if (json_object_object_get_ex(resp,"key",&v)) {
            const char *key=json_object_get_string(v);
            DLOG("inform: setparam key='%s'", key);
            struct json_object *val_o;
            if (json_object_object_get_ex(resp,"value",&val_o)) {
                const char *val=json_object_get_string(val_o);
                DLOG("inform: setparam value='%s'", val);
                if (!strcmp(key,"inform_url")) strncpy(st->inform_url,val,sizeof(st->inform_url)-1);
                if (!strcmp(key,"authkey"))    strncpy(st->authkey,val,sizeof(st->authkey)-1);
            }
        }
        state_save(st);
        strcpy(action_out,"setparam");
        return;
    }

    if (!strcmp(type,"cmd")) {
        const char *cmd="";
        if (json_object_object_get_ex(resp,"cmd",&v)) cmd=json_object_get_string(v);
        DLOG("inform: cmd='%s'", cmd);

        if (!strcmp(cmd,"set-adopt")||!strcmp(cmd,"adopt")) {
            DLOG("inform: iniciando adopcion...");
            if (json_object_object_get_ex(resp,"uri",&v)) {
                strncpy(st->inform_url,json_object_get_string(v),sizeof(st->inform_url)-1);
                DLOG("inform: nueva inform_url: %s", st->inform_url);
            }
            if (json_object_object_get_ex(resp,"key",&v)) {
                strncpy(st->authkey,json_object_get_string(v),sizeof(st->authkey)-1);
                DLOG("inform: nueva authkey: %.8s...", st->authkey);
            }
            st->adopted=true;
            state_save(st);
            strcpy(action_out,"adopted");
            printf("[openuf] Adoptado. Clave: %.8s...\n", st->authkey);

        } else if (!strcmp(cmd,"reboot")) {
            DLOG("inform: REBOOT ordenado por el controlador");
            strcpy(action_out,"reboot");
            system("reboot &");
        } else if (!strcmp(cmd,"reset")) {
            DLOG("inform: RESET ordenado — borrando estado y reiniciando");
            strcpy(action_out,"reset");
            system("rm -f " OPENUF_STATE_FILE);
            system("reboot &");
        } else if (!strcmp(cmd,"locate")) {
            DLOG("inform: locate (parpadeo LED)");
            strcpy(action_out,"locate");
        } else {
            DLOG("inform: cmd desconocido '%s'", cmd);
            snprintf(action_out,64,"cmd:%s",cmd);
        }
        return;
    }

    if (!strcmp(type,"setstate")) {
        DLOG("inform: setstate recibido — aplicando configuracion WiFi");
        if (json_object_object_get_ex(resp,"cfgversion",&v)) {
            snprintf(st->cfgversion,sizeof(st->cfgversion),"%s",json_object_get_string(v));
            DLOG("inform: nueva cfgversion='%s'", st->cfgversion);
        }
        struct json_object *rt=NULL,*vt=NULL;
        json_object_object_get_ex(resp,"radio_table",&rt);
        json_object_object_get_ex(resp,"vap_table",&vt);
        if (rt) DLOG("inform: radio_table presente (%d entradas)", json_object_array_length(rt));
        if (vt) DLOG("inform: vap_table presente (%d entradas)", json_object_array_length(vt));
        if (rt||vt) {
            printf("[openuf] Aplicando config WiFi del controlador...\n");
            wlan_apply_config(resp,model);
        } else {
            DLOG("inform: setstate sin radio_table ni vap_table — nada que aplicar");
        }
        state_save(st);
        strcpy(action_out,"setstate");
        return;
    }

    DLOG("inform: tipo desconocido '%s'", type);
    snprintf(action_out,64,"unknown:%s",type);
}

/* ═══ inform_send ════════════════════════════════════════════════ */
int inform_send(openuf_state_t *st, const uf_model_t *model,
                long uptime, char *err_out)
{
    DLOG("inform: inform_send — url=%s adopted=%s uptime=%lds",
         st->inform_url, st->adopted?"SI":"NO", uptime);

    if (!st->inform_url[0]) {
        strncpy(err_out,"no inform_url",127);
        DLOG("inform: ABORTANDO — no hay inform_url configurada");
        return -1;
    }

    const char *key_hex = st->authkey[0] ? st->authkey : DEFAULT_AUTH_KEY;
    DLOG("inform: usando clave %.8s... (%s)",
         key_hex, st->authkey[0] ? "adoptado" : "DEFAULT");

    /* MAC sin colones */
    char mac_hex[32]={0};
    { const char *s=st->mac; int j=0;
      for(int i=0;s[i]&&j<12;i++) if(s[i]!=':') mac_hex[j++]=s[i]; }
    DLOG("inform: mac_hex=%s", mac_hex);

    DLOG("inform: construyendo JSON payload...");
    char *payload=build_payload(st,model,uptime);
    if (!payload) { strncpy(err_out,"build_payload OOM",127); DLOG("inform: payload FALLO"); return -1; }
    DLOG("inform: payload listo (%zu bytes)", strlen(payload));

    DLOG("inform: construyendo paquete TNBU...");
    size_t pkt_len=0;
    unsigned char *pkt=build_packet(mac_hex,key_hex,payload,&pkt_len);
    free(payload);
    if (!pkt) { strncpy(err_out,"build_packet failed",127); DLOG("inform: build_packet FALLO"); return -1; }
    DLOG("inform: paquete TNBU listo (%zu bytes)", pkt_len);

    DLOG("inform: HTTP POST a %s (%zu bytes)...", st->inform_url, pkt_len);
    unsigned char *resp_body=NULL;
    size_t resp_len=0;
    int status=http_post(st->inform_url,"application/x-binary-data",pkt,pkt_len,&resp_body,&resp_len);
    free(pkt);

    DLOG("inform: HTTP status=%d resp_len=%zu", status, resp_len);

    if (status<0) { snprintf(err_out,127,"HTTP connect failed"); DLOG("inform: HTTP FALLO (connect)"); return -1; }
    if (status!=200) { snprintf(err_out,127,"HTTP %d",status); DLOG("inform: HTTP status inesperado %d",status); free(resp_body); return -1; }

    if (!resp_body||resp_len==0) {
        DLOG("inform: respuesta vacia (noop implicito)");
        free(resp_body); return 0;
    }
    DLOG("inform: descifrando respuesta (%zu bytes)...", resp_len);
    DLOG_HEX("respuesta raw (primeros bytes)", resp_body, resp_len<32?(int)resp_len:32);

    char *resp_json=parse_packet(resp_body,resp_len,key_hex);
    free(resp_body);
    if (!resp_json) { snprintf(err_out,127,"parse_packet failed"); DLOG("inform: parse_packet FALLO"); return -1; }
    DLOG("inform: JSON respuesta: %s", resp_json);

    struct json_object *resp_obj=json_tokener_parse(resp_json);
    free(resp_json);
    if (!resp_obj) { snprintf(err_out,127,"JSON parse failed"); DLOG("inform: json_tokener_parse FALLO"); return -1; }

    char action[64]="noop";
    handle_response(st,model,resp_obj,action);
    json_object_put(resp_obj);

    if (strcmp(action,"noop")!=0) {
        printf("[openuf] accion: %s\n",action);
        DLOG("inform: accion ejecutada: %s", action);
    } else {
        DLOG("inform: accion: noop (sin cambios)");
    }
    return 0;
}
