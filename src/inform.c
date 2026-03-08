/*
 * openuf - inform.c
 *
 * Protocolo Inform de UniFi — implementación completa.
 *
 * ── CÓMO FUNCIONA ────────────────────────────────────────────────────
 *
 * Cada 10 segundos el AP hace HTTP POST a http://<controller>:8080/inform
 * con un paquete binario TNBU que contiene JSON cifrado con AES-128-CBC.
 *
 * El controlador responde con otro paquete TNBU. El AP descifra, parsea
 * el JSON y ejecuta la acción (_type).
 *
 * ── PAQUETE BINARIO TNBU ─────────────────────────────────────────────
 *
 *   Offset  Bytes  Campo
 *   ------  -----  -----
 *   0       4      Magic "TNBU"
 *   4       4      Versión paquete (=0), uint32 BE
 *   8       6      MAC del AP
 *   14      2      Flags: bit0=cifrado, bit1=zlib
 *   16      16     IV de AES (cuando cifrado)
 *   32      4      Versión de datos (=1), uint32 BE
 *   36      4      Longitud del payload, uint32 BE
 *   40      N      Payload JSON, cifrado con AES-128-CBC
 *
 * ── CÓMO SE LEEN LOS PARÁMETROS ──────────────────────────────────────
 *
 *   CPU:        sysinfo_cpu_percent()          → /proc/stat (delta 2 llamadas)
 *   RAM:        sysinfo_mem()                  → /proc/meminfo
 *   Interfaces: sysinfo_iface()                → /proc/net/dev + /sys/class/net/
 *   Radios:     sysinfo_radio()                → iw dev <iface> info + survey
 *   VAPs UCI:   wlan_get_vap_table()           → libuci wireless.*
 *   Clientes WiFi: clients_build_sta_table()   → iw dev <iface> station dump
 *   Clientes IP: clients_mac_to_ip()           → /proc/net/arp
 *   Clientes nombre: clients_mac_to_hostname() → /tmp/dhcp.leases
 *   LLDP vecinos: lldp_read_neighbors()        → lldpctl -f json
 *
 * ── CICLO DE ADOPCIÓN ────────────────────────────────────────────────
 *
 *   1. AP envía inform con key=DEFAULT, default=true, state=1
 *   2. Controller responde: {_type:"cmd", cmd:"set-adopt",
 *                            key:"nuevaclave32hex", uri:"http://..."}
 *   3. AP guarda nueva clave + URL en state.json, adopted=true
 *   4. AP envía inform con nueva clave, state=4, default=false
 *   5. Controller responde: {_type:"setstate", radio_table:[...], vap_table:[...]}
 *   6. AP aplica config WiFi via wlan_apply_config() → libuci → wifi reload
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

/* ─── Big-endian helpers ────────────────────────────────────────── */
static void put32be(unsigned char *p, uint32_t v)
{
    p[0]=(v>>24)&0xff; p[1]=(v>>16)&0xff;
    p[2]=(v>> 8)&0xff; p[3]=v&0xff;
}
static void put16be(unsigned char *p, uint16_t v)
{
    p[0]=(v>>8)&0xff; p[1]=v&0xff;
}
static uint32_t get32be(const unsigned char *p)
{
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|
           ((uint32_t)p[2]<<8)|(uint32_t)p[3];
}
static uint16_t get16be(const unsigned char *p)
{
    return ((uint16_t)p[0]<<8)|(uint16_t)p[1];
}

/* ═══════════════════════════════════════════════════════════════════
   sys_stats — CPU y memoria del sistema
   ═══════════════════════════════════════════════════════════════════
   El controlador muestra CPU y RAM en la vista del dispositivo.
   Leemos /proc/stat y /proc/meminfo directamente.
*/
static struct json_object *build_sys_stats(void)
{
    struct json_object *o = json_object_new_object();

    mem_stats_t mem;
    if (sysinfo_mem(&mem) == 0) {
        long used_kb = mem.total_kb - mem.free_kb
                       - mem.buffer_kb - mem.cached_kb;
        if (used_kb < 0) used_kb = 0;
        json_object_object_add(o, "mem_total",
            json_object_new_int64(mem.total_kb * 1024LL));
        json_object_object_add(o, "mem_used",
            json_object_new_int64(used_kb * 1024LL));
        json_object_object_add(o, "mem_buffer",
            json_object_new_int64(mem.buffer_kb * 1024LL));
    } else {
        json_object_object_add(o, "mem_total",  json_object_new_int(0));
        json_object_object_add(o, "mem_used",   json_object_new_int(0));
        json_object_object_add(o, "mem_buffer", json_object_new_int(0));
    }

    /* CPU — delta respecto a llamada anterior (cada ~10s da buen promedio) */
    json_object_object_add(o, "cpu",
        json_object_new_int(sysinfo_cpu_percent()));

    return o;
}

/* ═══════════════════════════════════════════════════════════════════
   if_table — estadísticas de interfaces de red
   ═══════════════════════════════════════════════════════════════════
   Reportamos todos los puertos ethernet del modelo.
   Leemos /proc/net/dev para contadores y /sys/class/net/<iface>/
   para velocidad, duplex y estado del enlace.
*/
static struct json_object *build_if_table(const uf_model_t *m,
                                          const openuf_state_t *st)
{
    struct json_object *arr = json_object_new_array();

    for (int i = 0; i < m->port_table_len; i++) {
        const char *ifname = m->port_table[i].ifname;
        iface_stats_t stats;
        sysinfo_iface(ifname, &stats);

        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "name",
            json_object_new_string(ifname));
        json_object_object_add(o, "mac",
            json_object_new_string(stats.mac[0] ? stats.mac : st->mac));
        json_object_object_add(o, "ip",
            json_object_new_string(stats.ip[0] ? stats.ip : st->ip));
        json_object_object_add(o, "up",
            json_object_new_boolean(stats.up));
        json_object_object_add(o, "speed",
            json_object_new_int(stats.speed > 0 ? stats.speed : 1000));
        json_object_object_add(o, "full_duplex",
            json_object_new_boolean(stats.full_duplex));
        json_object_object_add(o, "num_port",
            json_object_new_int(1));
        json_object_object_add(o, "rx_bytes",
            json_object_new_int64(stats.rx_bytes));
        json_object_object_add(o, "tx_bytes",
            json_object_new_int64(stats.tx_bytes));
        json_object_object_add(o, "rx_packets",
            json_object_new_int64(stats.rx_packets));
        json_object_object_add(o, "tx_packets",
            json_object_new_int64(stats.tx_packets));
        json_object_object_add(o, "rx_errors",
            json_object_new_int64(stats.rx_errors));
        json_object_object_add(o, "tx_errors",
            json_object_new_int64(stats.tx_errors));
        json_object_object_add(o, "rx_dropped",
            json_object_new_int64(stats.rx_dropped));
        json_object_object_add(o, "tx_dropped",
            json_object_new_int64(stats.tx_dropped));
        json_object_object_add(o, "rx_multicast",
            json_object_new_int64(stats.rx_multicast));
        json_object_array_add(arr, o);
    }
    return arr;
}

/* ═══════════════════════════════════════════════════════════════════
   radio_table — definición estática del hardware de radio
   ═══════════════════════════════════════════════════════════════════
   Describe las capacidades físicas de cada radio al controlador.
   El controlador usa esto para saber qué frecuencias y modos soporta.
*/
static void build_radio_table(struct json_object *root,
                               const uf_model_t *m)
{
    struct json_object *arr = json_object_new_array();
    for (int i = 0; i < m->radio_table_len; i++) {
        const uf_radio_t *r = &m->radio_table[i];
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "name",          json_object_new_string(r->name));
        json_object_object_add(o, "radio",         json_object_new_string(r->radio));
        json_object_object_add(o, "channel",       json_object_new_int(r->channel));
        json_object_object_add(o, "ht",            json_object_new_string(r->ht));
        json_object_object_add(o, "min_txpower",   json_object_new_int(r->min_txpower));
        json_object_object_add(o, "max_txpower",   json_object_new_int(r->max_txpower));
        json_object_object_add(o, "nss",           json_object_new_int(r->nss));
        json_object_object_add(o, "tx_power",      json_object_new_int(r->tx_power));
        json_object_object_add(o, "radio_caps",    json_object_new_int(r->radio_caps));
        json_object_object_add(o, "antenna_gain",  json_object_new_int(r->antenna_gain));
        json_object_object_add(o, "he_enabled",    json_object_new_boolean(r->he_enabled));
        json_object_object_add(o, "builtin_antenna",   json_object_new_boolean(true));
        json_object_object_add(o, "builtin_ant_gain",  json_object_new_int(0));
        json_object_array_add(arr, o);
    }
    json_object_object_add(root, "radio_table", arr);
}

/* ═══════════════════════════════════════════════════════════════════
   radio_table_stats — estadísticas dinámicas de canal
   ═══════════════════════════════════════════════════════════════════
   Leemos en tiempo real la utilización del canal con:
     iw dev wlan0 survey dump    → active/busy/tx/rx time
     iw dev wlan0 info           → canal actual, potencia
   El controlador muestra estos datos en la vista de RF.
*/
static struct json_object *build_radio_table_stats(const uf_model_t *m)
{
    struct json_object *arr = json_object_new_array();

    for (int i = 0; i < m->radio_map_len; i++) {
        const uf_radio_map_t *rm = &m->radio_map[i];

        /* Mapear "radio0" → "wlan0" por convención OpenWrt */
        char wlan_iface[32];
        int ridx = 0;
        sscanf(rm->device, "radio%d", &ridx);
        snprintf(wlan_iface, sizeof(wlan_iface), "wlan%d", ridx);

        /* Nombre del radio en la tabla estática */
        const char *radio_name = (i < m->radio_table_len)
                                 ? m->radio_table[i].name : wlan_iface;
        int default_ch = (i < m->radio_table_len)
                         ? m->radio_table[i].channel : 6;
        int default_pwr = (i < m->radio_table_len)
                          ? m->radio_table[i].tx_power : 20;

        radio_stats_t rs;
        if (sysinfo_radio(wlan_iface, &rs) != 0) {
            memset(&rs, 0, sizeof(rs));
            rs.noise = -95;
        }

        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "name",
            json_object_new_string(radio_name));
        json_object_object_add(o, "channel",
            json_object_new_int(rs.channel ? rs.channel : default_ch));
        json_object_object_add(o, "tx_power",
            json_object_new_int(rs.tx_power ? rs.tx_power : default_pwr));
        json_object_object_add(o, "cu_self_tx",
            json_object_new_int(rs.cu_self_tx));
        json_object_object_add(o, "cu_self_rx",
            json_object_new_int(rs.cu_self_rx));
        json_object_object_add(o, "cu_total",
            json_object_new_int(rs.cu_total));
        json_object_object_add(o, "num_sta",
            json_object_new_int(rs.num_sta));
        json_object_object_add(o, "noise",
            json_object_new_int(rs.noise));
        json_object_array_add(arr, o);
    }
    return arr;
}

/* ═══════════════════════════════════════════════════════════════════
   port_table — estado real de los puertos ethernet
   ═══════════════════════════════════════════════════════════════════
   Leemos /sys/class/net/<iface>/speed y operstate para
   reflejar el estado real de cada puerto en el controlador.
*/
static void build_port_table(struct json_object *root,
                              const uf_model_t *m)
{
    struct json_object *arr = json_object_new_array();
    for (int i = 0; i < m->port_table_len; i++) {
        const uf_port_t *pt = &m->port_table[i];
        iface_stats_t stats;
        sysinfo_iface(pt->ifname, &stats);

        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "ifname",
            json_object_new_string(pt->ifname));
        json_object_object_add(o, "name",
            json_object_new_string(pt->name));
        json_object_object_add(o, "port_idx",
            json_object_new_int(pt->port_idx));
        json_object_object_add(o, "poe_caps",
            json_object_new_int(pt->poe_caps));
        json_object_object_add(o, "media",
            json_object_new_string(pt->media));
        json_object_object_add(o, "speed",
            json_object_new_int(stats.speed > 0 ? stats.speed : pt->speed));
        json_object_object_add(o, "up",
            json_object_new_boolean(stats.up));
        json_object_object_add(o, "is_uplink",
            json_object_new_boolean(pt->is_uplink));
        json_object_object_add(o, "full_duplex",
            json_object_new_boolean(stats.full_duplex));
        json_object_object_add(o, "rx_bytes",
            json_object_new_int64(stats.rx_bytes));
        json_object_object_add(o, "tx_bytes",
            json_object_new_int64(stats.tx_bytes));
        json_object_array_add(arr, o);
    }
    json_object_object_add(root, "port_table", arr);
}

static void build_eth_table(struct json_object *root, const uf_model_t *m)
{
    struct json_object *arr = json_object_new_array();
    for (int i = 0; i < m->ethernet_table_len; i++) {
        const uf_eth_entry_t *e = &m->ethernet_table[i];
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "name",     json_object_new_string(e->name));
        json_object_object_add(o, "num_port", json_object_new_int(e->num_port));
        json_object_array_add(arr, o);
    }
    json_object_object_add(root, "ethernet_table", arr);
}

/* ═══════════════════════════════════════════════════════════════════
   vap_table — VAPs activas con clientes conectados (sta_table)
   ═══════════════════════════════════════════════════════════════════
   Para cada VAP activa en UCI:
   1. Leemos estadísticas de la interfaz wlan con sysinfo_iface()
   2. Obtenemos el canal actual con sysinfo_radio()
   3. Enumeramos clientes con clients_build_sta_table()
      → iw dev wlan0 station dump (señal, bitrate, bytes, uptime)
      → /proc/net/arp (MAC → IP)
      → /tmp/dhcp.leases (MAC → hostname)

   El sta_table anidado es lo que el controlador usa para:
   - Mostrar clientes en el dashboard
   - Calcular estadísticas por cliente
   - Dibujar la topología de la red
*/
static struct json_object *build_vap_table(const uf_model_t *m)
{
    /* Obtener lista de VAPs desde UCI */
    struct json_object *uci_vaps = wlan_get_vap_table(m);
    int nvaps = json_object_array_length(uci_vaps);

    struct json_object *arr = json_object_new_array();

    for (int i = 0; i < nvaps; i++) {
        struct json_object *vap = json_object_array_get_idx(uci_vaps, i);
        struct json_object *v;

        const char *essid    = "";
        const char *vap_name = "";
        const char *radio    = "ng";
        const char *bssid    = "00:00:00:00:00:00";

        if (json_object_object_get_ex(vap, "essid",  &v)) essid    = json_object_get_string(v);
        if (json_object_object_get_ex(vap, "name",   &v)) vap_name = json_object_get_string(v);
        if (json_object_object_get_ex(vap, "radio",  &v)) radio    = json_object_get_string(v);
        if (json_object_object_get_ex(vap, "bssid",  &v)) bssid    = json_object_get_string(v);

        /* Mapear banda → interfaz wlan y canal actual */
        char wlan_iface[32] = "wlan0";
        int  channel = 6;
        for (int j = 0; j < m->radio_map_len; j++) {
            if (strcmp(m->radio_map[j].band, radio) == 0) {
                int idx = 0;
                sscanf(m->radio_map[j].device, "radio%d", &idx);
                snprintf(wlan_iface, sizeof(wlan_iface), "wlan%d", idx);
                radio_stats_t rs;
                if (sysinfo_radio(wlan_iface, &rs) == 0 && rs.channel)
                    channel = rs.channel;
                else if (idx < m->radio_table_len)
                    channel = m->radio_table[idx].channel;
                break;
            }
        }

        /* Estadísticas de la interfaz inalámbrica */
        iface_stats_t iface_st;
        sysinfo_iface(wlan_iface, &iface_st);

        /* Clientes conectados a esta VAP */
        struct json_object *sta_tbl =
            clients_build_sta_table(wlan_iface, radio, channel, vap_name);
        int num_sta = json_object_array_length(sta_tbl);

        /* Calcular tx_power del radio correspondiente */
        int tx_pwr = 20;
        radio_stats_t rs2;
        if (sysinfo_radio(wlan_iface, &rs2) == 0 && rs2.tx_power)
            tx_pwr = rs2.tx_power;

        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "essid",
            json_object_new_string(essid));
        json_object_object_add(o, "bssid",
            json_object_new_string(bssid));
        json_object_object_add(o, "name",
            json_object_new_string(vap_name));
        json_object_object_add(o, "radio",
            json_object_new_string(radio));
        json_object_object_add(o, "up",
            json_object_new_boolean(iface_st.up));
        json_object_object_add(o, "channel",
            json_object_new_int(channel));
        json_object_object_add(o, "tx_power",
            json_object_new_int(tx_pwr));
        json_object_object_add(o, "num_sta",
            json_object_new_int(num_sta));
        json_object_object_add(o, "rx_bytes",
            json_object_new_int64(iface_st.rx_bytes));
        json_object_object_add(o, "tx_bytes",
            json_object_new_int64(iface_st.tx_bytes));
        json_object_object_add(o, "rx_packets",
            json_object_new_int64(iface_st.rx_packets));
        json_object_object_add(o, "tx_packets",
            json_object_new_int64(iface_st.tx_packets));
        json_object_object_add(o, "rx_errors",
            json_object_new_int64(iface_st.rx_errors));
        json_object_object_add(o, "tx_errors",
            json_object_new_int64(iface_st.tx_errors));
        json_object_object_add(o, "rx_dropped",
            json_object_new_int64(iface_st.rx_dropped));
        json_object_object_add(o, "tx_dropped",
            json_object_new_int64(iface_st.tx_dropped));
        json_object_object_add(o, "id",
            json_object_new_string("user"));
        json_object_object_add(o, "usage",
            json_object_new_string("user"));
        json_object_object_add(o, "ccq",
            json_object_new_int(0));
        /* sta_table anidado — clientes de ESTA VAP */
        json_object_object_add(o, "sta_table", sta_tbl);

        json_object_array_add(arr, o);
    }
    json_object_put(uci_vaps);
    return arr;
}

/* ═══════════════════════════════════════════════════════════════════
   build_payload — ensamblado completo del JSON inform
   ═══════════════════════════════════════════════════════════════════ */
static char *build_payload(const openuf_state_t *st,
                            const uf_model_t *m,
                            long uptime)
{
    /* MAC sin colones → serial (uppercase) */
    char mac_clean[32] = {0};
    {
        const char *s = st->mac; int j = 0;
        for (int i = 0; s[i] && j < 12; i++)
            if (s[i] != ':') {
                char c = s[i];
                if (c >= 'a' && c <= 'f') c -= 32;
                mac_clean[j++] = c;
            }
    }

    char fw_version[64];
    snprintf(fw_version, sizeof(fw_version), "%s%s", m->fw_pre, m->fw_ver);

    char inform_url_buf[256];
    if (st->inform_url[0])
        strncpy(inform_url_buf, st->inform_url, sizeof(inform_url_buf)-1);
    else
        snprintf(inform_url_buf, sizeof(inform_url_buf),
                 "http://unifi:%d%s", INFORM_PORT, INFORM_PATH);

    struct json_object *root = json_object_new_object();

    /* ── Identidad del dispositivo ──────────────────────────────── */
    json_object_object_add(root, "mac",
        json_object_new_string(st->mac));
    json_object_object_add(root, "serial",
        json_object_new_string(mac_clean));
    json_object_object_add(root, "model",
        json_object_new_string(m->model));
    json_object_object_add(root, "model_display",
        json_object_new_string(m->model_display));
    json_object_object_add(root, "display_name",
        json_object_new_string(m->display_name));
    json_object_object_add(root, "board_rev",
        json_object_new_int(m->board_rev));
    json_object_object_add(root, "version",
        json_object_new_string(fw_version));
    json_object_object_add(root, "bootrom_version",
        json_object_new_string("openuf-v0.4"));
    json_object_object_add(root, "required_version",
        json_object_new_string("2.4.4"));
    json_object_object_add(root, "ip",
        json_object_new_string(st->ip));
    json_object_object_add(root, "hostname",
        json_object_new_string(st->hostname[0] ? st->hostname : m->display_name));
    json_object_object_add(root, "inform_url",
        json_object_new_string(inform_url_buf));
    json_object_object_add(root, "uptime",
        json_object_new_int64(uptime));
    json_object_object_add(root, "time",
        json_object_new_int64((long long)uptime));
    json_object_object_add(root, "state",
        json_object_new_int(st->adopted ? 4 : 1));
    json_object_object_add(root, "default",
        json_object_new_boolean(!st->adopted));
    json_object_object_add(root, "cfgversion",
        json_object_new_string(st->cfgversion));
    json_object_object_add(root, "x_authkey",
        json_object_new_string(st->adopted ? st->authkey : DEFAULT_AUTH_KEY));
    json_object_object_add(root, "_default_key",
        json_object_new_boolean(!st->adopted));
    json_object_object_add(root, "has_eth1",
        json_object_new_boolean(m->has_eth1));
    json_object_object_add(root, "isolated",
        json_object_new_boolean(false));
    json_object_object_add(root, "locating",
        json_object_new_boolean(false));
    json_object_object_add(root, "uplink",
        json_object_new_string("eth0"));
    json_object_object_add(root, "country_code",
        json_object_new_int(0));

    /* ── CPU + RAM ──────────────────────────────────────────────── */
    json_object_object_add(root, "sys_stats", build_sys_stats());

    /* ── Interfaces ethernet con contadores reales ──────────────── */
    json_object_object_add(root, "if_table", build_if_table(m, st));

    /* ── Capacidades de radio (estático del modelo) ─────────────── */
    build_radio_table(root, m);

    /* ── Utilización de canal en tiempo real ────────────────────── */
    json_object_object_add(root, "radio_table_stats",
        build_radio_table_stats(m));

    /* ── Puertos ethernet con estado real ───────────────────────── */
    build_port_table(root, m);
    build_eth_table(root, m);

    /* ── VAPs con clientes WiFi (sta_table anidado) ─────────────── */
    json_object_object_add(root, "vap_table", build_vap_table(m));

    /* ── Vecinos LLDP para topología visual ─────────────────────── */
    json_object_object_add(root, "lldp_table", lldp_read_neighbors());

    /* Contadores globales */
    json_object_object_add(root, "bytes_r",  json_object_new_int(0));
    json_object_object_add(root, "bytes_d",  json_object_new_int(0));
    json_object_object_add(root, "num_sta",  json_object_new_int(0));

    const char *s = json_object_to_json_string(root);
    
    /* Log shows what authkey is actually in the payload */
    LOG("Payload state=%d, default=%s, adopted=%d, x_authkey=%.8s...", 
        st->adopted ? 4 : 1, 
        !st->adopted ? "true" : "false",
        st->adopted,
        st->authkey[0] ? st->authkey : "DEFAULT");
    
    char *copy = strdup(s);
    json_object_put(root);
    return copy;
}

/* ═══════════════════════════════════════════════════════════════════
   Paquete binario TNBU
   ═══════════════════════════════════════════════════════════════════ */
static unsigned char *build_packet(const char *mac_hex,
                                   const char *key_hex,
                                   const char *payload,
                                   size_t *out_len)
{
    unsigned char iv_hex[33] = {0};
    if (crypto_random_hex(iv_hex, 16) != 0) return NULL;

    size_t pl_len = strlen(payload);
    unsigned char *enc = malloc(pl_len + 32);
    if (!enc) return NULL;

    int enc_len = crypto_encrypt(key_hex, (char *)iv_hex,
                                 (const unsigned char *)payload, pl_len, enc);
    if (enc_len < 0) { free(enc); return NULL; }

    unsigned char mac_bin[6];
    crypto_hex2bin(mac_hex, mac_bin, 6);

    size_t pkt_len = 4 + 4 + 6 + 2 + 16 + 4 + 4 + enc_len;
    unsigned char *pkt = malloc(pkt_len);
    if (!pkt) { free(enc); return NULL; }

    unsigned char *p = pkt;
    memcpy(p, INFORM_MAGIC, 4);         p += 4;
    put32be(p, INFORM_PKT_VERSION);     p += 4;
    memcpy(p, mac_bin, 6);              p += 6;
    put16be(p, INFORM_FLAG_ENCRYPTED);  p += 2;

    unsigned char iv_bin[16];
    crypto_hex2bin((char *)iv_hex, iv_bin, 16);
    memcpy(p, iv_bin, 16);              p += 16;
    put32be(p, INFORM_DATA_VERSION);    p += 4;
    put32be(p, (uint32_t)enc_len);      p += 4;
    memcpy(p, enc, enc_len);
    free(enc);

    *out_len = pkt_len;
    return pkt;
}

/* ═══════════════════════════════════════════════════════════════════
   Parsear respuesta binaria del controlador
   ═══════════════════════════════════════════════════════════════════ */
static char *parse_packet(const unsigned char *data, size_t data_len,
                           const char *key_hex)
{
    if (data_len < 40) return NULL;
    if (memcmp(data, INFORM_MAGIC, 4) != 0) return NULL;

    uint16_t flags   = get16be(data + 14);
    const unsigned char *iv_bin = data + 16;
    uint32_t body_len = get32be(data + 36);
    const unsigned char *body   = data + 40;

    if (40 + body_len > data_len) return NULL;

    if (flags & INFORM_FLAG_ENCRYPTED) {
        char iv_hex[33];
        crypto_bin2hex(iv_bin, 16, iv_hex);
        unsigned char *plain = malloc(body_len + 1);
        if (!plain) return NULL;
        int pl = crypto_decrypt(key_hex, iv_hex, body, body_len, plain);
        if (pl < 0) { free(plain); return NULL; }
        plain[pl] = '\0';
        return (char *)plain;
    }

    char *copy = malloc(body_len + 1);
    if (!copy) return NULL;
    memcpy(copy, body, body_len);
    copy[body_len] = '\0';
    return copy;
}

/* ═══════════════════════════════════════════════════════════════════
   Procesar comando JSON del controlador
   ═══════════════════════════════════════════════════════════════════

   _type == "noop"     → no hacer nada
   _type == "cmd"      → set-adopt / reboot / reset / locate
   _type == "setstate" → aplicar radio_table + vap_table via UCI
   _type == "setparam" → cambiar un parámetro individual
*/
static void handle_response(openuf_state_t *st,
                             const uf_model_t *model,
                             struct json_object *resp,
                             char *action_out)
{
    struct json_object *v;
    const char *type = "noop";
    if (json_object_object_get_ex(resp, "_type", &v))
        type = json_object_get_string(v);

    LOG("Handling response type: %s", type);

    /* ── noop ────────────────────────────────────────────────────── */
    if (!strcmp(type, "noop")) {
        strcpy(action_out, "noop");
        return;
    }

    /* ── setparam ────────────────────────────────────────────────── */
    if (!strcmp(type, "setparam")) {
        /* Primero, intentar parsear mgmt_cfg (controller moderna con parámetros) */
        if (json_object_object_get_ex(resp, "mgmt_cfg", &v)) {
            const char *mgmt_cfg = json_object_get_string(v);
            LOG("Parsing mgmt_cfg: %s", mgmt_cfg);
            
            /* Parsear pares clave=valor separados por newline */
            char cfg_copy[2048];
            strncpy(cfg_copy, mgmt_cfg, sizeof(cfg_copy)-1);
            
            char *line = strtok(cfg_copy, "\n");
            while (line) {
                char *eq = strchr(line, '=');
                if (eq) {
                    *eq = '\0';
                    const char *key = line;
                    const char *val = eq + 1;
                    
                    LOG("mgmt_cfg param: %s = %s", key, val);
                    
                    /* For adoption: extract authkey from setparam when not adopted */
                    if (!strcmp(key, "authkey") && st->adopted == 0) {
                        strncpy(st->authkey, val, sizeof(st->authkey)-1);
                        LOG("Updated authkey from setparam for adoption");
                    } else if (!strcmp(key, "cfgversion")) {
                        strncpy(st->cfgversion, val, sizeof(st->cfgversion)-1);
                    } else if (!strcmp(key, "mgmt_url")) {
                        /* Could save mgmt_url for future use */
                    }
                    /* Ignore use_aes_gcm, report_crash, etc. from mgmt_cfg */
                }
                line = strtok(NULL, "\n");
            }
        }
        
        /* Alternativa: parsear key/value directo (controller antigua) */
        if (json_object_object_get_ex(resp, "key", &v)) {
            const char *key = json_object_get_string(v);
            struct json_object *val_o;
            if (json_object_object_get_ex(resp, "value", &val_o)) {
                const char *val = json_object_get_string(val_o);
                LOG("setparam key=%s val=%s", key, val);
                if (!strcmp(key, "inform_url"))
                    strncpy(st->inform_url, val, sizeof(st->inform_url)-1);
                /* Do NOT accept authkey via setparam - only via set-adopt */
            }
        }
        
        state_save(st);
        LOG("State saved after setparam");
        strcpy(action_out, "setparam");
        return;
    }

    /* ── cmd ─────────────────────────────────────────────────────── */
    if (!strcmp(type, "cmd")) {
        const char *cmd = "";
        if (json_object_object_get_ex(resp, "cmd", &v))
            cmd = json_object_get_string(v);

        if (!strcmp(cmd, "set-adopt") || !strcmp(cmd, "adopt")) {
            if (json_object_object_get_ex(resp, "uri", &v))
                strncpy(st->inform_url, json_object_get_string(v),
                        sizeof(st->inform_url)-1);
            if (json_object_object_get_ex(resp, "key", &v))
                strncpy(st->authkey, json_object_get_string(v),
                        sizeof(st->authkey)-1);
            st->adopted = true;
            state_save(st);
            strcpy(action_out, "adopted");
            LOG("Adopted successfully. Key: %.8s...", st->authkey);

        } else if (!strcmp(cmd, "reboot")) {
            strcpy(action_out, "reboot");
            system("reboot &");

        } else if (!strcmp(cmd, "reset")) {
            strcpy(action_out, "reset");
            system("rm -f " OPENUF_STATE_FILE);
            system("reboot &");

        } else if (!strcmp(cmd, "locate")) {
            /* Parpadear LED — en OpenWrt: echo 1 > /sys/class/leds/.../trigger */
            strcpy(action_out, "locate");
        } else {
            snprintf(action_out, 64, "cmd:%s", cmd);
        }
        return;
    }

    /* ── setstate — configuración WiFi del controlador ──────────── */
    if (!strcmp(type, "setstate")) {
        if (json_object_object_get_ex(resp, "cfgversion", &v))
            snprintf(st->cfgversion, sizeof(st->cfgversion),
                     "%s", json_object_get_string(v));

        struct json_object *rt = NULL, *vt = NULL;
        json_object_object_get_ex(resp, "radio_table", &rt);
        json_object_object_get_ex(resp, "vap_table",   &vt);
        if (rt || vt) {
            printf("[openuf] Aplicando config WiFi del controlador...\n");
            wlan_apply_config(resp, model);
        }

        state_save(st);
        strcpy(action_out, "setstate");
        return;
    }

    snprintf(action_out, 64, "unknown:%s", type);
}

/* ═══════════════════════════════════════════════════════════════════
   inform_send — función principal pública
   ═══════════════════════════════════════════════════════════════════ */
int inform_send(openuf_state_t *st,
                const uf_model_t *model,
                long uptime,
                char *err_out)
{
    if (!st->inform_url[0]) {
        LOG("No inform_url set");
        strncpy(err_out, "no inform_url", 127);
        return -1;
    }

    const char *key_hex = (st->authkey[0]) ? st->authkey : DEFAULT_AUTH_KEY;
    
    /* CRITICAL: When not adopted, ALWAYS use DEFAULT_AUTH_KEY */
    if (!st->adopted && st->authkey[0] && strcmp(st->authkey, DEFAULT_AUTH_KEY) != 0) {
        LOG("WARNING: Device not adopted but has custom authkey! Using DEFAULT instead!");
        key_hex = DEFAULT_AUTH_KEY;
    }
    
    LOG("Sending inform: adopted=%d, authkey=%.8s..., inform_url=%s", 
        st->adopted, key_hex, st->inform_url);

    /* MAC sin colones */
    char mac_hex[32] = {0};
    {
        const char *s = st->mac; int j = 0;
        for (int i = 0; s[i] && j < 12; i++)
            if (s[i] != ':') mac_hex[j++] = s[i];
    }

    char *payload = build_payload(st, model, uptime);
    if (!payload) { strncpy(err_out, "build_payload OOM", 127); return -1; }

    LOG("Built payload, length: %zu", strlen(payload));

    size_t pkt_len = 0;
    unsigned char *pkt = build_packet(mac_hex, key_hex, payload, &pkt_len);
    free(payload);
    if (!pkt) { strncpy(err_out, "build_packet failed", 127); return -1; }

    LOG("Built packet, length: %zu", pkt_len);

    unsigned char *resp_body = NULL;
    size_t resp_len = 0;
    int status = http_post(st->inform_url,
                           "application/x-binary-data",
                           pkt, pkt_len,
                           &resp_body, &resp_len);
    free(pkt);

    LOG("HTTP POST to %s, status: %d, response length: %zu", st->inform_url, status, resp_len);

    if (status < 0) {
        snprintf(err_out, 127, "HTTP connect failed");
        return -1;
    }
    if (status != 200) {
        snprintf(err_out, 127, "HTTP %d", status);
        free(resp_body);
        return -1;
    }

    if (!resp_body || resp_len == 0) { 
        LOG("No response body");
        free(resp_body); 
        return 0; 
    }

    char *resp_json = parse_packet(resp_body, resp_len, key_hex);
    free(resp_body);
    if (!resp_json) { 
        LOG("Failed to parse response packet");
        snprintf(err_out, 127, "parse_packet failed"); 
        return -1; 
    }

    LOG("Parsed response JSON: %s", resp_json);

    struct json_object *resp_obj = json_tokener_parse(resp_json);
    free(resp_json);
    if (!resp_obj) { 
        LOG("Failed to parse JSON");
        snprintf(err_out, 127, "JSON parse failed"); 
        return -1; 
    }

    char action[64] = "noop";
    handle_response(st, model, resp_obj, action);
    json_object_put(resp_obj);

    LOG("Response action: %s", action);

    if (strcmp(action, "noop") != 0)
        printf("[openuf] acción: %s\n", action);

    return 0;
}
