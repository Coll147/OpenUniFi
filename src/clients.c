/*
 * openuf - clients.c
 *
 * Enumera clientes para el payload inform → sta_table.
 *
 * ── Parseo de iw dev station dump ───────────────────────────────────
 *
 * La salida tiene bloques por cliente:
 *
 *   Station aa:bb:cc:dd:ee:ff (on wlan0)
 *     inactive time:   120 ms
 *     rx bytes:        2000000
 *     rx packets:      2000
 *     tx bytes:        5000000
 *     tx packets:      5000
 *     signal:          -62 [-62, -65] dBm
 *     tx bitrate:      144.4 MBit/s MCS 15
 *     rx bitrate:      108.0 MBit/s
 *     connected time:  1800 seconds
 *
 * Detectamos el inicio de cada cliente con "Station XX:XX:..." y
 * rellenamos los campos hasta encontrar el siguiente cliente.
 *
 * ── ARP: /proc/net/arp ─────────────────────────────────────────────
 *
 *   IP           HW type  Flags   HW addr            Mask  Device
 *   192.168.1.x  0x1      0x2     aa:bb:cc:dd:ee:ff  *     br-lan
 *
 *   Flags 0x2 = entrada completa (reachable).
 *   Flags 0x0 = incompleta (no responde ARP), ignorar.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <json-c/json.h>

#include "clients.h"

/* ─── Normalizar MAC a minúsculas ─────────────────────────────────── */
static void mac_lower(const char *src, char *dst, size_t sz)
{
    for (size_t i = 0; src[i] && i < sz-1; i++)
        dst[i] = tolower((unsigned char)src[i]);
    dst[strlen(src) < sz ? strlen(src) : sz-1] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════
   /proc/net/arp — MAC → IP
   ═══════════════════════════════════════════════════════════════════ */
int clients_mac_to_ip(const char *mac, char *ip_out, size_t sz)
{
    ip_out[0] = '\0';
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;

    char line[256];
    fgets(line, sizeof(line), f); /* skip header */

    char ml[32] = {0};
    mac_lower(mac, ml, sizeof(ml));

    while (fgets(line, sizeof(line), f)) {
        char ip[64], hw_type[16], flags[16], hw[32], mask[16], dev[32];
        if (sscanf(line, "%63s %15s %15s %31s %15s %31s",
                   ip, hw_type, flags, hw, mask, dev) != 6) continue;
        if (strcmp(flags, "0x2") != 0) continue;
        char hl[32] = {0};
        mac_lower(hw, hl, sizeof(hl));
        if (strcmp(ml, hl) == 0) {
            strncpy(ip_out, ip, sz-1);
            fclose(f); return 0;
        }
    }
    fclose(f);
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════
   /tmp/dhcp.leases — MAC → hostname
   ═══════════════════════════════════════════════════════════════════ */
int clients_mac_to_hostname(const char *mac, char *out, size_t sz)
{
    out[0] = '\0';
    static const char *files[] = {
        "/tmp/dhcp.leases",
        "/var/lib/misc/dnsmasq.leases",
        NULL
    };

    char ml[32] = {0};
    mac_lower(mac, ml, sizeof(ml));

    for (int fi = 0; files[fi]; fi++) {
        FILE *f = fopen(files[fi], "r");
        if (!f) continue;
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            long ts;
            char lm[32], lip[64], lh[64], lcid[64];
            if (sscanf(line, "%ld %31s %63s %63s %63s",
                       &ts, lm, lip, lh, lcid) < 4) continue;
            char ll[32] = {0};
            mac_lower(lm, ll, sizeof(ll));
            if (strcmp(ml, ll) == 0 && strcmp(lh, "*") != 0) {
                strncpy(out, lh, sz-1);
                fclose(f); return 0;
            }
        }
        fclose(f);
    }
    return -1;
}

/* ─── Parsear tasa de bits "144.4 MBit/s ..." → kbps ───────────── */
static long parse_rate_kbps(const char *s)
{
    float r = 0;
    sscanf(s, "%f MBit/s", &r);
    return (long)(r * 1000.0f);
}

/* ═══════════════════════════════════════════════════════════════════
   iw dev <iface> station dump → array sta_info_t
   ═══════════════════════════════════════════════════════════════════ */
int clients_read_wifi(const char *wlan_iface,
                      const char *radio_band,
                      int         channel,
                      sta_info_t *out,
                      int         max_out)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd),
             "iw dev %s station dump 2>/dev/null", wlan_iface);
    FILE *p = popen(cmd, "r");
    if (!p) return 0;

    int count = 0;
    sta_info_t *cur = NULL;
    char line[256];

    while (fgets(line, sizeof(line), p)) {
        line[strcspn(line, "\r\n")] = '\0';

        /* ── Nueva estación ──────────────────────────────────────── */
        char mac[32], on_iface[32];
        if (sscanf(line, "Station %31s (on %31[^)])", mac, on_iface) == 2) {
            if (count >= max_out) break;
            cur = &out[count++];
            memset(cur, 0, sizeof(*cur));
            strncpy(cur->mac,      mac,        sizeof(cur->mac)-1);
            strncpy(cur->vap_name, wlan_iface, sizeof(cur->vap_name)-1);
            strncpy(cur->radio,    radio_band, sizeof(cur->radio)-1);
            cur->channel = channel;
            cur->noise   = -95;
            continue;
        }
        if (!cur) continue;

        /* ── Contadores ──────────────────────────────────────────── */
        long long llv;
        if (sscanf(line, " rx bytes: %lld", &llv) == 1) { cur->rx_bytes   = llv; continue; }
        if (sscanf(line, " tx bytes: %lld", &llv) == 1) { cur->tx_bytes   = llv; continue; }
        if (sscanf(line, " rx packets: %lld", &llv) == 1) { cur->rx_packets = llv; continue; }
        if (sscanf(line, " tx packets: %lld", &llv) == 1) { cur->tx_packets = llv; continue; }

        /* ── Señal ───────────────────────────────────────────────── */
        int sig;
        if (sscanf(line, " signal: %d", &sig) == 1) { cur->signal = sig; continue; }

        /* ── Bitrate ─────────────────────────────────────────────── */
        char rest[128];
        if (sscanf(line, " tx bitrate: %127[^\n]", rest) == 1) {
            cur->tx_rate = parse_rate_kbps(rest); continue;
        }
        if (sscanf(line, " rx bitrate: %127[^\n]", rest) == 1) {
            cur->rx_rate = parse_rate_kbps(rest); continue;
        }

        /* ── Tiempo conectado ────────────────────────────────────── */
        int upt;
        if (sscanf(line, " connected time: %d seconds", &upt) == 1) {
            cur->uptime = upt; continue;
        }
    }
    pclose(p);

    /* ── Enriquecer: IP, hostname, rssi, CCQ ─────────────────────── */
    for (int i = 0; i < count; i++) {
        sta_info_t *s = &out[i];
        clients_mac_to_ip(s->mac, s->ip, sizeof(s->ip));
        clients_mac_to_hostname(s->mac, s->hostname, sizeof(s->hostname));
        if (!s->hostname[0])
            strncpy(s->hostname, s->mac, sizeof(s->hostname)-1);

        /* RSN = SNR estimado (signal - noise) */
        s->rssi = s->signal - s->noise;
        if (s->rssi < 0) s->rssi = 0;

        /* CCQ: métrica 0-1000
         * -50 dBm → 1000 (excelente)
         * -90 dBm → 0    (muy malo)
         * fórmula lineal: (signal + 90) * 25, limitado 0-1000 */
        int ccq = (s->signal + 90) * 25;
        s->ccq = (ccq < 0) ? 0 : (ccq > 1000) ? 1000 : ccq;
    }
    return count;
}

/* ═══════════════════════════════════════════════════════════════════
   Construir JSON sta_table para un VAP
   ═══════════════════════════════════════════════════════════════════

   El JSON array resultante se anida dentro de vap_table[i].sta_table
   en el payload inform. Ejemplo de entrada:
   {
     "mac": "aa:bb:cc:dd:ee:ff",
     "ip": "192.168.1.100",
     "hostname": "mi-movil",
     "signal": -62,
     "rssi": 33,
     "noise": -95,
     "tx_rate": 144000,
     "rx_rate": 108000,
     "tx_bytes": 5000000,
     "rx_bytes": 2000000,
     "tx_packets": 5000,
     "rx_packets": 2000,
     "uptime": 1800,
     "radio": "ng",
     "channel": 6,
     "vap_name": "ath0",
     "is_11r": false,
     "ccq": 700
   }
*/
struct json_object *clients_build_sta_table(const char *wlan_iface,
                                            const char *radio_band,
                                            int         channel,
                                            const char *vap_name)
{
    sta_info_t stas[MAX_STA];
    int n = clients_read_wifi(wlan_iface, radio_band, channel,
                              stas, MAX_STA);

    struct json_object *arr = json_object_new_array();
    for (int i = 0; i < n; i++) {
        sta_info_t *s = &stas[i];
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "mac",        json_object_new_string(s->mac));
        json_object_object_add(o, "ip",         json_object_new_string(s->ip));
        json_object_object_add(o, "hostname",   json_object_new_string(s->hostname));
        json_object_object_add(o, "signal",     json_object_new_int(s->signal));
        json_object_object_add(o, "rssi",       json_object_new_int(s->rssi));
        json_object_object_add(o, "noise",      json_object_new_int(s->noise));
        json_object_object_add(o, "tx_rate",    json_object_new_int64(s->tx_rate));
        json_object_object_add(o, "rx_rate",    json_object_new_int64(s->rx_rate));
        json_object_object_add(o, "tx_bytes",   json_object_new_int64(s->tx_bytes));
        json_object_object_add(o, "rx_bytes",   json_object_new_int64(s->rx_bytes));
        json_object_object_add(o, "tx_packets", json_object_new_int64(s->tx_packets));
        json_object_object_add(o, "rx_packets", json_object_new_int64(s->rx_packets));
        json_object_object_add(o, "uptime",     json_object_new_int(s->uptime));
        json_object_object_add(o, "radio",      json_object_new_string(s->radio));
        json_object_object_add(o, "channel",    json_object_new_int(s->channel));
        json_object_object_add(o, "vap_name",   json_object_new_string(
            vap_name ? vap_name : wlan_iface));
        json_object_object_add(o, "is_11r",     json_object_new_boolean(s->is_11r));
        json_object_object_add(o, "ccq",        json_object_new_int(s->ccq));
        json_object_object_add(o, "idletime",   json_object_new_int(0));
        json_object_array_add(arr, o);
    }
    return arr;
}
