#ifndef OPENUF_CLIENTS_H
#define OPENUF_CLIENTS_H

/*
 * openuf - clients.h
 *
 * Enumera clientes conectados (WiFi y ethernet) para el sta_table
 * del payload inform.
 *
 * ── WiFi: iw dev <iface> station dump ────────────────────────────
 *
 *   Por cada cliente asociado devuelve:
 *     MAC, señal (dBm), tx/rx bitrate (MBit/s), tx/rx bytes,
 *     tx/rx packets, connected time (segundos)
 *
 * ── IP del cliente: /proc/net/arp ───────────────────────────────
 *
 *   Cruce MAC → IP. Solo entradas completas (flags=0x2).
 *
 * ── Hostname: /tmp/dhcp.leases (dnsmasq) ────────────────────────
 *
 *   Formato: timestamp MAC IP hostname client-id
 *
 * ── Ethernet: bridge fdb show ───────────────────────────────────
 *
 *   MACs dinámicas (no permanent, no multicast) en el bridge.
 *
 * ── CCQ (Client Connection Quality) ─────────────────────────────
 *
 *   Métrica 0-1000 basada en RSSI. El controlador la muestra
 *   como barra de calidad de señal del cliente.
 *     CCQ = clamp((signal + 90) * 25, 0, 1000)
 */

#include <stdbool.h>
#include <stddef.h>
#include <json-c/json.h>

#define MAX_STA 128

typedef struct {
    char      mac[32];
    char      ip[64];
    char      hostname[64];
    int       signal;     /* RSSI dBm (negativo) */
    int       noise;      /* dBm */
    int       rssi;       /* SNR ≈ signal - noise */
    long      tx_rate;    /* kbps */
    long      rx_rate;
    long long tx_bytes;
    long long rx_bytes;
    long long tx_packets;
    long long rx_packets;
    int       uptime;     /* segundos conectado */
    char      radio[8];   /* "ng" / "na" / "6g" */
    int       channel;
    char      vap_name[32];
    bool      is_11r;
    int       ccq;
    bool      is_wired;
} sta_info_t;

/* Lee clientes WiFi de una interfaz. Devuelve nº de clientes. */
int clients_read_wifi(const char *wlan_iface,
                      const char *radio_band,
                      int         channel,
                      sta_info_t *out,
                      int         max_out);

/* Construye JSON array sta_table para un VAP.
 * El caller debe liberar con json_object_put(). */
struct json_object *clients_build_sta_table(const char *wlan_iface,
                                            const char *radio_band,
                                            int         channel,
                                            const char *vap_name);

/* Busca IP en /proc/net/arp dado un MAC. */
int clients_mac_to_ip(const char *mac, char *ip_out, size_t sz);

/* Busca hostname en /tmp/dhcp.leases dado un MAC. */
int clients_mac_to_hostname(const char *mac, char *out, size_t sz);

#endif /* OPENUF_CLIENTS_H */
