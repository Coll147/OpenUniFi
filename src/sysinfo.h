#ifndef OPENUF_SYSINFO_H
#define OPENUF_SYSINFO_H

/*
 * openuf - sysinfo.h
 *
 * Lee estadísticas del sistema (CPU, RAM, interfaces, radios).
 * Todas las lecturas son del kernel Linux directamente:
 *
 *   /proc/stat        → uso CPU (deltas entre dos snapshots)
 *   /proc/meminfo     → memoria total/libre/buffer/cache
 *   /proc/net/dev     → contadores rx/tx por interfaz
 *   /sys/class/net/   → speed, duplex, operstate, MAC
 *   iw dev <if> info  → canal actual, potencia TX
 *   iw dev <if> survey dump → utilización del canal
 */

#include <stdbool.h>

/* ── Memoria ─────────────────────────────────────────────────────── */
typedef struct {
    long total_kb;
    long free_kb;
    long buffer_kb;
    long cached_kb;
} mem_stats_t;

int sysinfo_mem(mem_stats_t *out);

/* ── CPU ─────────────────────────────────────────────────────────── */
/* Retorna % uso CPU (0-100). Primera llamada retorna 0 (toma snapshot).
 * Las siguientes calculan el delta respecto a la anterior.
 * Con intervalo de 10s da un buen promedio de uso. */
int sysinfo_cpu_percent(void);

/* ── Interfaz de red ─────────────────────────────────────────────── */
typedef struct {
    char      name[32];
    char      mac[32];
    char      ip[64];
    bool      up;
    int       speed;        /* Mbps: 10/100/1000; -1 si no disponible */
    bool      full_duplex;
    long long rx_bytes;
    long long tx_bytes;
    long long rx_packets;
    long long tx_packets;
    long long rx_errors;
    long long tx_errors;
    long long rx_dropped;
    long long tx_dropped;
    long long rx_multicast;
} iface_stats_t;

int sysinfo_iface(const char *ifname, iface_stats_t *out);

/* ── Radio WiFi ─────────────────────────────────────────────────── */
typedef struct {
    char name[32];
    char iface[32];
    int  channel;
    int  tx_power;
    int  cu_total;    /* % uso canal total */
    int  cu_self_tx;  /* % tiempo transmitiendo */
    int  cu_self_rx;  /* % tiempo recibiendo */
    int  num_sta;
    int  noise;       /* dBm */
} radio_stats_t;

/* iface: "wlan0", "wlan1" */
int sysinfo_radio(const char *iface, radio_stats_t *out);

#endif /* OPENUF_SYSINFO_H */
