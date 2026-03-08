/*
 * openuf - sysinfo.c
 *
 * Lee estadísticas del sistema para el payload inform.
 *
 * ── CPU: /proc/stat ──────────────────────────────────────────────────
 *
 *   Formato: cpu  user nice system idle iowait irq softirq steal
 *
 *   El uso se calcula con dos snapshots separados en el tiempo:
 *     activo = user + nice + system + irq + softirq + steal
 *     total  = activo + idle + iowait
 *     uso %  = (Δactivo / Δtotal) × 100
 *
 * ── Memoria: /proc/meminfo ───────────────────────────────────────────
 *
 *   MemTotal, MemFree, Buffers, Cached
 *   used = total - free - buffers - cached
 *
 * ── Interfaces: /proc/net/dev + /sys/class/net/<iface>/ ─────────────
 *
 *   /proc/net/dev        → contadores acumulados rx/tx
 *   /sys/class/net/speed → velocidad negociada (Mbps)
 *   /sys/class/net/duplex → "full" / "half"
 *   /sys/class/net/operstate → "up" / "down" / "unknown"
 *   /sys/class/net/address → MAC
 *   ioctl SIOCGIFADDR    → IP
 *
 * ── Radio: iw dev <iface> info + survey dump ─────────────────────────
 *
 *   info: canal actual, potencia TX
 *   survey dump: active/busy/tx/rx time → calcular % utilización
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "sysinfo.h"

/* ═══════════════════════════════════════════════════════════════════
   Memoria
   ═══════════════════════════════════════════════════════════════════ */
int sysinfo_mem(mem_stats_t *out)
{
    memset(out, 0, sizeof(*out));
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        long val = 0;
        if      (sscanf(line, "MemTotal: %ld kB",  &val) == 1) out->total_kb  = val;
        else if (sscanf(line, "MemFree: %ld kB",   &val) == 1) out->free_kb   = val;
        else if (sscanf(line, "Buffers: %ld kB",   &val) == 1) out->buffer_kb = val;
        else if (sscanf(line, "Cached: %ld kB",    &val) == 1) out->cached_kb = val;
    }
    fclose(f);
    return (out->total_kb > 0) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════
   CPU
   ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    unsigned long long user, nice, sys, idle, iowait, irq, softirq, steal;
} cpu_snap_t;

static cpu_snap_t g_prev = {0};
static int        g_valid = 0;

static int read_cpu(cpu_snap_t *s)
{
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return -1;
    int r = fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                   &s->user, &s->nice, &s->sys, &s->idle,
                   &s->iowait, &s->irq, &s->softirq, &s->steal);
    fclose(f);
    return (r >= 4) ? 0 : -1;
}

int sysinfo_cpu_percent(void)
{
    cpu_snap_t cur;
    if (read_cpu(&cur) != 0) return 0;

    if (!g_valid) { g_prev = cur; g_valid = 1; return 0; }

    unsigned long long da = (cur.user - g_prev.user)
                          + (cur.nice - g_prev.nice)
                          + (cur.sys  - g_prev.sys)
                          + (cur.irq  - g_prev.irq)
                          + (cur.softirq - g_prev.softirq)
                          + (cur.steal - g_prev.steal);
    unsigned long long di = (cur.idle  - g_prev.idle)
                          + (cur.iowait - g_prev.iowait);
    unsigned long long dt = da + di;
    g_prev = cur;
    return (dt == 0) ? 0 : (int)((da * 100) / dt);
}

/* ═══════════════════════════════════════════════════════════════════
   Interfaz de red
   ═══════════════════════════════════════════════════════════════════ */
static int read_sysfs_str(const char *iface, const char *file,
                           char *out, size_t sz)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/%s", iface, file);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[64] = {0};
    fgets(buf, sizeof(buf), f);
    fclose(f);
    buf[strcspn(buf, "\r\n")] = '\0';
    strncpy(out, buf, sz - 1);
    return (strlen(out) > 0) ? 0 : -1;
}

static int read_sysfs_int(const char *iface, const char *file)
{
    char buf[32] = {0};
    if (read_sysfs_str(iface, file, buf, sizeof(buf)) != 0) return -1;
    int v = -1; sscanf(buf, "%d", &v); return v;
}

static void read_ip_ioctl(const char *iface, char *out, size_t sz)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
        strncpy(out, inet_ntoa(sa->sin_addr), sz - 1);
    }
    close(fd);
}

int sysinfo_iface(const char *ifname, iface_stats_t *out)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->name, ifname, sizeof(out->name) - 1);

    /* MAC, operstate, speed, duplex */
    read_sysfs_str(ifname, "address",  out->mac, sizeof(out->mac));
    char opstate[32] = {0};
    read_sysfs_str(ifname, "operstate", opstate, sizeof(opstate));
    out->up = (strcmp(opstate, "up") == 0 || strcmp(opstate, "unknown") == 0);
    int sp = read_sysfs_int(ifname, "speed");
    out->speed = (sp > 0) ? sp : 1000;

    char dup[16] = {0};
    read_sysfs_str(ifname, "duplex", dup, sizeof(dup));
    out->full_duplex = (strncmp(dup, "full", 4) == 0);

    /* IP */
    read_ip_ioctl(ifname, out->ip, sizeof(out->ip));

    /* Contadores de /proc/net/dev */
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return 0;

    char line[512];
    fgets(line, sizeof(line), f); /* skip header lines */
    fgets(line, sizeof(line), f);

    while (fgets(line, sizeof(line), f)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;

        /* Extraer nombre de interfaz (puede tener espacios al inicio) */
        size_t end = colon - line;
        while (end > 0 && line[end-1] == ' ') end--;
        size_t start = 0;
        while (start < end && line[start] == ' ') start++;
        char name[32] = {0};
        size_t nlen = end - start;
        if (nlen >= sizeof(name)) continue;
        strncpy(name, line + start, nlen);

        if (strcmp(name, ifname) != 0) continue;

        long long rb,rp,re,rd,rf,rframe,rcomp,rmulti;
        long long tb,tp,te,td,tf,tcol,tcomp,tcarr;
        sscanf(colon+1,
               "%lld %lld %lld %lld %lld %lld %lld %lld"
               " %lld %lld %lld %lld %lld %lld %lld %lld",
               &rb,&rp,&re,&rd,&rf,&rframe,&rcomp,&rmulti,
               &tb,&tp,&te,&td,&tf,&tcol,&tcomp,&tcarr);
        out->rx_bytes    = rb; out->rx_packets  = rp;
        out->rx_errors   = re; out->rx_dropped  = rd;
        out->rx_multicast= rmulti;
        out->tx_bytes    = tb; out->tx_packets  = tp;
        out->tx_errors   = te; out->tx_dropped  = td;
        break;
    }
    fclose(f);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
   Radio WiFi
   ═══════════════════════════════════════════════════════════════════

   1. iw dev wlan0 info  → canal y potencia
      Ejemplo:
        Interface wlan0
          channel 6 (2437 MHz), width: 20 MHz
          txpower 20.00 dBm

   2. iw dev wlan0 survey dump  → utilización del canal
      Buscamos el bloque con "[in use]":
        frequency: 2437 MHz [in use]
        channel active time: 12345 ms
        channel busy time:     987 ms
        channel transmit time: 456 ms
        channel receive time:  321 ms

   Calculamos:
     cu_total   = busy/active × 100
     cu_self_tx = transmit/active × 100
     cu_self_rx = receive/active × 100
*/
int sysinfo_radio(const char *iface, radio_stats_t *out)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->iface, iface, sizeof(out->iface) - 1);
    out->noise = -95;

    char cmd[128];

    /* iw dev <iface> info */
    snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null", iface);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;

    char line[256];
    while (fgets(line, sizeof(line), p)) {
        int ch; float mhz;
        if (sscanf(line, " channel %d (%f MHz)", &ch, &mhz) == 2)
            out->channel = ch;
        float tp;
        if (sscanf(line, " txpower %f dBm", &tp) == 1)
            out->tx_power = (int)tp;
    }
    pclose(p);

    /* iw dev <iface> survey dump */
    snprintf(cmd, sizeof(cmd), "iw dev %s survey dump 2>/dev/null", iface);
    p = popen(cmd, "r");
    if (!p) return 0;

    long long active=0, busy=0, tx_t=0, rx_t=0;
    int in_use = 0;
    while (fgets(line, sizeof(line), p)) {
        if (strstr(line, "[in use]")) {
            in_use = 1; active=busy=tx_t=rx_t=0; continue;
        }
        if (!in_use) continue;
        /* Nueva frecuencia sin [in use] resetea el bloque */
        if (strstr(line, "frequency:") && !strstr(line, "[in use]")) {
            in_use = 0; continue;
        }
        float noise; long long val;
        if (sscanf(line, " noise: %f dBm", &noise) == 1) out->noise = (int)noise;
        if (sscanf(line, " channel active time: %lld ms", &val) == 1)  active = val;
        if (sscanf(line, " channel busy time: %lld ms", &val) == 1)    busy   = val;
        if (sscanf(line, " channel transmit time: %lld ms", &val) == 1) tx_t  = val;
        if (sscanf(line, " channel receive time: %lld ms", &val) == 1)  rx_t  = val;
    }
    pclose(p);

    if (active > 0) {
        out->cu_total   = (int)(busy * 100 / active);
        out->cu_self_tx = (int)(tx_t * 100 / active);
        out->cu_self_rx = (int)(rx_t * 100 / active);
    }

    /* Número de clientes asociados */
    snprintf(cmd, sizeof(cmd),
             "iw dev %s station dump 2>/dev/null | grep -c '^Station'",
             iface);
    p = popen(cmd, "r");
    if (p) { fscanf(p, "%d", &out->num_sta); pclose(p); }

    return 0;
}
