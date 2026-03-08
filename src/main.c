/*
 * openuf - main.c
 *
 * Daemon principal. Bucle con tres tareas:
 *   1. Announce  – UDP broadcast+multicast cada 10s (descubrimiento L2)
 *   2. Inform    – HTTP POST cifrado cada 10s (adopción + telemetría)
 *   3. LLDP      – Raw frame L2 cada 30s (topología visual en UniFi)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include "state.h"
#include "ufmodel.h"
#include "announce.h"
#include "inform.h"
#include "lldp.h"

#ifdef ENABLE_LOGGING
FILE *log_fp = NULL;
#endif

#define LLDP_INTERVAL  30   /* segundos entre frames LLDP */
#define LLDP_TTL      120   /* validez del registro LLDP en segundos */

static int get_mac(const char *iface, char *out, size_t sz)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[32] = {0};
    fgets(buf, sizeof(buf), f);
    fclose(f);
    buf[strcspn(buf, "\r\n")] = '\0';
    if (strlen(buf) < 11) return -1;
    strncpy(out, buf, sz-1);
    return 0;
}

static int get_ip(const char *iface, char *out, size_t sz)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    int ret = -1;
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
        strncpy(out, inet_ntoa(sa->sin_addr), sz-1);
        ret = 0;
    }
    close(fd);
    return ret;
}

int main(int argc, char *argv[])
{
    for (int i = 1; i < argc-1; i++)
        if (!strcmp(argv[i], "-c"))
            setenv("OPENUF_CONF", argv[i+1], 1);

    openuf_config_t cfg;
    config_load(&cfg);

#ifdef ENABLE_LOGGING
    if (cfg.enable_logging) {
        log_fp = fopen("/var/log/openuf.log", "a");
        if (log_fp) {
            LOG("Logging enabled");
        }
    }
#endif

    const uf_model_t *model = ufmodel_find(cfg.ufmodel);

    char mac_str[32] = "00:00:00:00:00:00";
    char ip_str[64]  = "192.168.1.1";

    if (get_mac(cfg.lan_if, mac_str, sizeof(mac_str)) != 0)
        get_mac("eth0", mac_str, sizeof(mac_str));
    if (get_ip(cfg.lan_if, ip_str, sizeof(ip_str)) != 0)
        get_ip("eth0", ip_str, sizeof(ip_str));

    openuf_state_t state;
    state_load(&state);
    strncpy(state.mac, mac_str, sizeof(state.mac)-1);
    strncpy(state.ip,  ip_str,  sizeof(state.ip)-1);
    if (!state.hostname[0])
        strncpy(state.hostname, model->display_name, sizeof(state.hostname)-1);

    /* Log initial state */
    LOG("Initial device state: adopted=%d, authkey=%.8s...", state.adopted, 
        state.authkey[0] ? state.authkey : "DEFAULT");

    if (!state.adopted || !state.inform_url[0])
        snprintf(state.inform_url, sizeof(state.inform_url),
                 "http://%s:%d%s", cfg.controller_ip, INFORM_PORT, INFORM_PATH);
    state_save(&state);

    printf("[openuf] Iniciando  modelo=%-8s  MAC=%s  IP=%s\n",
           model->model, mac_str, ip_str);
    printf("[openuf] Controlador: %s\n", state.inform_url);
    printf("[openuf] Adoptado: %s\n", state.adopted ? "sí" : "no");
    printf("[openuf] LLDP disponible: %s\n",
           lldp_available() ? "sí (lldpd)" : "no (solo envío propio)");
    fflush(stdout);

    LOG("Daemon started");

    /* ── Announce socket ────────────────────────────────────────── */
    announce_ctx_t ann;
    if (cfg.enable_announce) {
        if (announce_init(&ann, model, mac_str, ip_str) != 0) {
            LOG("Fallo al iniciar announce");
            cfg.enable_announce = 0;
        }
    }

    /* ── Descripción LLDP del dispositivo ───────────────────────── */
    char lldp_desc[128];
    snprintf(lldp_desc, sizeof(lldp_desc),
             "%s %s%s (openuf)",
             model->model_display, model->fw_pre, model->fw_ver);

    /* ── Bucle principal ─────────────────────────────────────────── */
    time_t start_time    = time(NULL);
    time_t last_announce = 0;
    time_t last_inform   = 0;
    time_t last_lldp     = 0;

    printf("[openuf] Bucle principal iniciado\n");
    fflush(stdout);

    while (1) {
        time_t now = time(NULL);

        /* Announce L2/UDP */
        if (cfg.enable_announce &&
            (now - last_announce) >= ANNOUNCE_INTERVAL) {
            LOG("Sending announce");
            announce_send(&ann);
            last_announce = now;
        }

        /* LLDP frames por cada interfaz ethernet */
        if ((now - last_lldp) >= LLDP_INTERVAL) {
            LOG("Sending LLDP frames");
            for (int i = 0; i < model->port_table_len; i++) {
                const char *iface = model->port_table[i].ifname;
                /* Leer MAC real de la interfaz si disponible */
                char iface_mac[32];
                if (get_mac(iface, iface_mac, sizeof(iface_mac)) != 0)
                    strncpy(iface_mac, mac_str, sizeof(iface_mac)-1);
                lldp_send_frame(iface, iface_mac,
                                state.hostname, lldp_desc, LLDP_TTL);
            }
            last_lldp = now;
        }

        /* Inform HTTP POST */
        if (cfg.enable_inform &&
            (now - last_inform) >= cfg.inform_interval) {
            last_inform = now;
            LOG("Sending inform");

            /* Actualizar IP en cada ciclo */
            char new_ip[64] = {0};
            if (get_ip(cfg.lan_if, new_ip, sizeof(new_ip)) == 0 ||
                get_ip("eth0",     new_ip, sizeof(new_ip)) == 0)
                strncpy(state.ip, new_ip, sizeof(state.ip)-1);

            long uptime = (long)(now - start_time);
            char err[128] = {0};
            if (inform_send(&state, model, uptime, err) != 0) {
                LOG("inform error: %s", err);
            }
        }

        sleep(1);
    }

    announce_close(&ann);

#ifdef ENABLE_LOGGING
    if (log_fp) {
        LOG("Shutting down");
        fclose(log_fp);
    }
#endif

    return 0;
}
