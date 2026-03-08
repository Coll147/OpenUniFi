/*
 * openuf - main.c
 *
 * Daemon principal. Bucle con tres tareas:
 *   1. Announce  – UDP broadcast+multicast cada 10s (descubrimiento L2)
 *   2. Inform    – HTTP POST cifrado cada 10s (adopcion + telemetria)
 *   3. LLDP      – Raw frame L2 cada 30s (topologia visual en UniFi)
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

#include "debug.h"
#include "config.h"
#include "state.h"
#include "ufmodel.h"
#include "announce.h"
#include "inform.h"
#include "lldp.h"

#define LLDP_INTERVAL  30
#define LLDP_TTL      120

static int get_mac(const char *iface, char *out, size_t sz)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface);
    DLOG("get_mac: leyendo %s", path);
    FILE *f = fopen(path, "r");
    if (!f) { DLOG("get_mac: no se pudo abrir %s", path); return -1; }
    char buf[32] = {0};
    fgets(buf, sizeof(buf), f);
    fclose(f);
    buf[strcspn(buf, "\r\n")] = '\0';
    if (strlen(buf) < 11) { DLOG("get_mac: MAC invalido '%s'", buf); return -1; }
    strncpy(out, buf, sz-1);
    DLOG("get_mac: %s → %s", iface, out);
    return 0;
}

static int get_ip(const char *iface, char *out, size_t sz)
{
    DLOG("get_ip: ioctl SIOCGIFADDR en %s", iface);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    int ret = -1;
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
        strncpy(out, inet_ntoa(sa->sin_addr), sz-1);
        DLOG("get_ip: %s → %s", iface, out);
        ret = 0;
    } else {
        DLOG("get_ip: ioctl fallo en %s", iface);
    }
    close(fd);
    return ret;
}

int main(int argc, char *argv[])
{
    DLOG("main: arrancando openuf (DEBUG activado)");

    for (int i = 1; i < argc-1; i++)
        if (!strcmp(argv[i], "-c")) {
            setenv("OPENUF_CONF", argv[i+1], 1);
            DLOG("main: usando fichero de config '%s'", argv[i+1]);
        }

    openuf_config_t cfg;
    config_load(&cfg);
    DLOG("main: config cargada — controller_ip=%s lan_if=%s modelo=%s interval=%d",
         cfg.controller_ip, cfg.lan_if, cfg.ufmodel, cfg.inform_interval);

    const uf_model_t *model = ufmodel_find(cfg.ufmodel);
    DLOG("main: modelo resuelto → '%s' (%s) radios=%d puertos=%d",
         model->model, model->display_name,
         model->radio_table_len, model->port_table_len);

    char mac_str[32] = "00:00:00:00:00:00";
    char ip_str[64]  = "192.168.1.1";

    if (get_mac(cfg.lan_if, mac_str, sizeof(mac_str)) != 0) {
        DLOG("main: get_mac fallo en %s, probando eth0", cfg.lan_if);
        get_mac("eth0", mac_str, sizeof(mac_str));
    }
    if (get_ip(cfg.lan_if, ip_str, sizeof(ip_str)) != 0) {
        DLOG("main: get_ip fallo en %s, probando eth0", cfg.lan_if);
        get_ip("eth0", ip_str, sizeof(ip_str));
    }
    DLOG("main: identidad final — MAC=%s IP=%s", mac_str, ip_str);

    openuf_state_t state;
    state_load(&state);
    DLOG("main: estado cargado — adopted=%s authkey=%.8s... cfgver=%s",
         state.adopted ? "si" : "no",
         state.authkey[0] ? state.authkey : "(default)",
         state.cfgversion);

    strncpy(state.mac, mac_str, sizeof(state.mac)-1);
    strncpy(state.ip,  ip_str,  sizeof(state.ip)-1);
    if (!state.hostname[0]) {
        strncpy(state.hostname, model->display_name, sizeof(state.hostname)-1);
        DLOG("main: hostname no configurado, usando '%s'", state.hostname);
    }

    if (!state.adopted || !state.inform_url[0]) {
        snprintf(state.inform_url, sizeof(state.inform_url),
                 "http://%s:%d%s", cfg.controller_ip, INFORM_PORT, INFORM_PATH);
        DLOG("main: inform_url construida desde config: %s", state.inform_url);
    } else {
        DLOG("main: inform_url desde estado: %s", state.inform_url);
    }
    state_save(&state);

    printf("[openuf] Iniciando  modelo=%-8s  MAC=%s  IP=%s\n",
           model->model, mac_str, ip_str);
    printf("[openuf] Controlador: %s\n", state.inform_url);
    printf("[openuf] Adoptado: %s\n", state.adopted ? "si" : "no");
    printf("[openuf] LLDP disponible: %s\n",
           lldp_available() ? "si (lldpd)" : "no (solo envio propio)");
    fflush(stdout);

    /* Announce socket */
    announce_ctx_t ann;
    if (cfg.enable_announce) {
        DLOG("main: inicializando announce socket");
        if (announce_init(&ann, model, mac_str, ip_str) != 0) {
            fprintf(stderr, "[openuf] Fallo al iniciar announce\n");
            cfg.enable_announce = 0;
        } else {
            DLOG("main: announce OK — broadcast + multicast 233.89.188.1:%d", ANNOUNCE_PORT);
        }
    } else {
        DLOG("main: announce desactivado en config");
    }

    char lldp_desc[128];
    snprintf(lldp_desc, sizeof(lldp_desc), "%s %s%s (openuf)",
             model->model_display, model->fw_pre, model->fw_ver);
    DLOG("main: descripcion LLDP: '%s'", lldp_desc);

    time_t start_time    = time(NULL);
    time_t last_announce = 0;
    time_t last_inform   = 0;
    time_t last_lldp     = 0;

    printf("[openuf] Bucle principal iniciado\n");
    fflush(stdout);
    DLOG("main: entrando en bucle principal — announce_interval=%ds inform_interval=%ds lldp_interval=%ds",
         ANNOUNCE_INTERVAL, cfg.inform_interval, LLDP_INTERVAL);

    while (1) {
        time_t now = time(NULL);

        /* Announce L2/UDP */
        if (cfg.enable_announce &&
            (now - last_announce) >= ANNOUNCE_INTERVAL) {
            DLOG("announce: enviando paquete (contador=%u uptime=%u)",
                 ann.counter + 1, ann.uptime + 10);
            announce_send(&ann);
            last_announce = now;
        }

        /* LLDP frames */
        if ((now - last_lldp) >= LLDP_INTERVAL) {
            DLOG("lldp: enviando frames por %d interfaces", model->port_table_len);
            for (int i = 0; i < model->port_table_len; i++) {
                const char *iface = model->port_table[i].ifname;
                char iface_mac[32];
                if (get_mac(iface, iface_mac, sizeof(iface_mac)) != 0)
                    strncpy(iface_mac, mac_str, sizeof(iface_mac)-1);
                DLOG("lldp: enviando frame en %s (mac=%s ttl=%d)", iface, iface_mac, LLDP_TTL);
                int r = lldp_send_frame(iface, iface_mac,
                                        state.hostname, lldp_desc, LLDP_TTL);
                DLOG("lldp: send %s → %s", iface, r == 0 ? "OK" : "FALLO (sin root?)");
            }
            last_lldp = now;
        }

        /* Inform HTTP POST */
        if (cfg.enable_inform &&
            (now - last_inform) >= cfg.inform_interval) {
            last_inform = now;
            long uptime = (long)(now - start_time);
            DLOG("inform: iniciando ciclo — uptime=%lds adopted=%s key=%.8s...",
                 uptime, state.adopted ? "si" : "no",
                 state.authkey[0] ? state.authkey : "DEFAULT");

            char new_ip[64] = {0};
            if (get_ip(cfg.lan_if, new_ip, sizeof(new_ip)) == 0 ||
                get_ip("eth0",     new_ip, sizeof(new_ip)) == 0) {
                if (strcmp(new_ip, state.ip) != 0) {
                    DLOG("inform: IP cambio %s → %s", state.ip, new_ip);
                }
                strncpy(state.ip, new_ip, sizeof(state.ip)-1);
            }

            char err[128] = {0};
            if (inform_send(&state, model, uptime, err) != 0) {
                fprintf(stderr, "[openuf] inform error: %s\n", err);
                DLOG("inform: ERROR — %s", err);
                fflush(stderr);
            } else {
                DLOG("inform: ciclo completado con exito");
            }
        }

        sleep(1);
    }

    announce_close(&ann);
    return 0;
}
