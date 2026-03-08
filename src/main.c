/*
 * openuf - main.c — Bucle principal: Announce + Inform + LLDP
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
#include "debug.h"

#define DBG_TAG "main"
#define LLDP_INTERVAL 30
#define LLDP_TTL     120

static int get_mac(const char *iface, char *out, size_t sz) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface);
    LOG_TRACE("leyendo MAC de %s", path);
    FILE *f = fopen(path, "r");
    if (!f) { LOG_DBG("iface '%s' no existe (sin MAC)", iface); return -1; }
    char buf[32] = {0};
    fgets(buf, sizeof(buf), f); fclose(f);
    buf[strcspn(buf, "\r\n")] = '\0';
    if (strlen(buf) < 11) { LOG_WARN("MAC inválida en '%s': '%s'", iface, buf); return -1; }
    strncpy(out, buf, sz-1);
    LOG_TRACE("MAC('%s') = %s", iface, out);
    return 0;
}

static int get_ip(const char *iface, char *out, size_t sz) {
    LOG_TRACE("ioctl SIOCGIFADDR en '%s'", iface);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { LOG_ERR("socket() falló: %m"); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    int ret = -1;
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
        strncpy(out, inet_ntoa(sa->sin_addr), sz-1);
        LOG_TRACE("IP('%s') = %s", iface, out);
        ret = 0;
    } else {
        LOG_TRACE("SIOCGIFADDR en '%s': sin IP todavía", iface);
    }
    close(fd); return ret;
}

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc-1; i++)
        if (!strcmp(argv[i], "-c")) setenv("OPENUF_CONF", argv[i+1], 1);

    debug_print_level();
    LOG_INFO("══════════════════════════════════════");
    LOG_INFO("openuf v0.4.0 arrancando");
    LOG_INFO("══════════════════════════════════════");

    openuf_config_t cfg;
    config_load(&cfg);

    const uf_model_t *model = ufmodel_find(cfg.ufmodel);
    LOG_INFO("modelo: %s (%s) — %d radios, %d puertos",
             model->model, model->model_display,
             model->radio_table_len, model->port_table_len);

    char mac_str[32] = "00:00:00:00:00:00";
    char ip_str[64]  = "192.168.1.1";
    LOG_DBG("detectando identidad en '%s'...", cfg.lan_if);
    if (get_mac(cfg.lan_if, mac_str, sizeof(mac_str)) != 0) {
        LOG_WARN("no hay MAC en '%s', probando eth0", cfg.lan_if);
        get_mac("eth0", mac_str, sizeof(mac_str));
    }
    if (get_ip(cfg.lan_if, ip_str, sizeof(ip_str)) != 0) {
        LOG_WARN("no hay IP en '%s', probando eth0", cfg.lan_if);
        get_ip("eth0", ip_str, sizeof(ip_str));
    }
    LOG_INFO("identidad: MAC=%s  IP=%s", mac_str, ip_str);

    openuf_state_t state;
    state_load(&state);
    strncpy(state.mac, mac_str, sizeof(state.mac)-1);
    strncpy(state.ip,  ip_str,  sizeof(state.ip)-1);
    if (!state.hostname[0])
        strncpy(state.hostname, model->display_name, sizeof(state.hostname)-1);

    if (!state.adopted || !state.inform_url[0]) {
        snprintf(state.inform_url, sizeof(state.inform_url),
                 "http://%s:%d%s", cfg.controller_ip, INFORM_PORT, INFORM_PATH);
        LOG_DBG("URL por defecto: %s", state.inform_url);
    }
    state_save(&state);

    LOG_INFO("estado: adoptado=%-3s  cfgversion=%s",
             state.adopted ? "SÍ" : "NO", state.cfgversion);
    LOG_INFO("inform URL: %s", state.inform_url);
    if (state.adopted)
        LOG_DBG("clave activa: %.8s...", state.authkey);
    else
        LOG_DBG("usando clave por defecto (no adoptado)");

    /* Announce */
    announce_ctx_t ann;
    if (cfg.enable_announce) {
        LOG_DBG("inicializando announce (UDP 10001)...");
        if (announce_init(&ann, model, mac_str, ip_str) != 0) {
            LOG_ERR("fallo announce — desactivando");
            cfg.enable_announce = 0;
        } else {
            LOG_INFO("announce: listo (broadcast + multicast 233.89.188.1)");
        }
    } else {
        LOG_INFO("announce: desactivado por config");
    }

    /* LLDP */
    char lldp_desc[128];
    snprintf(lldp_desc, sizeof(lldp_desc), "%s %s%s (openuf)",
             model->model_display, model->fw_pre, model->fw_ver);
    LOG_INFO("LLDP: '%s'  lldpd=%s",
             lldp_desc, lldp_available() ? "sí" : "no (sólo raw)");

    time_t start      = time(NULL);
    time_t t_announce = 0, t_inform = 0, t_lldp = 0;
    int n_inform = 0, n_announce = 0;

    LOG_INFO("══════════════════════════════════════");
    LOG_INFO("bucle principal iniciado");
    LOG_INFO("══════════════════════════════════════");

    while (1) {
        time_t now    = time(NULL);
        long   uptime = (long)(now - start);

        if (cfg.enable_announce && (now - t_announce) >= ANNOUNCE_INTERVAL) {
            LOG_DBG("announce #%d (uptime=%lds)", ++n_announce, uptime);
            announce_send(&ann);
            t_announce = now;
        }

        if ((now - t_lldp) >= LLDP_INTERVAL) {
            LOG_DBG("LLDP frames en %d interfaces...", model->port_table_len);
            for (int i = 0; i < model->port_table_len; i++) {
                const char *iface = model->port_table[i].ifname;
                char imac[32]; if (get_mac(iface, imac, sizeof(imac)) != 0)
                    strncpy(imac, mac_str, sizeof(imac)-1);
                int r = lldp_send_frame(iface, imac, state.hostname, lldp_desc, LLDP_TTL);
                if (r == 0) LOG_DBG("  LLDP enviado en %s", iface);
                else        LOG_TRACE("  LLDP en %s: sin permisos o iface down", iface);
            }
            t_lldp = now;
        }

        if (cfg.enable_inform && (now - t_inform) >= cfg.inform_interval) {
            t_inform = now; n_inform++;
            char new_ip[64] = {0};
            if (get_ip(cfg.lan_if, new_ip, sizeof(new_ip)) == 0 ||
                get_ip("eth0",     new_ip, sizeof(new_ip)) == 0) {
                if (strcmp(new_ip, state.ip) != 0) {
                    LOG_INFO("IP cambió: %s → %s", state.ip, new_ip);
                    strncpy(state.ip, new_ip, sizeof(state.ip)-1);
                }
            }
            LOG_DBG("─── inform #%d (uptime=%lds, adoptado=%s) ───",
                    n_inform, uptime, state.adopted ? "sí" : "no");
            char err[128] = {0};
            if (inform_send(&state, model, uptime, err) != 0)
                LOG_ERR("inform #%d: %s", n_inform, err);
            else
                LOG_DBG("inform #%d OK", n_inform);
        }

        sleep(1);
    }
    announce_close(&ann);
    return 0;
}
