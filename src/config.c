#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#include "debug.h"

#define DBG_TAG "config"

void config_load(openuf_config_t *cfg) {
    strncpy(cfg->controller_ip,  DEFAULT_CONTROLLER_IP,  sizeof(cfg->controller_ip)-1);
    strncpy(cfg->lan_if,         DEFAULT_LAN_IF,         sizeof(cfg->lan_if)-1);
    strncpy(cfg->ufmodel,        DEFAULT_UFMODEL,        sizeof(cfg->ufmodel)-1);
    cfg->inform_interval = DEFAULT_INFORM_INTERVAL;
    cfg->enable_announce = 1;
    cfg->enable_inform   = 1;

    LOG_DBG("cargando %s ...", OPENUF_CONF_FILE);
    FILE *f = fopen(OPENUF_CONF_FILE, "r");
    if (!f) { LOG_WARN("no se encontró %s — usando defaults", OPENUF_CONF_FILE); goto done; }

    int lineno = 0, parsed = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;
        char key[64]={0}, val[192]={0};
        if (sscanf(line, " %63[^= ] = %191s", key, val) != 2) {
            LOG_WARN("línea %d: formato inválido: '%s'", lineno, line);
            continue;
        }
        if      (!strcmp(key,"controller_ip"))   { strncpy(cfg->controller_ip,val,sizeof(cfg->controller_ip)-1); parsed++; }
        else if (!strcmp(key,"lan_if"))          { strncpy(cfg->lan_if,val,sizeof(cfg->lan_if)-1); parsed++; }
        else if (!strcmp(key,"ufmodel"))         { strncpy(cfg->ufmodel,val,sizeof(cfg->ufmodel)-1); parsed++; }
        else if (!strcmp(key,"inform_interval")) { cfg->inform_interval=atoi(val); parsed++; }
        else if (!strcmp(key,"enable_announce")) { cfg->enable_announce=atoi(val); parsed++; }
        else if (!strcmp(key,"enable_inform"))   { cfg->enable_inform=atoi(val); parsed++; }
        else LOG_WARN("clave desconocida en línea %d: '%s'", lineno, key);
        LOG_TRACE("  %s = %s", key, val);
    }
    fclose(f);
    LOG_DBG("%d claves en %d líneas", parsed, lineno);

done:
    LOG_INFO("controller=%s  lan_if=%s  modelo=%s  intervalo=%ds  announce=%d  inform=%d",
             cfg->controller_ip, cfg->lan_if, cfg->ufmodel,
             cfg->inform_interval, cfg->enable_announce, cfg->enable_inform);
    if (cfg->inform_interval < 5) {
        LOG_WARN("inform_interval=%d muy bajo — forzando 5s", cfg->inform_interval);
        cfg->inform_interval = 5;
    }
}
