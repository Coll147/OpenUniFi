#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"

void config_load(openuf_config_t *cfg)
{
    /* Defaults */
    strncpy(cfg->controller_ip,   DEFAULT_CONTROLLER_IP,   sizeof(cfg->controller_ip) - 1);
    strncpy(cfg->lan_if,          DEFAULT_LAN_IF,          sizeof(cfg->lan_if) - 1);
    strncpy(cfg->ufmodel,         DEFAULT_UFMODEL,         sizeof(cfg->ufmodel) - 1);
    cfg->inform_interval = DEFAULT_INFORM_INTERVAL;
    cfg->enable_announce = 1;
    cfg->enable_inform   = 1;
    cfg->enable_logging  = 0;

    FILE *f = fopen(OPENUF_CONF_FILE, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        line[strcspn(line, "\r\n")] = '\0';
        /* Skip comments / empty */
        if (line[0] == '#' || line[0] == '\0') continue;

        char key[64] = {0}, val[192] = {0};
        if (sscanf(line, " %63[^= ] = %191s", key, val) != 2) continue;

        if      (!strcmp(key, "controller_ip"))    strncpy(cfg->controller_ip, val, sizeof(cfg->controller_ip) - 1);
        else if (!strcmp(key, "lan_if"))           strncpy(cfg->lan_if,        val, sizeof(cfg->lan_if) - 1);
        else if (!strcmp(key, "ufmodel"))          strncpy(cfg->ufmodel,       val, sizeof(cfg->ufmodel) - 1);
        else if (!strcmp(key, "inform_interval"))  cfg->inform_interval = atoi(val);
        else if (!strcmp(key, "enable_announce"))  cfg->enable_announce = atoi(val);
        else if (!strcmp(key, "enable_inform"))    cfg->enable_inform   = atoi(val);
        else if (!strcmp(key, "enable_logging"))   cfg->enable_logging = atoi(val);
    }
    fclose(f);
}
