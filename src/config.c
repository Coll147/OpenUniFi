#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "debug.h"

void config_load(openuf_config_t *cfg)
{
    /* Defaults */
    strncpy(cfg->controller_ip,  "192.168.1.1",   sizeof(cfg->controller_ip)-1);
    strncpy(cfg->lan_if,         "br-lan",         sizeof(cfg->lan_if)-1);
    strncpy(cfg->ufmodel,        "u6-inwall",      sizeof(cfg->ufmodel)-1);
    cfg->inform_interval = 10;
    cfg->enable_announce = 1;
    cfg->enable_inform   = 1;

    const char *path = getenv("OPENUF_CONF");
    if (!path) path = OPENUF_CONF_FILE;

    DLOG("config: cargando '%s'", path);
    FILE *f = fopen(path, "r");
    if (!f) {
        DLOG("config: fichero no encontrado, usando defaults");
        return;
    }

    char line[256];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* Ignorar comentarios y lineas vacias */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        line[strcspn(line, "\r\n")] = '\0';

        char key[64] = {0}, val[192] = {0};
        if (sscanf(line, " %63[^= \t] = %191[^\n]", key, val) != 2) {
            DLOG("config: linea %d ignorada: '%s'", lineno, line);
            continue;
        }
        /* Recortar espacios del valor */
        int vlen = strlen(val);
        while (vlen > 0 && (val[vlen-1]==' ' || val[vlen-1]=='\t')) val[--vlen]='\0';

        DLOG("config: linea %d  '%s' = '%s'", lineno, key, val);

        if      (!strcmp(key,"controller_ip"))  strncpy(cfg->controller_ip,  val, sizeof(cfg->controller_ip)-1);
        else if (!strcmp(key,"lan_if"))         strncpy(cfg->lan_if,         val, sizeof(cfg->lan_if)-1);
        else if (!strcmp(key,"ufmodel"))        strncpy(cfg->ufmodel,        val, sizeof(cfg->ufmodel)-1);
        else if (!strcmp(key,"inform_interval"))cfg->inform_interval = atoi(val);
        else if (!strcmp(key,"enable_announce"))cfg->enable_announce = atoi(val);
        else if (!strcmp(key,"enable_inform"))  cfg->enable_inform   = atoi(val);
        else                                    DLOG("config: clave desconocida '%s'", key);
    }
    fclose(f);

    DLOG("config: resultado final — controller_ip=%s lan_if=%s modelo=%s interval=%d announce=%d inform=%d",
         cfg->controller_ip, cfg->lan_if, cfg->ufmodel,
         cfg->inform_interval, cfg->enable_announce, cfg->enable_inform);
}
