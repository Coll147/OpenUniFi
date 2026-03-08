#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include "state.h"
#include "config.h"
#include "debug.h"

static void state_defaults(openuf_state_t *st)
{
    memset(st, 0, sizeof(*st));
    st->adopted = false;
    strncpy(st->authkey,    DEFAULT_AUTH_KEY, sizeof(st->authkey)-1);
    strncpy(st->cfgversion, "0",              sizeof(st->cfgversion)-1);
    DLOG("state: inicializado con valores por defecto (key=DEFAULT)");
}

void state_load(openuf_state_t *st)
{
    state_defaults(st);

    DLOG("state: cargando desde %s", OPENUF_STATE_FILE);
    FILE *f = fopen(OPENUF_STATE_FILE, "r");
    if (!f) {
        DLOG("state: fichero no existe — primera ejecucion");
        return;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    DLOG("state: fichero abierto, tamano=%ld bytes", sz);

    if (sz <= 0 || sz > 4096) {
        DLOG("state: tamano invalido (%ld bytes), ignorando", sz);
        fclose(f); return;
    }

    char *buf = malloc(sz+1);
    if (!buf) { DLOG("state: OOM"); fclose(f); return; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);

    DLOG("state: JSON raw (%ld bytes): %s", sz, buf);

    struct json_object *root = json_tokener_parse(buf);
    free(buf);
    if (!root) { DLOG("state: JSON invalido, ignorando"); return; }

    struct json_object *v;
#define LS(field, key) \
    if (json_object_object_get_ex(root, key, &v)) { \
        strncpy(st->field, json_object_get_string(v), sizeof(st->field)-1); \
        DLOG("state:   %-12s = %s", key, st->field); \
    }
#define LB(field, key) \
    if (json_object_object_get_ex(root, key, &v)) { \
        st->field = json_object_get_boolean(v); \
        DLOG("state:   %-12s = %s", key, st->field ? "true" : "false"); \
    }

    LB(adopted,    "adopted");
    LS(authkey,    "authkey");
    LS(inform_url, "inform_url");
    LS(cfgversion, "cfgversion");
    LS(mac,        "mac");
    LS(ip,         "ip");
    LS(hostname,   "hostname");
#undef LS
#undef LB

    json_object_put(root);
    DLOG("state: cargado — adopted=%s cfgversion=%s url=%s key=%.8s...",
         st->adopted ? "SI" : "NO", st->cfgversion,
         st->inform_url,
         st->authkey[0] ? st->authkey : "(default)");
}

int state_save(const openuf_state_t *st)
{
    DLOG("state: guardando (adopted=%s cfgver=%s ip=%s)",
         st->adopted ? "SI" : "NO", st->cfgversion, st->ip);

    mkdir("/etc/openuf", 0755);

    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "adopted",    json_object_new_boolean(st->adopted));
    json_object_object_add(root, "authkey",    json_object_new_string(st->authkey));
    json_object_object_add(root, "inform_url", json_object_new_string(st->inform_url));
    json_object_object_add(root, "cfgversion", json_object_new_string(st->cfgversion));
    json_object_object_add(root, "mac",        json_object_new_string(st->mac));
    json_object_object_add(root, "ip",         json_object_new_string(st->ip));
    json_object_object_add(root, "hostname",   json_object_new_string(st->hostname));

    const char *s = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    DLOG("state: JSON a escribir:\n%s", s);

    FILE *f = fopen(OPENUF_STATE_FILE, "w");
    if (!f) {
        DLOG("state: ERROR abriendo %s para escritura", OPENUF_STATE_FILE);
        json_object_put(root); return -1;
    }
    fputs(s, f);
    fclose(f);
    json_object_put(root);
    DLOG("state: guardado OK en %s", OPENUF_STATE_FILE);
    return 0;
}
