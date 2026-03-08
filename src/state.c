#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include "state.h"
#include "config.h"
#include "debug.h"

#define DBG_TAG "state"

static void state_defaults(openuf_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->adopted = false;
    strncpy(st->authkey,    DEFAULT_AUTH_KEY, sizeof(st->authkey)-1);
    strncpy(st->cfgversion, "0",              sizeof(st->cfgversion)-1);
}

void state_load(openuf_state_t *st) {
    state_defaults(st);
    LOG_DBG("cargando estado desde %s...", OPENUF_STATE_FILE);
    FILE *f = fopen(OPENUF_STATE_FILE, "r");
    if (!f) { LOG_INFO("sin estado previo (%s) — primera ejecución", OPENUF_STATE_FILE); return; }

    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    if (sz <= 0 || sz > 4096) {
        LOG_ERR("tamaño de estado inválido: %ld bytes", sz);
        fclose(f); return;
    }
    char *buf = malloc(sz+1);
    if (!buf) { LOG_ERR("OOM"); fclose(f); return; }
    fread(buf, 1, sz, f); buf[sz]='\0'; fclose(f);

    LOG_TRACE("JSON estado (%ld bytes):\n%s", sz, buf);
    struct json_object *root = json_tokener_parse(buf);
    free(buf);
    if (!root) { LOG_ERR("JSON de estado inválido — ignorando"); return; }

    struct json_object *v;
#define LS(field,key) \
    if (json_object_object_get_ex(root,key,&v)&&json_object_is_type(v,json_type_string)) { \
        strncpy(st->field,json_object_get_string(v),sizeof(st->field)-1); \
        LOG_TRACE("  %-12s = %s",key,st->field); }
#define LB(field,key) \
    if (json_object_object_get_ex(root,key,&v)) { \
        st->field=json_object_get_boolean(v); \
        LOG_TRACE("  %-12s = %s",key,st->field?"true":"false"); }

    LB(adopted,"adopted"); LS(authkey,"authkey"); LS(inform_url,"inform_url");
    LS(cfgversion,"cfgversion"); LS(mac,"mac"); LS(ip,"ip"); LS(hostname,"hostname");
    json_object_put(root);

    LOG_INFO("estado cargado: adoptado=%s  cfgversion=%s  url=%s",
             st->adopted?"SÍ":"NO", st->cfgversion, st->inform_url);
    if (st->adopted) LOG_DBG("clave activa: %.8s...", st->authkey);
}

int state_save(const openuf_state_t *st) {
    LOG_DBG("guardando estado (adoptado=%s)...", st->adopted?"SÍ":"NO");
    mkdir("/etc/openuf", 0755);
    struct json_object *root = json_object_new_object();
    json_object_object_add(root,"adopted",    json_object_new_boolean(st->adopted));
    json_object_object_add(root,"authkey",    json_object_new_string(st->authkey));
    json_object_object_add(root,"inform_url", json_object_new_string(st->inform_url));
    json_object_object_add(root,"cfgversion", json_object_new_string(st->cfgversion));
    json_object_object_add(root,"mac",        json_object_new_string(st->mac));
    json_object_object_add(root,"ip",         json_object_new_string(st->ip));
    json_object_object_add(root,"hostname",   json_object_new_string(st->hostname));
    const char *s = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    LOG_TRACE("escribiendo:\n%s", s);
    FILE *f = fopen(OPENUF_STATE_FILE, "w");
    if (!f) { LOG_ERR("no se pudo escribir %s: %m", OPENUF_STATE_FILE); json_object_put(root); return -1; }
    fputs(s, f); fclose(f); json_object_put(root);
    LOG_DBG("estado guardado en %s", OPENUF_STATE_FILE);
    return 0;
}
