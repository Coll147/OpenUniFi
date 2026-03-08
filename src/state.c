#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include "state.h"
#include "config.h"

#ifdef ENABLE_LOGGING
#include <stdio.h>
extern FILE *log_fp;
#define LOG(fmt, ...) do { if (log_fp) { fprintf(log_fp, "[%s] " fmt "\n", __func__, ##__VA_ARGS__); fflush(log_fp); } } while(0)
#else
#define LOG(fmt, ...) do {} while(0)
#endif

static void state_defaults(openuf_state_t *st)
{
    memset(st, 0, sizeof(*st));
    st->adopted = false;
    strncpy(st->authkey,    DEFAULT_AUTH_KEY, sizeof(st->authkey) - 1);
    strncpy(st->cfgversion, "0",              sizeof(st->cfgversion) - 1);
}

void state_load(openuf_state_t *st)
{
    state_defaults(st);

    FILE *f = fopen(OPENUF_STATE_FILE, "r");
    if (!f) {
        LOG("State file not found, using defaults");
        return;
    }

    /* Read whole file */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 4096) { fclose(f); return; }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);

    struct json_object *root = json_tokener_parse(buf);
    free(buf);
    if (!root) {
        LOG("Failed to parse state file");
        return;
    }

    struct json_object *v;
#define LOAD_STR(field, key) \
    if (json_object_object_get_ex(root, key, &v) && json_object_is_type(v, json_type_string)) \
        strncpy(st->field, json_object_get_string(v), sizeof(st->field) - 1)
#define LOAD_BOOL(field, key) \
    if (json_object_object_get_ex(root, key, &v)) \
        st->field = json_object_get_boolean(v)

    LOAD_BOOL(adopted,    "adopted");
    LOAD_STR (authkey,    "authkey");
    LOAD_STR (inform_url, "inform_url");
    LOAD_STR (cfgversion, "cfgversion");
    LOAD_STR (mac,        "mac");
    LOAD_STR (ip,         "ip");
    LOAD_STR (hostname,   "hostname");

    /* CRITICAL: If not adopted, force DEFAULT_AUTH_KEY */
    if (!st->adopted) {
        LOG("Device not adopted - resetting authkey to DEFAULT");
        strncpy(st->authkey, DEFAULT_AUTH_KEY, sizeof(st->authkey) - 1);
    }

    LOG("State loaded: adopted=%d, authkey=%.8s..., inform_url=%s", 
        st->adopted, st->authkey[0] ? st->authkey : "DEFAULT", st->inform_url);

    json_object_put(root);
}

int state_save(const openuf_state_t *st)
{
    /* Ensure directory exists */
    mkdir("/etc/openuf", 0755);

    LOG("Saving state: adopted=%d, authkey=%.8s..., inform_url=%s", 
        st->adopted, st->authkey[0] ? st->authkey : "DEFAULT", st->inform_url);

    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "adopted",    json_object_new_boolean(st->adopted));
    json_object_object_add(root, "authkey",    json_object_new_string(st->authkey));
    json_object_object_add(root, "inform_url", json_object_new_string(st->inform_url));
    json_object_object_add(root, "cfgversion", json_object_new_string(st->cfgversion));
    json_object_object_add(root, "mac",        json_object_new_string(st->mac));
    json_object_object_add(root, "ip",         json_object_new_string(st->ip));
    json_object_object_add(root, "hostname",   json_object_new_string(st->hostname));

    const char *s = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);

    FILE *f = fopen(OPENUF_STATE_FILE, "w");
    if (!f) { 
        LOG("Failed to open state file for writing");
        json_object_put(root); 
        return -1; 
    }
    fputs(s, f);
    fclose(f);
    json_object_put(root);
    LOG("State saved successfully");
    return 0;
}
