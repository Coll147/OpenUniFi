#ifndef OPENUF_CONFIG_H
#define OPENUF_CONFIG_H

/* ─── Build-time defaults (override with /etc/openuf/openuf.conf) ─── */
#define OPENUF_VERSION          "0.3-C"
#define OPENUF_STATE_FILE       "/etc/openuf/state.json"
#define OPENUF_CONF_FILE        "/etc/openuf/openuf.conf"

#define DEFAULT_CONTROLLER_IP   "192.168.1.2"
#define DEFAULT_LAN_IF          "br-lan"
#define DEFAULT_UFMODEL         "u6-inwall"
#define DEFAULT_INFORM_INTERVAL 10
#define ANNOUNCE_INTERVAL       10
#define ANNOUNCE_PORT           10001
#define INFORM_PORT             8080
#define INFORM_PATH             "/inform"
#define DEFAULT_AUTH_KEY        "ba86f2bbe107c7c57eb5f2690775c712"

#ifdef ENABLE_LOGGING
#include <stdio.h>
extern FILE *log_fp;
#define LOG(fmt, ...) do { if (log_fp) { fprintf(log_fp, "[%s] " fmt "\n", __func__, ##__VA_ARGS__); fflush(log_fp); } } while(0)
#else
#define LOG(fmt, ...) do {} while(0)
#endif

typedef struct {
    char controller_ip[64];
    char lan_if[32];
    char ufmodel[32];          /* "u6-inwall" | "u6-lite" */
    int  inform_interval;
    int  enable_announce;
    int  enable_inform;
    int  enable_logging;
} openuf_config_t;

/* Parse /etc/openuf/openuf.conf (simple key=value).
 * Fills *cfg with defaults first, then overrides from file. */
void config_load(openuf_config_t *cfg);

#endif /* OPENUF_CONFIG_H */
