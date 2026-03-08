#ifndef OPENUF_UFMODEL_H
#define OPENUF_UFMODEL_H

#include <stdbool.h>

/* ─── Radio entry ─────────────────────────────────────────────────── */
typedef struct {
    const char *name;        /* "wifi0", "wifi1" */
    const char *radio;       /* "ng" (2.4 GHz) | "na" (5 GHz) | "6g" */
    int         channel;
    const char *ht;          /* "HT20", "HT40", "HT80" */
    int         min_txpower;
    int         max_txpower;
    int         nss;
    int         tx_power;
    int         radio_caps;
    int         antenna_gain;
    bool        he_enabled;
} uf_radio_t;

/* ─── Ethernet port entry ─────────────────────────────────────────── */
typedef struct {
    const char *ifname;
    const char *name;
    int         port_idx;
    int         poe_caps;
    const char *media;       /* "GE" */
    int         speed;
    bool        up;
    bool        is_uplink;
    bool        full_duplex;
} uf_port_t;

/* ─── Ethernet table entry ────────────────────────────────────────── */
typedef struct {
    const char *name;
    int         num_port;
} uf_eth_entry_t;

/* ─── Radio map entry (band → OpenWrt device) ─────────────────────── */
typedef struct {
    const char *band;   /* "ng", "na", "6g" */
    const char *device; /* "radio0", "radio1" */
} uf_radio_map_t;

/* ─── Full model descriptor ───────────────────────────────────────── */
typedef struct {
    const char     *model;          /* "U6IW", "U6LITE" */
    const char     *model_display;  /* "U6 IW" */
    const char     *display_name;   /* "U6-IW" */
    const char     *platform;       /* used in announce PKT_PLATFORM */
    int             board_rev;
    bool            has_eth1;

    /* Firmware strings */
    const char     *fw_pre;         /* "U6IW.mt7622_5_4.v" */
    const char     *fw_ver;         /* "6.6.55.14430" */
    const char     *fw_buildtime;   /* "230901.1200" */
    const char     *fw_factoryver;

    /* Tables */
    const uf_radio_t     *radio_table;
    int                   radio_table_len;
    const uf_port_t      *port_table;
    int                   port_table_len;
    const uf_eth_entry_t *ethernet_table;
    int                   ethernet_table_len;
    const uf_radio_map_t *radio_map;
    int                   radio_map_len;
} uf_model_t;

/* ─── Model registry ──────────────────────────────────────────────── */
const uf_model_t *ufmodel_find(const char *name);

extern const uf_model_t model_u6inwall;
extern const uf_model_t model_u6lite;
extern const uf_model_t model_uapg1;
extern const uf_model_t model_uapg1lr;
extern const uf_model_t model_uapg2aclr;

#endif /* OPENUF_UFMODEL_H */
