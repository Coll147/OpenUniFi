/*
 * openuf - models.c
 *
 * Descriptores de hardware para los modelos emulados.
 *
 * ── Por qué U6 InWall como modelo principal ─────────────────────────
 *
 * Se elige U6 IW porque:
 *   • 5 puertos GbE (eth0-eth4) → cubre la mayoría de routers OpenWrt
 *     con 4 LAN + 1 WAN convertidos a puertos independientes
 *   • WiFi 6 (802.11ax) en 2.4 GHz y 5 GHz
 *   • Sin PoE uplink (el router alimenta por adaptador)
 *   • Firmware string reconocido por UniFi Network 7.x+
 *
 * Los 5 puertos se mapean así en un router típico OpenWrt:
 *   eth0 → Puerto 1 (WAN físico, reconfigurado como LAN)
 *   eth1 → Puerto 2
 *   eth2 → Puerto 3
 *   eth3 → Puerto 4
 *   eth4 → Puerto 5 (o CPU en SoCs sin eth4 físico)
 */

#include "ufmodel.h"
#define DBG_TAG "models"
#include "debug.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
   U6 InWall — 5 puertos GbE + WiFi 6 (2.4+5 GHz)
   ═══════════════════════════════════════════════════════════════════ */
static const uf_radio_t u6iw_radios[] = {
    /* name     radio  ch  ht       min max nss pwr  caps ant he */
    { "wifi0", "ng",   6, "HT40",   5, 23,  2,  20,   4,  0, true },
    { "wifi1", "na",  36, "HT80",   5, 23,  2,  20,   7,  0, true },
};

/* 5 puertos: puerto 0 es uplink, 1-4 son LAN */
static const uf_port_t u6iw_ports[] = {
    /* ifname  name    idx  poe_caps  media  speed  up     uplink  duplex */
    { "eth0", "eth0",  0,   255,     "GE", 1000, false, true,  true },
    { "eth1", "eth1",  1,     0,     "GE", 1000, false, false, true },
    { "eth2", "eth2",  2,     0,     "GE", 1000, false, false, true },
    { "eth3", "eth3",  3,     0,     "GE", 1000, false, false, true },
    { "eth4", "eth4",  4,     4,     "GE", 1000, false, false, true },
};

static const uf_eth_entry_t u6iw_eth[] = {
    { "eth0", 5 },
};

static const uf_radio_map_t u6iw_rmap[] = {
    { "ng", "radio0" },
    { "na", "radio1" },
};

const uf_model_t model_u6inwall = {
    .model              = "U6IW",
    .model_display      = "U6 IW",
    .display_name       = "U6-IW",
    .platform           = "U6IW",
    .board_rev          = 3,
    .has_eth1           = true,
    .fw_pre             = "U6IW.mt7622_5_4.v",
    .fw_ver             = "6.6.55.14430",
    .fw_buildtime       = "230901.1200",
    .fw_factoryver      = "6.6.55.14430",
    .radio_table        = u6iw_radios,
    .radio_table_len    = 2,
    .port_table         = u6iw_ports,
    .port_table_len     = 5,
    .ethernet_table     = u6iw_eth,
    .ethernet_table_len = 1,
    .radio_map          = u6iw_rmap,
    .radio_map_len      = 2,
};

/* ═══════════════════════════════════════════════════════════════════
   U6 Lite — 1 puerto GbE + WiFi 6 (2.4+5 GHz)
   ═══════════════════════════════════════════════════════════════════ */
static const uf_radio_t u6lite_radios[] = {
    { "wifi0", "ng",  6, "HT40",  5, 23, 2, 20, 4, 0, true },
    { "wifi1", "na", 36, "HT80",  5, 23, 2, 20, 7, 0, true },
};
static const uf_port_t u6lite_ports[] = {
    { "eth0", "eth0", 0, 255, "GE", 1000, false, true, true },
};
static const uf_eth_entry_t u6lite_eth[] = { { "eth0", 1 } };
static const uf_radio_map_t u6lite_rmap[] = {
    { "ng", "radio0" }, { "na", "radio1" },
};
const uf_model_t model_u6lite = {
    .model="U6LITE", .model_display="U6 Lite", .display_name="U6-Lite",
    .platform="U6LITE", .board_rev=3, .has_eth1=false,
    .fw_pre="U6LITE.mt7622_5_4.v", .fw_ver="6.6.55.14430",
    .fw_buildtime="230901.1200", .fw_factoryver="6.6.55.14430",
    .radio_table=u6lite_radios, .radio_table_len=2,
    .port_table=u6lite_ports,   .port_table_len=1,
    .ethernet_table=u6lite_eth, .ethernet_table_len=1,
    .radio_map=u6lite_rmap,     .radio_map_len=2,
};

/* ═══════════════════════════════════════════════════════════════════
   UAP Gen 1 — 1 puerto Fast Ethernet + WiFi N 2.4 GHz
   ═══════════════════════════════════════════════════════════════════ */
static const uf_radio_t uapg1_radios[] = {
    { "wifi0", "ng", 6, "HT20", 5, 23, 2, 20, 4, 0, false },
};
static const uf_port_t uapg1_ports[] = {
    { "eth0", "eth0", 0, 255, "GE", 100, false, true, true },
};
static const uf_eth_entry_t uapg1_eth[] = { { "eth0", 1 } };
static const uf_radio_map_t uapg1_rmap[] = { { "ng", "radio0" } };
const uf_model_t model_uapg1 = {
    .model="BZ2", .model_display="UAP", .display_name="UAP",
    .platform="BZ2", .board_rev=1, .has_eth1=false,
    .fw_pre="BZ2.ar7240.v", .fw_ver="6.6.55.14430",
    .fw_buildtime="230901.1200", .fw_factoryver="6.6.55.14430",
    .radio_table=uapg1_radios, .radio_table_len=1,
    .port_table=uapg1_ports,   .port_table_len=1,
    .ethernet_table=uapg1_eth, .ethernet_table_len=1,
    .radio_map=uapg1_rmap,     .radio_map_len=1,
};

/* ═══════════════════════════════════════════════════════════════════
   UAP Gen 1 LR
   ═══════════════════════════════════════════════════════════════════ */
static const uf_radio_t uapg1lr_radios[] = {
    { "wifi0", "ng", 6, "HT20", 5, 23, 2, 22, 4, 0, false },
};
static const uf_port_t uapg1lr_ports[] = {
    { "eth0", "eth0", 0, 255, "GE", 100, false, true, true },
};
static const uf_eth_entry_t uapg1lr_eth[] = { { "eth0", 1 } };
static const uf_radio_map_t uapg1lr_rmap[] = { { "ng", "radio0" } };
const uf_model_t model_uapg1lr = {
    .model="BZ2LR", .model_display="UAP-LR", .display_name="UAP-LR",
    .platform="BZ2LR", .board_rev=1, .has_eth1=false,
    .fw_pre="BZ2LR.ar7240.v", .fw_ver="6.6.55.14430",
    .fw_buildtime="230901.1200", .fw_factoryver="6.6.55.14430",
    .radio_table=uapg1lr_radios, .radio_table_len=1,
    .port_table=uapg1lr_ports,   .port_table_len=1,
    .ethernet_table=uapg1lr_eth, .ethernet_table_len=1,
    .radio_map=uapg1lr_rmap,     .radio_map_len=1,
};

/* ═══════════════════════════════════════════════════════════════════
   UAP AC LR — 1 puerto GbE + WiFi AC dual-band
   ═══════════════════════════════════════════════════════════════════ */
static const uf_radio_t uapg2aclr_radios[] = {
    { "wifi0", "ng",  6, "HT40",  5, 23, 2, 20, 4, 0, false },
    { "wifi1", "na", 36, "HT80",  5, 23, 2, 20, 7, 0, false },
};
static const uf_port_t uapg2aclr_ports[] = {
    { "eth0", "eth0", 0, 255, "GE", 1000, false, true, true },
};
static const uf_eth_entry_t uapg2aclr_eth[] = { { "eth0", 1 } };
static const uf_radio_map_t uapg2aclr_rmap[] = {
    { "ng", "radio0" }, { "na", "radio1" },
};
const uf_model_t model_uapg2aclr = {
    .model="U2IW", .model_display="UAP-AC-LR", .display_name="UAP-AC-LR",
    .platform="U2IW", .board_rev=2, .has_eth1=false,
    .fw_pre="U2IW.qca956x.v", .fw_ver="6.6.55.14430",
    .fw_buildtime="230901.1200", .fw_factoryver="6.6.55.14430",
    .radio_table=uapg2aclr_radios, .radio_table_len=2,
    .port_table=uapg2aclr_ports,   .port_table_len=1,
    .ethernet_table=uapg2aclr_eth, .ethernet_table_len=1,
    .radio_map=uapg2aclr_rmap,     .radio_map_len=2,
};

/* ─── Registro de modelos ─────────────────────────────────────── */
static const uf_model_t *all_models[] = {
    &model_u6inwall,
    &model_u6lite,
    &model_uapg1,
    &model_uapg1lr,
    &model_uapg2aclr,
    NULL
};

const uf_model_t *ufmodel_find(const char *name)
{
    if (!name) { LOG_DBG("ufmodel_find(NULL) -> u6inwall por defecto"); return &model_u6inwall; }
    LOG_DBG("buscando modelo '%s'", name);
    for (int i = 0; all_models[i]; i++) {
        const uf_model_t *m = all_models[i];
        if (!strcasecmp(name, m->model)        ||
            !strcasecmp(name, m->model_display) ||
            !strcasecmp(name, m->display_name)  ||
            !strcasecmp(name, m->platform)) {
            LOG_DBG("encontrado '%s' -> %s (%s)", name, m->model, m->display_name);
            return m;
        }
    }
    /* Aliases */
    if (!strcasecmp(name,"u6-inwall")||!strcasecmp(name,"u6iw"))  { LOG_DBG("alias u6iw");        return &model_u6inwall; }
    if (!strcasecmp(name,"u6-lite"))                               { LOG_DBG("alias u6-lite");     return &model_u6lite;   }
    if (!strcasecmp(name,"uapg1"))                                 { LOG_DBG("alias uapg1");       return &model_uapg1;    }
    if (!strcasecmp(name,"uapg1-lr"))                              { LOG_DBG("alias uapg1-lr");    return &model_uapg1lr;  }
    if (!strcasecmp(name,"uapg2-ac-lr"))                           { LOG_DBG("alias uapg2-ac-lr"); return &model_uapg2aclr;}

    LOG_DBG("modelo '%s' no encontrado -- usando u6inwall por defecto", name);
    return &model_u6inwall;
}
