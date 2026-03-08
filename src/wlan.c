/*
 * openuf - wlan.c
 *
 * Traduce la configuración WiFi del controlador UniFi en settings
 * UCI de OpenWrt usando libuci directamente (sin shell).
 *
 * ── CÓMO SE APLICA LA CONFIGURACIÓN ────────────────────────────────
 *
 * El controlador envía "setstate" con:
 *   radio_table[]  → configuración de las radios (canal, potencia, HT)
 *   vap_table[]    → configuración de las redes WiFi (SSID, clave, roaming...)
 *
 * Este módulo:
 *   1. Borra todas las wifi-iface UCI con prefijo "openuf_"
 *   2. Aplica radio_table → wireless.<device>.channel/txpower/htmode
 *   3. Crea nuevas wifi-iface por cada VAP con su configuración
 *   4. Ejecuta "wifi reload" para aplicar sin reiniciar
 *
 * ── MAPEO DE SEGURIDAD ──────────────────────────────────────────────
 *
 *   UniFi          OpenWrt UCI         Descripción
 *   ─────────────────────────────────────────────
 *   open           none                Sin contraseña
 *   wpapsk         psk                 WPA Personal
 *   wpa2psk        psk2                WPA2 Personal
 *   wpapskwpa2psk  psk-mixed           WPA/WPA2 mixto
 *   wpa3           sae                 WPA3 Personal
 *   wpa3transition sae-mixed           WPA2+WPA3 transición
 *   wpa2enterprise wpa2                WPA2 Enterprise (RADIUS)
 *   wpa3enterprise wpa3                WPA3 Enterprise
 *
 * ── BAND STEERING (802.11k/v) ──────────────────────────────────────
 *
 *   Cuando UniFi activa band_steering, configuramos en UCI:
 *     ieee80211k = 1   → Neighbor Reports (AP informa a cliente de otros APs)
 *     ieee80211v = 1   → BSS Transition Management (AP puede pedir que el
 *                         cliente se mueva a otro AP/radio)
 *     rrm_neighbor_report = 1
 *     bss_transition = 1
 *
 *   El hostapd de OpenWrt usa estos flags para implementar 802.11k/v.
 *   Band steering real requiere lógica adicional (daemon externo o
 *   script que monitoriza RSSI y envía BTM Request).
 *
 * ── FAST ROAMING (802.11r) ─────────────────────────────────────────
 *
 *   Cuando UniFi activa fast_roaming_enabled:
 *     ieee80211r = 1          → FT (Fast BSS Transition)
 *     ft_over_ds = 1          → FT sobre Distribution System (más compatible)
 *     mobility_domain = XXXX  → Mismo dominio en todos los APs del site
 *     ft_psk_generate_local = 1  → PSK sin servidor FT externo
 *
 *   El mobility_domain se deriva de los primeros 2 bytes del MAC del AP.
 *   Todos los APs del mismo site deben usar el mismo mobility_domain.
 *
 * ── PMF (Protected Management Frames / 802.11w) ─────────────────────
 *
 *   pmf_mode  → ieee80211w:
 *     "disabled" → 0 (sin PMF)
 *     "optional" → 1 (PMF opcional, compatible con clientes sin PMF)
 *     "required" → 2 (PMF obligatorio, solo clientes con PMF)
 *
 *   WPA3 siempre requiere PMF=2.
 *
 * ── LECTURA DE VAPs DESDE UCI ───────────────────────────────────────
 *
 *   wlan_get_vap_table() itera todas las wifi-iface de /etc/config/wireless
 *   que tengan prefijo "openuf_" y construye el JSON vap_table para
 *   incluirlo en el payload inform.
 *
 *   Para cada VAP leemos: ssid, device, bssid, encryption, key, disabled
 *   y los traducimos al formato que espera el controlador.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uci.h>
#include <json-c/json.h>

#include "wlan.h"
#include "ufmodel.h"

/* ─── Mapeo de seguridad UniFi → OpenWrt UCI ────────────────────── */
static const char *sec_to_uci(const char *uf)
{
    if (!uf || !strcmp(uf,"open"))          return "none";
    if (!strcmp(uf,"wpapsk"))               return "psk";
    if (!strcmp(uf,"wpa2psk"))              return "psk2";
    if (!strcmp(uf,"wpapskwpa2psk"))        return "psk-mixed";
    if (!strcmp(uf,"wpa3"))                 return "sae";
    if (!strcmp(uf,"wpa3transition"))       return "sae-mixed";
    if (!strcmp(uf,"wpa2enterprise"))       return "wpa2";
    if (!strcmp(uf,"wpa3enterprise"))       return "wpa3";
    return "psk2";   /* default */
}

/* Mapeo inverso: UCI → UniFi (para wlan_get_vap_table) */
static const char *sec_to_unifi(const char *uci)
{
    if (!uci || !strcmp(uci,"none"))        return "open";
    if (!strcmp(uci,"psk"))                 return "wpapsk";
    if (!strcmp(uci,"psk2"))                return "wpa2psk";
    if (!strcmp(uci,"psk-mixed"))           return "wpapskwpa2psk";
    if (!strcmp(uci,"sae"))                 return "wpa3";
    if (!strcmp(uci,"sae-mixed"))           return "wpa3transition";
    if (!strcmp(uci,"wpa2"))                return "wpa2enterprise";
    if (!strcmp(uci,"wpa3"))                return "wpa3enterprise";
    return "wpa2psk";
}

/* ─── Nombre de sección UCI seguro (máx 15 chars) ──────────────── */
static void safe_section_name(const char *ssid, char *out, size_t sz)
{
    size_t j = 0;
    for (size_t i = 0; ssid[i] && j < sz-1 && j < 15; i++) {
        char c = ssid[i];
        if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
            (c>='0'&&c<='9')||c=='_'||c=='-')
            out[j++] = c;
        else
            out[j++] = '_';
    }
    out[j] = '\0';
}

/* ─── libuci: set un valor en wireless ─────────────────────────── */
static int uci_set_val(struct uci_context *ctx,
                       const char *path, const char *val)
{
    struct uci_ptr ptr;
    char *p = malloc(strlen(path) + strlen(val) + 2);
    if (!p) return -1;
    sprintf(p, "%s=%s", path, val);
    int ret = uci_lookup_ptr(ctx, &ptr, p, true);
    free(p);
    if (ret != UCI_OK) return -1;
    return (uci_set(ctx, &ptr) == UCI_OK) ? 0 : -1;
}

/* Wrapper que formatea path y value en printf style */
#define UCI_SET(ctx, pkg, sec, opt, val) do { \
    char _path[256]; \
    snprintf(_path, sizeof(_path), "%s.%s.%s", pkg, sec, opt); \
    uci_set_val(ctx, _path, val); \
} while(0)

#define UCI_SET_INT(ctx, pkg, sec, opt, ival) do { \
    char _v[32]; snprintf(_v, sizeof(_v), "%d", ival); \
    UCI_SET(ctx, pkg, sec, opt, _v); \
} while(0)

/* ─── Encontrar/crear sección UCI ──────────────────────────────── */
static int uci_ensure_section(struct uci_context *ctx,
                               struct uci_package *pkg,
                               const char *sec_name,
                               const char *sec_type)
{
    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!strcmp(s->e.name, sec_name) && !strcmp(s->type, sec_type))
            return 0;  /* ya existe */
    }
    /* Crear nueva sección con nombre */
    struct uci_ptr ptr = {0};
    ptr.package = (char *)pkg->e.name;
    ptr.section = (char *)sec_name;
    ptr.flags   = UCI_LOOKUP_EXTENDED;
    if (uci_set(ctx, &ptr) != UCI_OK) return -1;

    /* Establecer tipo */
    char path[256];
    snprintf(path, sizeof(path), "wireless.%s", sec_name);
    struct uci_ptr tptr;
    char *p = malloc(strlen(path) + strlen(sec_type) + 2);
    if (!p) return -1;
    sprintf(p, "%s=%s", path, sec_type);
    uci_lookup_ptr(ctx, &tptr, p, true);
    free(p);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
   wlan_clear — eliminar todas las VAPs gestionadas por openuf
   ═══════════════════════════════════════════════════════════════════ */
void wlan_clear(void)
{
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return;

    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "wireless", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        return;
    }

    /* Recopilar secciones a eliminar (no modificar durante iteración) */
    char *to_del[64];
    int ndel = 0;
    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!strcmp(s->type, "wifi-iface") &&
            strncmp(s->e.name, "openuf_", 7) == 0 &&
            ndel < 64) {
            to_del[ndel++] = strdup(s->e.name);
        }
    }

    for (int i = 0; i < ndel; i++) {
        struct uci_ptr ptr;
        char path[128];
        snprintf(path, sizeof(path), "wireless.%s", to_del[i]);
        if (uci_lookup_ptr(ctx, &ptr, path, true) == UCI_OK)
            uci_delete(ctx, &ptr);
        free(to_del[i]);
    }

    if (ndel > 0) {
        uci_commit(ctx, &pkg, false);
        printf("[openuf] wlan_clear: eliminadas %d VAPs\n", ndel);
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
}

/* ═══════════════════════════════════════════════════════════════════
   wlan_apply_radio — aplicar config de radio (canal, HT, potencia)
   ═══════════════════════════════════════════════════════════════════

   Lectura de parámetros del JSON del controlador:
     channel     → wireless.<device>.channel
     ht          → wireless.<device>.htmode ("HT20" / "HT40" / "HT80" / "HE80")
     tx_power    → wireless.<device>.txpower
     min_rssi    → no se mapea a UCI (requiere daemon externo)
*/
void wlan_apply_radio(struct json_object *radio_json,
                      const char *device_name)
{
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return;

    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "wireless", &pkg) != UCI_OK) {
        uci_free_context(ctx); return;
    }

    struct json_object *v;
    char path[256];

#define RP(key, uci_opt) \
    if (json_object_object_get_ex(radio_json, key, &v)) { \
        snprintf(path, sizeof(path), "wireless.%s.%s=%s", \
                 device_name, uci_opt, json_object_get_string(v)); \
        struct uci_ptr ptr; \
        if (uci_lookup_ptr(ctx, &ptr, path, true) == UCI_OK) \
            uci_set(ctx, &ptr); \
    }

    RP("ht",       "htmode");

    /* Canal: 0 = auto en UniFi */
    if (json_object_object_get_ex(radio_json, "channel", &v)) {
        int ch = json_object_get_int(v);
        if (ch == 0) {
            snprintf(path, sizeof(path), "wireless.%s.channel=auto", device_name);
        } else {
            snprintf(path, sizeof(path), "wireless.%s.channel=%d", device_name, ch);
        }
        struct uci_ptr ptr;
        if (uci_lookup_ptr(ctx, &ptr, path, true) == UCI_OK)
            uci_set(ctx, &ptr);
    }

    /* tx_power */
    if (json_object_object_get_ex(radio_json, "tx_power", &v)) {
        snprintf(path, sizeof(path), "wireless.%s.txpower=%d",
                 device_name, json_object_get_int(v));
        struct uci_ptr ptr;
        if (uci_lookup_ptr(ctx, &ptr, path, true) == UCI_OK)
            uci_set(ctx, &ptr);
    }

    /* Habilitar el radio */
    snprintf(path, sizeof(path), "wireless.%s.disabled=0", device_name);
    struct uci_ptr ptr;
    if (uci_lookup_ptr(ctx, &ptr, path, true) == UCI_OK)
        uci_set(ctx, &ptr);

#undef RP

    uci_commit(ctx, &pkg, false);
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
}

/* ═══════════════════════════════════════════════════════════════════
   Crear una VAP (wifi-iface UCI) desde un JSON VAP del controlador
   ═══════════════════════════════════════════════════════════════════

   Parámetros del controlador que leemos y cómo los mapeamos:

   essid                → wireless.openuf_X.ssid
   x_passphrase         → wireless.openuf_X.key
   security             → wireless.openuf_X.encryption (via sec_to_uci)
   hide_ssid            → wireless.openuf_X.hidden
   guest_policy         → wireless.openuf_X.isolate (aislamiento de clientes)
   fast_roaming_enabled → ieee80211r, ft_over_ds, mobility_domain, ft_psk_generate_local
   band_steering        → ieee80211k, ieee80211v, rrm_neighbor_report, bss_transition
   pmf_mode             → ieee80211w (0/1/2)
   wpa3_support         → añadir "sae-mixed" si WPA2+WPA3
   uapsd                → uapsd (U-APSD power saving)
   vlan_id              → wireless.openuf_X.vlan_id (si ≠ 0)
*/
static void apply_vap(struct uci_context *ctx,
                      struct uci_package *pkg,
                      struct json_object *vap_json,
                      const char *device_name,
                      const char *mac_str,
                      int vap_idx)
{
    struct json_object *v;
    const char *essid    = "";
    const char *security = "wpa2psk";
    const char *pass     = "";

    if (json_object_object_get_ex(vap_json, "essid",       &v)) essid    = json_object_get_string(v);
    if (json_object_object_get_ex(vap_json, "security",    &v)) security = json_object_get_string(v);
    if (json_object_object_get_ex(vap_json, "x_passphrase",&v)) pass     = json_object_get_string(v);

    /* Nombre de sección: openuf_<idx>_<ssid_safe> */
    char safe[16] = {0};
    safe_section_name(essid, safe, sizeof(safe));
    char sec_name[48];
    snprintf(sec_name, sizeof(sec_name), "openuf_%d_%s", vap_idx, safe);

    uci_ensure_section(ctx, pkg, sec_name, "wifi-iface");

    UCI_SET(ctx, "wireless", sec_name, "device",     device_name);
    UCI_SET(ctx, "wireless", sec_name, "mode",       "ap");
    UCI_SET(ctx, "wireless", sec_name, "ssid",       essid);
    UCI_SET(ctx, "wireless", sec_name, "network",    "lan");
    UCI_SET(ctx, "wireless", sec_name, "encryption", sec_to_uci(security));

    /* Contraseña */
    if (pass && pass[0] && strcmp(security,"open") != 0)
        UCI_SET(ctx, "wireless", sec_name, "key", pass);

    /* SSID oculto */
    int hidden = 0;
    if (json_object_object_get_ex(vap_json, "hide_ssid", &v))
        hidden = json_object_get_boolean(v) ? 1 : 0;
    UCI_SET_INT(ctx, "wireless", sec_name, "hidden", hidden);

    /* Aislamiento de clientes (guest network) */
    int isolate = 0;
    if (json_object_object_get_ex(vap_json, "guest_policy", &v))
        isolate = json_object_get_boolean(v) ? 1 : 0;
    UCI_SET_INT(ctx, "wireless", sec_name, "isolate", isolate);

    /* U-APSD (ahorro de energía para clientes móviles) */
    int uapsd = 1;
    if (json_object_object_get_ex(vap_json, "uapsd", &v))
        uapsd = json_object_get_boolean(v) ? 1 : 0;
    UCI_SET_INT(ctx, "wireless", sec_name, "uapsd", uapsd);

    /* ── PMF (Protected Management Frames / 802.11w) ──────────────
     * "disabled" → 0, "optional" → 1, "required" → 2
     * WPA3 (sae/sae-mixed) siempre requiere ieee80211w=2 */
    int pmf = 0;
    if (json_object_object_get_ex(vap_json, "pmf_mode", &v)) {
        const char *pm = json_object_get_string(v);
        if (!strcmp(pm, "optional")) pmf = 1;
        if (!strcmp(pm, "required")) pmf = 2;
    }
    /* WPA3 obliga PMF=2 */
    if (!strcmp(security,"wpa3") || !strcmp(security,"wpa3transition") ||
        !strcmp(security,"wpa3enterprise"))
        pmf = 2;
    UCI_SET_INT(ctx, "wireless", sec_name, "ieee80211w", pmf);

    /* ── Fast Roaming (802.11r FT) ────────────────────────────────
     * Permite que los clientes se muevan entre APs sin re-autenticación
     * completa. El handshake FT sólo tarda ~50ms vs ~200-300ms normal. */
    int ft = 0;
    if (json_object_object_get_ex(vap_json, "fast_roaming_enabled", &v))
        ft = json_object_get_boolean(v) ? 1 : 0;
    if (ft) {
        UCI_SET_INT(ctx, "wireless", sec_name, "ieee80211r",          1);
        UCI_SET_INT(ctx, "wireless", sec_name, "ft_over_ds",          1);
        UCI_SET_INT(ctx, "wireless", sec_name, "ft_psk_generate_local", 1);
        /* mobility_domain: derivar de MAC del AP (2 bytes) */
        char mdomain[8] = {0};
        if (mac_str && strlen(mac_str) >= 5) {
            /* Usar bytes 0 y 1 de la MAC como dominio */
            char b0[3]={mac_str[0],mac_str[1],0};
            char b1[3]={mac_str[3],mac_str[4],0};
            unsigned int v0=0,v1=0;
            sscanf(b0,"%x",&v0); sscanf(b1,"%x",&v1);
            snprintf(mdomain, sizeof(mdomain), "%02x%02x", v0, v1);
        } else {
            strcpy(mdomain, "1234");
        }
        UCI_SET(ctx, "wireless", sec_name, "mobility_domain", mdomain);
    } else {
        UCI_SET_INT(ctx, "wireless", sec_name, "ieee80211r", 0);
    }

    /* ── Band Steering (802.11k/v) ────────────────────────────────
     * 802.11k: Neighbor Reports → el AP informa al cliente qué otros
     *          APs existen para facilitar el roaming.
     * 802.11v: BSS Transition Management → el AP puede "sugerir" al
     *          cliente que se mueva a otro AP con mejor señal. */
    int band_steer = 0;
    if (json_object_object_get_ex(vap_json, "band_steering", &v))
        band_steer = json_object_get_boolean(v) ? 1 : 0;
    if (band_steer) {
        UCI_SET_INT(ctx, "wireless", sec_name, "ieee80211k",           1);
        UCI_SET_INT(ctx, "wireless", sec_name, "ieee80211v",           1);
        UCI_SET_INT(ctx, "wireless", sec_name, "rrm_neighbor_report",  1);
        UCI_SET_INT(ctx, "wireless", sec_name, "bss_transition",       1);
    } else {
        UCI_SET_INT(ctx, "wireless", sec_name, "ieee80211k", 0);
        UCI_SET_INT(ctx, "wireless", sec_name, "ieee80211v", 0);
    }

    /* ── VLAN ──────────────────────────────────────────────────────
     * Si vlan_id ≠ 0, configurar la interfaz con VLAN tagging. */
    if (json_object_object_get_ex(vap_json, "vlan_id", &v)) {
        int vid = json_object_get_int(v);
        if (vid > 0) {
            UCI_SET_INT(ctx, "wireless", sec_name, "vlan_id", vid);
            /* Establecer network a vlanXXX si existe */
            char vlan_net[32];
            snprintf(vlan_net, sizeof(vlan_net), "vlan%d", vid);
            UCI_SET(ctx, "wireless", sec_name, "network", vlan_net);
        }
    }

    printf("[openuf] VAP '%s' → %s enc=%s ft=%d bs=%d pmf=%d\n",
           essid, sec_name, sec_to_uci(security), ft, band_steer, pmf);
}

/* ═══════════════════════════════════════════════════════════════════
   wlan_apply_config — aplicar configuración completa del controlador
   ═══════════════════════════════════════════════════════════════════

   Llamado desde inform.c → handle_response() cuando _type=="setstate".
   config_json es el JSON completo del controlador.

   Proceso:
   1. Eliminar VAPs antiguas (prefijo openuf_)
   2. Aplicar radio_table (canal, potencia, htmode) por radio
   3. Crear una VAP por cada entrada en vap_table
   4. Hacer commit UCI
   5. Ejecutar "wifi reload" para aplicar sin reiniciar el AP
*/
void wlan_apply_config(struct json_object *config_json,
                       const uf_model_t *model)
{
    struct json_object *rt_arr = NULL, *vt_arr = NULL, *v;
    json_object_object_get_ex(config_json, "radio_table", &rt_arr);
    json_object_object_get_ex(config_json, "vap_table",   &vt_arr);

    /* Obtener MAC del AP para mobility_domain */
    char mac_str[32] = "00:00:00:00:00:00";
    {
        char path[128];
        snprintf(path, sizeof(path), "/sys/class/net/eth0/address");
        FILE *f = fopen(path, "r");
        if (f) { fgets(mac_str, sizeof(mac_str), f); fclose(f); }
        mac_str[strcspn(mac_str, "\r\n")] = '\0';
    }

    /* 1. Limpiar VAPs antiguas */
    wlan_clear();

    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return;
    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "wireless", &pkg) != UCI_OK) {
        uci_free_context(ctx); return;
    }

    /* 2. Aplicar radio_table */
    if (rt_arr && json_object_is_type(rt_arr, json_type_array)) {
        int nr = json_object_array_length(rt_arr);
        for (int i = 0; i < nr; i++) {
            struct json_object *r = json_object_array_get_idx(rt_arr, i);
            if (!r) continue;
            /* Buscar el device UCI correspondiente a esta banda */
            const char *radio_band = "";
            if (json_object_object_get_ex(r, "radio", &v))
                radio_band = json_object_get_string(v);
            const char *device_name = "radio0";
            for (int j = 0; j < model->radio_map_len; j++) {
                if (!strcmp(model->radio_map[j].band, radio_band)) {
                    device_name = model->radio_map[j].device;
                    break;
                }
            }
            wlan_apply_radio(r, device_name);
        }
    }

    /* 3. Crear VAPs */
    if (vt_arr && json_object_is_type(vt_arr, json_type_array)) {
        int nv = json_object_array_length(vt_arr);
        for (int i = 0; i < nv; i++) {
            struct json_object *vap = json_object_array_get_idx(vt_arr, i);
            if (!vap) continue;

            /* Buscar device UCI para este VAP */
            const char *radio_band = "ng";
            if (json_object_object_get_ex(vap, "radio", &v))
                radio_band = json_object_get_string(v);
            const char *device_name = "radio0";
            for (int j = 0; j < model->radio_map_len; j++) {
                if (!strcmp(model->radio_map[j].band, radio_band)) {
                    device_name = model->radio_map[j].device;
                    break;
                }
            }
            apply_vap(ctx, pkg, vap, device_name, mac_str, i);
        }
    }

    /* 4. Commit UCI */
    uci_commit(ctx, &pkg, false);
    uci_unload(ctx, pkg);
    uci_free_context(ctx);

    /* 5. Aplicar cambios sin reiniciar (wifi reload recarga hostapd) */
    printf("[openuf] Ejecutando wifi reload...\n");
    system("wifi reload 2>/dev/null &");
}

/* ═══════════════════════════════════════════════════════════════════
   wlan_get_vap_table — leer VAPs activas desde UCI
   ═══════════════════════════════════════════════════════════════════

   Itera todas las wifi-iface con prefijo "openuf_" en /etc/config/wireless
   y construye el JSON vap_table para incluir en el payload inform.

   Campos que leemos de UCI → campos en el JSON:
     ssid       → essid
     device     → (usado para buscar radio y BSSID)
     encryption → security (via sec_to_unifi)
     hidden     → hide_ssid
     ieee80211r → fast_roaming_enabled
     ieee80211k → band_steering
     ieee80211w → pmf_mode ("disabled"/"optional"/"required")
     disabled   → up (inverso)

   También intentamos leer el BSSID real de la interfaz wlan
   desde /sys/class/net/<iface>/address.
*/
struct json_object *wlan_get_vap_table(const uf_model_t *model)
{
    struct json_object *arr = json_object_new_array();

    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return arr;

    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "wireless", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        return arr;
    }

    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (strcmp(sec->type, "wifi-iface") != 0) continue;
        /* Solo reportar VAPs gestionadas por openuf */
        if (strncmp(sec->e.name, "openuf_", 7) != 0) continue;

#define UCI_GET(opt) uci_lookup_option_string(ctx, sec, opt)

        const char *ssid   = UCI_GET("ssid");
        const char *device = UCI_GET("device");
        const char *enc    = UCI_GET("encryption");
        const char *dis    = UCI_GET("disabled");
        const char *r11    = UCI_GET("ieee80211r");
        const char *k11    = UCI_GET("ieee80211k");
        const char *w11    = UCI_GET("ieee80211w");
        const char *hidden = UCI_GET("hidden");

        if (!ssid) ssid = "";
        if (!device) device = "radio0";

        /* Banda de este radio */
        const char *radio_band = "ng";
        for (int j = 0; j < model->radio_map_len; j++) {
            if (!strcmp(model->radio_map[j].device, device)) {
                radio_band = model->radio_map[j].band;
                break;
            }
        }

        /* Nombre de la interfaz wlan (wlan0 para radio0, etc.) */
        char wlan_iface[32] = "wlan0";
        int ridx = 0;
        sscanf(device, "radio%d", &ridx);
        snprintf(wlan_iface, sizeof(wlan_iface), "wlan%d", ridx);

        /* Leer BSSID real desde sysfs */
        char bssid[32] = "00:00:00:00:00:00";
        {
            char path[128];
            snprintf(path, sizeof(path), "/sys/class/net/%s/address", wlan_iface);
            FILE *f = fopen(path, "r");
            if (f) {
                fgets(bssid, sizeof(bssid), f); fclose(f);
                bssid[strcspn(bssid, "\r\n")] = '\0';
            }
        }

        /* PMF: ieee80211w → "disabled"/"optional"/"required" */
        const char *pmf = "disabled";
        if (w11) {
            if (!strcmp(w11,"1")) pmf = "optional";
            if (!strcmp(w11,"2")) pmf = "required";
        }

        bool ft_on = (r11 && !strcmp(r11,"1"));
        bool bs_on = (k11 && !strcmp(k11,"1"));
        bool hid   = (hidden && !strcmp(hidden,"1"));
        bool up    = !(dis && !strcmp(dis,"1"));

        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "essid",               json_object_new_string(ssid));
        json_object_object_add(o, "bssid",               json_object_new_string(bssid));
        json_object_object_add(o, "name",                json_object_new_string(sec->e.name));
        json_object_object_add(o, "radio",               json_object_new_string(radio_band));
        json_object_object_add(o, "security",            json_object_new_string(sec_to_unifi(enc)));
        json_object_object_add(o, "up",                  json_object_new_boolean(up));
        json_object_object_add(o, "hide_ssid",           json_object_new_boolean(hid));
        json_object_object_add(o, "fast_roaming_enabled",json_object_new_boolean(ft_on));
        json_object_object_add(o, "band_steering",       json_object_new_boolean(bs_on));
        json_object_object_add(o, "pmf_mode",            json_object_new_string(pmf));
        json_object_object_add(o, "num_sta",             json_object_new_int(0));
        json_object_array_add(arr, o);
#undef UCI_GET
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return arr;
}
