#ifndef OPENUF_WLAN_H
#define OPENUF_WLAN_H

#include <json-c/json.h>
#include "ufmodel.h"

/*
 * Translate UniFi WLAN/VAP config into OpenWrt UCI wireless settings.
 * All openuf-managed interfaces are named  openuf_NN_<ssid>  so they
 * can be safely removed on re-provision.
 */

/* Remove all UCI wifi-iface sections whose name starts with "openuf_" */
void wlan_clear(void);

/* Apply radio-level settings from a UniFi radio_table entry.
 * radio_json : JSON object with fields: channel, ht, tx_power
 * device_name: OpenWrt radio device ("radio0", "radio1")  */
void wlan_apply_radio(struct json_object *radio_json,
                      const char *device_name);

/* Apply full config pushed by controller (setstate).
 * config_json: decoded setstate JSON object
 * model      : model descriptor for radio_map lookup */
void wlan_apply_config(struct json_object *config_json,
                       const uf_model_t *model);

/* Build vap_table JSON array from current UCI state.
 * Caller owns returned json_object. */
struct json_object *wlan_get_vap_table(const uf_model_t *model);

#endif /* OPENUF_WLAN_H */
