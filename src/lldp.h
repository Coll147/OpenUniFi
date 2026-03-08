#ifndef OPENUF_LLDP_H
#define OPENUF_LLDP_H

/*
 * openuf - lldp.h
 *
 * LLDP (Link Layer Discovery Protocol — IEEE 802.1AB)
 *
 * ── ENVÍO de frames LLDP propios ────────────────────────────────
 *
 *   El AP transmite frames LLDP por cada puerto ethernet.
 *   Esto permite al switch upstream registrar al AP como vecino,
 *   y al controlador UniFi construir el mapa de topología visual.
 *
 *   Frame Ethernet:
 *     dst  = 01:80:c2:00:00:0e  (multicast LLDP estándar)
 *     src  = MAC del AP
 *     type = 0x88cc
 *
 *   Payload (TLVs encadenados):
 *     Header TLV = [type:7bits | len_hi:1bit][len_lo:8bits]
 *
 *     TLV type=1  Chassis ID   subtype=4(MAC), value=MAC[6]
 *     TLV type=2  Port ID      subtype=5(ifname), value="eth0"
 *     TLV type=3  TTL          value=uint16_BE
 *     TLV type=5  System Name  value=hostname
 *     TLV type=6  System Desc  value="modelo versión"
 *     TLV type=7  Capabilities cap=0x0040(WLAN-AP), en=0x0040
 *     TLV type=0  End of LLDPDU  len=0
 *
 * ── LECTURA de vecinos: lldpctl -f json ─────────────────────────
 *
 *   Si lldpd está instalado, leemos los vecinos detectados
 *   y los incluimos en lldp_table del payload inform.
 *
 *   lldp_table en el JSON inform:
 *   [{
 *     "local_port": "eth0",
 *     "chassis_id": "aa:bb:cc:...",
 *     "port_id":    "Gi1/0/3",
 *     "sys_name":   "switch-piso1",
 *     "sys_desc":   "Cisco Catalyst 2960",
 *     "port_desc":  "to-AP"
 *   }]
 *
 * ── SIN lldpd ───────────────────────────────────────────────────
 *
 *   lldp_send_frame() funciona sin lldpd (usa raw socket directo).
 *   lldp_read_neighbors() retorna array vacío si no hay lldpctl.
 */

#include <stdbool.h>
#include <json-c/json.h>

/* Envía un frame LLDP por raw socket AF_PACKET.
 * Requiere ejecutar como root (CAP_NET_RAW).
 * Devuelve 0 si ok, -1 si error (sin root → error silencioso). */
int lldp_send_frame(const char *ifname,
                    const char *mac_str,
                    const char *hostname,
                    const char *model_desc,
                    int         ttl);

/* Lee vecinos LLDP de lldpctl y retorna JSON array lldp_table.
 * Si lldpctl no está, retorna array vacío (no falla).
 * Caller libera con json_object_put(). */
struct json_object *lldp_read_neighbors(void);

/* true si lldpctl está instalado */
bool lldp_available(void);

#endif /* OPENUF_LLDP_H */
