/*
 * openuf - lldp.c
 *
 * LLDP completo: envío de frames propios + lectura de vecinos.
 *
 * ── Construcción del frame ────────────────────────────────────────
 *
 * Los TLVs LLDP tienen cabecera de 2 bytes:
 *   bit 15..9  → tipo (7 bits)
 *   bit 8..0   → longitud (9 bits, max 511 bytes)
 *
 *   uint16_t header_be = (type << 9) | (len & 0x1ff)
 *
 * Ejemplo: Chassis ID TLV (type=1), 7 bytes de valor:
 *   header = (1 << 9) | 7 = 0x0207
 *   → bytes: 0x02 0x07 [subtype=4] [MAC 6 bytes]
 *
 * ── Envío con AF_PACKET ───────────────────────────────────────────
 *
 *   1. socket(AF_PACKET, SOCK_RAW, htons(0x88cc))
 *   2. ioctl(SIOCGIFINDEX) → ifindex
 *   3. Construir frame completo en buffer
 *   4. sendto() con sockaddr_ll
 *
 *   Sin CAP_NET_RAW (no root) → socket() devuelve EPERM.
 *   Lo ignoramos silenciosamente (LLDP es opcional).
 *
 * ── Lectura de vecinos con lldpctl ───────────────────────────────
 *
 *   lldpctl -f json retorna:
 *   {
 *     "lldp": {
 *       "interface": [
 *         {
 *           "name": "eth0",
 *           "chassis": {
 *             "id":   {"type":"mac", "value":"aa:bb:..."},
 *             "name": {"value":"switch1"},
 *             "descr":{"value":"Cisco Catalyst 2960"}
 *           },
 *           "port": {
 *             "id":   {"type":"ifname", "value":"Gi1/0/3"},
 *             "descr":{"value":"to-AP"}
 *           }
 *         }
 *       ]
 *     }
 *   }
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <json-c/json.h>

#include "lldp.h"

/* ─── Constantes ────────────────────────────────────────────────── */
static const uint8_t LLDP_DST[6]  = {0x01,0x80,0xc2,0x00,0x00,0x0e};
#define LLDP_ETHERTYPE   0x88cc
#define CAP_WLAN_AP      0x0040

/* ─── Escribir TLV en buffer ────────────────────────────────────── */
static int tlv_write(uint8_t *buf, int pos, int maxlen,
                     int type, const uint8_t *val, int vlen)
{
    if (pos + 2 + vlen > maxlen) return pos;
    uint16_t hdr = (uint16_t)((type << 9) | (vlen & 0x1ff));
    buf[pos++] = (hdr >> 8) & 0xff;
    buf[pos++] =  hdr       & 0xff;
    if (val && vlen > 0) { memcpy(buf+pos, val, vlen); pos += vlen; }
    return pos;
}

static int tlv_str(uint8_t *buf, int pos, int maxlen,
                   int type, const char *str)
{
    return tlv_write(buf, pos, maxlen, type,
                     (const uint8_t*)str, (int)strlen(str));
}

/* ─── Parsear MAC "aa:bb:cc:dd:ee:ff" → bytes ──────────────────── */
static void parse_mac(const char *s, uint8_t out[6])
{
    unsigned int b[6]={0};
    sscanf(s,"%x:%x:%x:%x:%x:%x",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
    for(int i=0;i<6;i++) out[i]=(uint8_t)b[i];
}

/* ═══════════════════════════════════════════════════════════════════
   lldp_send_frame
   ═══════════════════════════════════════════════════════════════════ */
int lldp_send_frame(const char *ifname,
                    const char *mac_str,
                    const char *hostname,
                    const char *model_desc,
                    int ttl)
{
    /* Socket raw — requiere root */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(LLDP_ETHERTYPE));
    if (fd < 0) return -1;   /* EPERM sin root → silencioso */

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    int ifindex = ifr.ifr_ifindex;

    uint8_t src[6];
    parse_mac(mac_str, src);

    uint8_t frame[1518];
    int pos = 0;

    /* Ethernet header */
    memcpy(frame,   LLDP_DST, 6);  pos += 6;  /* dst */
    memcpy(frame+6, src, 6);       pos += 6;  /* src */
    frame[pos++] = 0x88;
    frame[pos++] = 0xcc;           /* EtherType 0x88cc */

    /* TLV: Chassis ID (type=1): subtype=4(MAC) + MAC */
    {
        uint8_t v[7]; v[0]=4; memcpy(v+1,src,6);
        pos = tlv_write(frame, pos, sizeof(frame), 1, v, 7);
    }

    /* TLV: Port ID (type=2): subtype=5(ifname) + nombre */
    {
        size_t nlen = strlen(ifname);
        uint8_t v[64]; v[0]=5; memcpy(v+1,ifname,nlen);
        pos = tlv_write(frame, pos, sizeof(frame), 2, v, (int)nlen+1);
    }

    /* TLV: TTL (type=3): uint16 BE */
    {
        uint8_t v[2] = {(uint8_t)(ttl>>8),(uint8_t)(ttl&0xff)};
        pos = tlv_write(frame, pos, sizeof(frame), 3, v, 2);
    }

    /* TLV: System Name (type=5) */
    if (hostname && hostname[0])
        pos = tlv_str(frame, pos, sizeof(frame), 5, hostname);

    /* TLV: System Description (type=6) */
    if (model_desc && model_desc[0])
        pos = tlv_str(frame, pos, sizeof(frame), 6, model_desc);

    /* TLV: System Capabilities (type=7): caps + enabled (WLAN AP) */
    {
        uint8_t v[4] = {
            0x00, (uint8_t)(CAP_WLAN_AP >> 8),
            0x00, (uint8_t)(CAP_WLAN_AP & 0xff)
        };
        /* Corregir: CAP_WLAN_AP = 0x0040, un solo byte basta */
        v[1] = 0x00; v[0] = 0x00;
        /* bit 6 de los 16 bits de capabilities */
        uint16_t cap = CAP_WLAN_AP;
        v[0] = (cap >> 8) & 0xff; v[1] = cap & 0xff;
        v[2] = v[0]; v[3] = v[1]; /* enabled = same */
        pos = tlv_write(frame, pos, sizeof(frame), 7, v, 4);
    }

    /* TLV: End (type=0, len=0) */
    pos = tlv_write(frame, pos, sizeof(frame), 0, NULL, 0);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family  = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen   = ETH_ALEN;
    memcpy(sa.sll_addr, LLDP_DST, 6);

    ssize_t sent = sendto(fd, frame, pos, 0,
                          (struct sockaddr*)&sa, sizeof(sa));
    close(fd);
    return (sent > 0) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════
   lldp_available
   ═══════════════════════════════════════════════════════════════════ */
bool lldp_available(void)
{
    return (access("/usr/sbin/lldpctl", X_OK) == 0 ||
            access("/usr/bin/lldpctl", X_OK) == 0);
}

/* ═══════════════════════════════════════════════════════════════════
   lldp_read_neighbors — parsea JSON de lldpctl
   ═══════════════════════════════════════════════════════════════════

   Navega: root → "lldp" → "interface" (array) → cada vecino.
   Por cada vecino extrae: chassis.id, chassis.name, chassis.descr,
   port.id, port.descr, y el nombre de la interfaz local.

   El resultado se incluye en lldp_table[] del payload inform.
   El controlador lo usa para dibujar las líneas de conexión en
   la topología visual (qué switch/puerto conecta a este AP).
*/
struct json_object *lldp_read_neighbors(void)
{
    struct json_object *result = json_object_new_array();
    if (!lldp_available()) return result;

    FILE *p = popen("lldpctl -f json 2>/dev/null", "r");
    if (!p) return result;

    /* Leer toda la salida (limitado a 16KB) */
    char buf[16384] = {0};
    size_t total = 0, n;
    char tmp[1024];
    while ((n = fread(tmp, 1, sizeof(tmp), p)) > 0 &&
           total + n < sizeof(buf)-1) {
        memcpy(buf+total, tmp, n); total += n;
    }
    pclose(p);
    if (!total) return result;

    struct json_object *root = json_tokener_parse(buf);
    if (!root) return result;

    /* Navegar: root.lldp.interface[] */
    struct json_object *lldp_o, *iface_arr;
    if (!json_object_object_get_ex(root, "lldp",      &lldp_o))  goto done;
    if (!json_object_object_get_ex(lldp_o, "interface", &iface_arr)) goto done;
    if (!json_object_is_type(iface_arr, json_type_array))            goto done;

    int ni = json_object_array_length(iface_arr);
    for (int i = 0; i < ni; i++) {
        struct json_object *iface = json_object_array_get_idx(iface_arr, i);
        if (!iface) continue;

        /* Puerto local */
        struct json_object *tmp_o;
        const char *local_port = "";
        if (json_object_object_get_ex(iface, "name", &tmp_o))
            local_port = json_object_get_string(tmp_o);

        /* Chassis */
        const char *chassis_id="", *sys_name="", *sys_desc="";
        struct json_object *chassis;
        if (json_object_object_get_ex(iface, "chassis", &chassis)) {
            struct json_object *cid, *cname, *cdescr;
            if (json_object_object_get_ex(chassis, "id", &cid)) {
                struct json_object *cv;
                if (json_object_object_get_ex(cid, "value", &cv))
                    chassis_id = json_object_get_string(cv);
            }
            if (json_object_object_get_ex(chassis, "name", &cname)) {
                struct json_object *cv;
                if (json_object_object_get_ex(cname, "value", &cv))
                    sys_name = json_object_get_string(cv);
            }
            if (json_object_object_get_ex(chassis, "descr", &cdescr)) {
                struct json_object *cv;
                if (json_object_object_get_ex(cdescr, "value", &cv))
                    sys_desc = json_object_get_string(cv);
            }
        }

        /* Port */
        const char *port_id="", *port_desc="";
        struct json_object *port;
        if (json_object_object_get_ex(iface, "port", &port)) {
            struct json_object *pid, *pdesc;
            if (json_object_object_get_ex(port, "id", &pid)) {
                struct json_object *pv;
                if (json_object_object_get_ex(pid, "value", &pv))
                    port_id = json_object_get_string(pv);
            }
            if (json_object_object_get_ex(port, "descr", &pdesc)) {
                struct json_object *pv;
                if (json_object_object_get_ex(pdesc, "value", &pv))
                    port_desc = json_object_get_string(pv);
            }
        }

        struct json_object *e = json_object_new_object();
        json_object_object_add(e, "local_port", json_object_new_string(local_port));
        json_object_object_add(e, "chassis_id", json_object_new_string(chassis_id));
        json_object_object_add(e, "port_id",    json_object_new_string(port_id));
        json_object_object_add(e, "sys_name",   json_object_new_string(sys_name));
        json_object_object_add(e, "sys_desc",   json_object_new_string(sys_desc));
        json_object_object_add(e, "port_desc",  json_object_new_string(port_desc));
        json_object_object_add(e, "port_table", json_object_new_array());
        json_object_array_add(result, e);
    }

done:
    json_object_put(root);
    return result;
}
