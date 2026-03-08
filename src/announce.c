/*
 * openuf - announce.c
 *
 * Implementa el protocolo de descubrimiento UDP de UniFi (puerto 10001).
 *
 * ── Destinos ─────────────────────────────────────────────────────────
 * El protocolo especifica que los paquetes de anuncio se envían a DOS destinos:
 *   1. Broadcast:  255.255.255.255:10001
 *   2. Multicast:  233.89.188.1:10001   ← requerido para redes con multicast
 *
 * El controlador UniFi escucha en ambas direcciones.
 * Usar sólo broadcast puede fallar en redes donde el broadcast está filtrado.
 *
 * ── Formato del paquete ──────────────────────────────────────────────
 * Header: [0x02][0x06][0x00][total_payload_len]  (4 bytes fijos)
 * TLVs:   [type:1][len_hi:1][len_lo:1][value:len]
 *
 * ── Modelo U6 InWall ─────────────────────────────────────────────────
 * Se emula este modelo específicamente porque:
 *   - Tiene 5 puertos GbE (eth0-eth4): cubre la mayoría de routers OpenWrt
 *   - Soporta WiFi 6 (802.11ax) en 2.4 GHz y 5 GHz
 *   - Tiene PoE passthrough (útil para redes de campus)
 *   - Es un modelo actual y bien soportado por el controlador
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "announce.h"
#include "config.h"

/* ─── Packet type constants ─────────────────────────────────────── */
#define PKT_TYPE_HW_ADDR        0x01
#define PKT_TYPE_IP_ADDR        0x02
#define PKT_TYPE_FWVER_VERBOSE  0x03
#define PKT_TYPE_UPTIME         0x0a
#define PKT_TYPE_HOSTNAME       0x0b
#define PKT_TYPE_PLATFORM       0x0c
#define PKT_TYPE_INC_COUNTER    0x12
#define PKT_TYPE_HW_ADDR2       0x13
#define PKT_TYPE_PLATFORM2      0x15
#define PKT_TYPE_FWVER_SHORT    0x16
#define PKT_TYPE_FWVER_FACTORY  0x1b

/* Fixed capability blob (types 0x17–0x1a) */
static const unsigned char PKT_BLOB[] = {
    0x17, 0x00, 0x01, 0x01,
    0x18, 0x00, 0x01, 0x00,
    0x19, 0x00, 0x01, 0x01,
    0x1a, 0x00, 0x01, 0x00,
};

/* ─── TLV helpers ───────────────────────────────────────────────── */
static int tlv_append(unsigned char *pkt, int pos, int max,
                      uint8_t type, const unsigned char *val, int vlen)
{
    if (pos + 3 + vlen > max) return pos;
    pkt[pos++] = type;
    pkt[pos++] = (vlen >> 8) & 0xff;
    pkt[pos++] = vlen & 0xff;
    memcpy(pkt + pos, val, vlen);
    return pos + vlen;
}

static int tlv_str(unsigned char *pkt, int pos, int max,
                   uint8_t type, const char *str)
{
    return tlv_append(pkt, pos, max, type,
                      (const unsigned char *)str, strlen(str));
}

static void put32be(unsigned char *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xff;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >>  8) & 0xff;
    p[3] =  v        & 0xff;
}

/* ─── parse_mac ─────────────────────────────────────────────────── */
static void parse_mac(const char *s, unsigned char out[6])
{
    unsigned int b[6] = {0};
    sscanf(s, "%x:%x:%x:%x:%x:%x",
           &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
    for (int i = 0; i < 6; i++) out[i] = (unsigned char)b[i];
}

static void parse_ip(const char *s, unsigned char out[4])
{
    unsigned int b[4] = {0};
    sscanf(s, "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]);
    for (int i = 0; i < 4; i++) out[i] = (unsigned char)b[i];
}

/* ─── announce_init ─────────────────────────────────────────────── */
int announce_init(announce_ctx_t *ctx,
                  const uf_model_t *m,
                  const char *mac_str,
                  const char *ip_str)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->sockfd      = -1;
    ctx->sockfd_mcast = -1;

    unsigned char mac[6], ip[4];
    parse_mac(mac_str, mac);
    parse_ip(ip_str,   ip);

    unsigned char *p   = ctx->pkt;
    int            pos = 0;
    int            max = (int)sizeof(ctx->pkt);

    /* Packet header: version=2, reserved=6, flags=0, len (filled later) */
    p[pos++] = 0x02;
    p[pos++] = 0x06;
    p[pos++] = 0x00;
    p[pos++] = 0x00;   /* total_payload_len – patched at end */

    /* IP_ADDR TLV: mac(6) + ip(4) */
    {
        unsigned char val[10];
        memcpy(val,     mac, 6);
        memcpy(val + 6, ip,  4);
        pos = tlv_append(p, pos, max, PKT_TYPE_IP_ADDR, val, 10);
    }

    /* HW_ADDR: mac */
    pos = tlv_append(p, pos, max, PKT_TYPE_HW_ADDR, mac, 6);

    /* UPTIME: 4-byte BE – record offset for patching */
    {
        unsigned char u4[4] = {0, 0, 0, 10};
        ctx->uptime_offset = pos + 3;   /* offset of the value bytes */
        pos = tlv_append(p, pos, max, PKT_TYPE_UPTIME, u4, 4);
    }

    /* HOSTNAME */
    pos = tlv_str(p, pos, max, PKT_TYPE_HOSTNAME, m->display_name);

    /* PLATFORM */
    pos = tlv_str(p, pos, max, PKT_TYPE_PLATFORM, m->platform);

    /* FWVER_VERBOSE: "<pre><ver>-<version>.<buildtime>" */
    {
        char fwv[128];
        snprintf(fwv, sizeof(fwv), "%s%s-openUF-%s.%s",
                 m->fw_pre, m->fw_ver, OPENUF_VERSION, m->fw_buildtime);
        pos = tlv_str(p, pos, max, PKT_TYPE_FWVER_VERBOSE, fwv);
    }

    /* FWVER_SHORT: "<ver>-openUF-<version>" */
    {
        char fws[64];
        snprintf(fws, sizeof(fws), "%s-openUF-%s", m->fw_ver, OPENUF_VERSION);
        pos = tlv_str(p, pos, max, PKT_TYPE_FWVER_SHORT, fws);
    }

    /* PLATFORM2 */
    pos = tlv_str(p, pos, max, PKT_TYPE_PLATFORM2, m->platform);

    /* Capability blob */
    memcpy(p + pos, PKT_BLOB, sizeof(PKT_BLOB));
    pos += sizeof(PKT_BLOB);

    /* HW_ADDR2: mac */
    pos = tlv_append(p, pos, max, PKT_TYPE_HW_ADDR2, mac, 6);

    /* INC_COUNTER: 4 bytes – record offset for patching */
    {
        unsigned char c4[4] = {0, 0, 0, 0};
        ctx->ctr_offset = pos + 3;
        pos = tlv_append(p, pos, max, PKT_TYPE_INC_COUNTER, c4, 4);
    }

    /* FWVER_FACTORY */
    pos = tlv_str(p, pos, max, PKT_TYPE_FWVER_FACTORY, m->fw_factoryver);

    /* Patch total payload length (byte 3 = total - 4 header bytes) */
    p[3] = (unsigned char)((pos - 4) & 0xff);

    ctx->pkt_len = pos;
    ctx->counter = 0;
    ctx->uptime  = 10;

    /* ── Socket para broadcast 255.255.255.255 ─────────────────── */
    ctx->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->sockfd < 0) {
        perror("[openuf] announce socket");
        return -1;
    }
    int on = 1;
    setsockopt(ctx->sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    /* Bind a puerto efímero — OpenWrt no permite setpeername() a broadcast */
    struct sockaddr_in bind_addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = 0,
    };
    bind(ctx->sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

    /* ── Socket para multicast 233.89.188.1 ────────────────────── */
    /* El controlador UniFi también escucha en este grupo multicast.
     * Esto es necesario cuando broadcast está filtrado en la red. */
    ctx->sockfd_mcast = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->sockfd_mcast >= 0) {
        int ttl = 1; /* TTL=1: no cruzar router */
        setsockopt(ctx->sockfd_mcast, IPPROTO_IP, IP_MULTICAST_TTL,
                   &ttl, sizeof(ttl));
        int loop = 0;
        setsockopt(ctx->sockfd_mcast, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &loop, sizeof(loop));
        bind(ctx->sockfd_mcast, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    }

    return 0;
}

/* ─── announce_send ─────────────────────────────────────────────── */
int announce_send(announce_ctx_t *ctx)
{
    ctx->counter++;
    ctx->uptime += 10;

    /* Patch counter and uptime in the packet buffer */
    put32be(ctx->pkt + ctx->ctr_offset,    ctx->counter);
    put32be(ctx->pkt + ctx->uptime_offset, ctx->uptime);

    int ret = 0;

    /* ── Envío 1: Broadcast 255.255.255.255:10001 ─────────────── */
    struct sockaddr_in dest_bcast = {
        .sin_family      = AF_INET,
        .sin_port        = htons(ANNOUNCE_PORT),
        .sin_addr.s_addr = INADDR_BROADCAST,
    };
    if (sendto(ctx->sockfd, ctx->pkt, ctx->pkt_len, 0,
               (struct sockaddr *)&dest_bcast, sizeof(dest_bcast)) < 0) {
        perror("[openuf] announce sendto broadcast");
        ret = -1;
    }

    /* ── Envío 2: Multicast 233.89.188.1:10001 ────────────────── */
    if (ctx->sockfd_mcast >= 0) {
        struct sockaddr_in dest_mcast = {
            .sin_family = AF_INET,
            .sin_port   = htons(ANNOUNCE_PORT),
        };
        inet_pton(AF_INET, "233.89.188.1", &dest_mcast.sin_addr);
        if (sendto(ctx->sockfd_mcast, ctx->pkt, ctx->pkt_len, 0,
                   (struct sockaddr *)&dest_mcast, sizeof(dest_mcast)) < 0) {
            /* No es error crítico — algunos kernels no tienen ruta multicast */
        }
    }

    return ret;
}

/* ─── announce_close ────────────────────────────────────────────── */
void announce_close(announce_ctx_t *ctx)
{
    if (ctx->sockfd >= 0) {
        close(ctx->sockfd);
        ctx->sockfd = -1;
    }
    if (ctx->sockfd_mcast >= 0) {
        close(ctx->sockfd_mcast);
        ctx->sockfd_mcast = -1;
    }
}
