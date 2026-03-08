/*
 * openuf - announce.c
 * Descubrimiento L2/L3 UniFi — UDP broadcast + multicast.
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
#include "debug.h"

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

static const unsigned char PKT_BLOB[] = {
    0x17,0x00,0x01,0x01,
    0x18,0x00,0x01,0x00,
    0x19,0x00,0x01,0x01,
    0x1a,0x00,0x01,0x00,
};

static int tlv_append(unsigned char *pkt, int pos, int max,
                      uint8_t type, const unsigned char *val, int vlen)
{
    if (pos + 3 + vlen > max) { DLOG("announce: TLV desbordamiento type=0x%02x", type); return pos; }
    pkt[pos++] = type;
    pkt[pos++] = (vlen >> 8) & 0xff;
    pkt[pos++] = vlen & 0xff;
    memcpy(pkt + pos, val, vlen);
    DLOG("announce: TLV type=0x%02x len=%d", type, vlen);
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
    p[0]=(v>>24)&0xff; p[1]=(v>>16)&0xff;
    p[2]=(v>>8)&0xff;  p[3]=v&0xff;
}

static void parse_mac(const char *s, unsigned char out[6])
{
    unsigned int b[6]={0};
    sscanf(s,"%x:%x:%x:%x:%x:%x",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
    for(int i=0;i<6;i++) out[i]=(unsigned char)b[i];
    DLOG("announce: MAC parseada '%s' → %02x:%02x:%02x:%02x:%02x:%02x",
         s, out[0],out[1],out[2],out[3],out[4],out[5]);
}

static void parse_ip(const char *s, unsigned char out[4])
{
    unsigned int b[4]={0};
    sscanf(s,"%u.%u.%u.%u",&b[0],&b[1],&b[2],&b[3]);
    for(int i=0;i<4;i++) out[i]=(unsigned char)b[i];
    DLOG("announce: IP parseada '%s' → %d.%d.%d.%d", s, out[0],out[1],out[2],out[3]);
}

int announce_init(announce_ctx_t *ctx,
                  const uf_model_t *m,
                  const char *mac_str,
                  const char *ip_str)
{
    DLOG("announce: init — modelo=%s mac=%s ip=%s", m->model, mac_str, ip_str);
    memset(ctx, 0, sizeof(*ctx));
    ctx->sockfd       = -1;
    ctx->sockfd_mcast = -1;

    unsigned char mac[6], ip[4];
    parse_mac(mac_str, mac);
    parse_ip(ip_str,   ip);

    unsigned char *p   = ctx->pkt;
    int            pos = 0;
    int            max = (int)sizeof(ctx->pkt);

    /* Header */
    p[pos++]=0x02; p[pos++]=0x06; p[pos++]=0x00; p[pos++]=0x00;
    DLOG("announce: cabecera del paquete escrita (4 bytes)");

    /* IP_ADDR TLV: mac(6) + ip(4) */
    {
        unsigned char val[10];
        memcpy(val, mac, 6); memcpy(val+6, ip, 4);
        pos = tlv_append(p, pos, max, PKT_TYPE_IP_ADDR, val, 10);
    }
    pos = tlv_append(p, pos, max, PKT_TYPE_HW_ADDR, mac, 6);

    {
        unsigned char u4[4]={0,0,0,10};
        ctx->uptime_offset = pos + 3;
        pos = tlv_append(p, pos, max, PKT_TYPE_UPTIME, u4, 4);
        DLOG("announce: uptime_offset=%d", ctx->uptime_offset);
    }

    pos = tlv_str(p, pos, max, PKT_TYPE_HOSTNAME, m->display_name);
    pos = tlv_str(p, pos, max, PKT_TYPE_PLATFORM, m->platform);

    {
        char fwv[128];
        snprintf(fwv, sizeof(fwv), "%s%s-openUF-%s.%s",
                 m->fw_pre, m->fw_ver, OPENUF_VERSION, m->fw_buildtime);
        DLOG("announce: fw_verbose = '%s'", fwv);
        pos = tlv_str(p, pos, max, PKT_TYPE_FWVER_VERBOSE, fwv);
    }
    {
        char fws[64];
        snprintf(fws, sizeof(fws), "%s-openUF-%s", m->fw_ver, OPENUF_VERSION);
        DLOG("announce: fw_short = '%s'", fws);
        pos = tlv_str(p, pos, max, PKT_TYPE_FWVER_SHORT, fws);
    }

    pos = tlv_str(p, pos, max, PKT_TYPE_PLATFORM2, m->platform);
    memcpy(p+pos, PKT_BLOB, sizeof(PKT_BLOB)); pos += sizeof(PKT_BLOB);
    DLOG("announce: blob de capacidades escrito (%zu bytes)", sizeof(PKT_BLOB));
    pos = tlv_append(p, pos, max, PKT_TYPE_HW_ADDR2, mac, 6);

    {
        unsigned char c4[4]={0};
        ctx->ctr_offset = pos + 3;
        pos = tlv_append(p, pos, max, PKT_TYPE_INC_COUNTER, c4, 4);
        DLOG("announce: ctr_offset=%d", ctx->ctr_offset);
    }

    pos = tlv_str(p, pos, max, PKT_TYPE_FWVER_FACTORY, m->fw_factoryver);
    p[3] = (unsigned char)((pos-4) & 0xff);
    ctx->pkt_len = pos;
    ctx->counter = 0;
    ctx->uptime  = 10;
    DLOG("announce: paquete construido — total=%d bytes payload=%d bytes", pos, pos-4);
    DLOG_HEX("announce pkt", p, pos);

    /* Socket broadcast */
    DLOG("announce: abriendo socket broadcast");
    ctx->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->sockfd < 0) { DLOG("announce: socket broadcast FALLO errno=%d", errno); return -1; }
    int on = 1;
    setsockopt(ctx->sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    struct sockaddr_in bind_addr = {.sin_family=AF_INET,.sin_addr.s_addr=INADDR_ANY,.sin_port=0};
    bind(ctx->sockfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr));
    DLOG("announce: socket broadcast listo (fd=%d)", ctx->sockfd);

    /* Socket multicast */
    DLOG("announce: abriendo socket multicast 233.89.188.1");
    ctx->sockfd_mcast = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->sockfd_mcast >= 0) {
        int ttl=1, loop=0;
        setsockopt(ctx->sockfd_mcast, IPPROTO_IP, IP_MULTICAST_TTL,  &ttl,  sizeof(ttl));
        setsockopt(ctx->sockfd_mcast, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
        bind(ctx->sockfd_mcast, (struct sockaddr*)&bind_addr, sizeof(bind_addr));
        DLOG("announce: socket multicast listo (fd=%d ttl=%d)", ctx->sockfd_mcast, ttl);
    } else {
        DLOG("announce: socket multicast FALLO (no critico)");
    }

    DLOG("announce: init completado OK");
    return 0;
}

int announce_send(announce_ctx_t *ctx)
{
    ctx->counter++;
    ctx->uptime += 10;
    put32be(ctx->pkt + ctx->ctr_offset,    ctx->counter);
    put32be(ctx->pkt + ctx->uptime_offset, ctx->uptime);

    DLOG("announce: enviando paquete #%u (uptime=%us pkt_len=%d)",
         ctx->counter, ctx->uptime, ctx->pkt_len);

    int ret = 0;

    /* Broadcast */
    struct sockaddr_in dest_bcast = {
        .sin_family=AF_INET, .sin_port=htons(ANNOUNCE_PORT),
        .sin_addr.s_addr=INADDR_BROADCAST,
    };
    ssize_t n = sendto(ctx->sockfd, ctx->pkt, ctx->pkt_len, 0,
                       (struct sockaddr*)&dest_bcast, sizeof(dest_bcast));
    if (n < 0) { DLOG("announce: sendto broadcast FALLO errno=%d", errno); ret=-1; }
    else        DLOG("announce: broadcast 255.255.255.255:%d → %zd bytes enviados", ANNOUNCE_PORT, n);

    /* Multicast */
    if (ctx->sockfd_mcast >= 0) {
        struct sockaddr_in dest_mcast = {.sin_family=AF_INET,.sin_port=htons(ANNOUNCE_PORT)};
        inet_pton(AF_INET, "233.89.188.1", &dest_mcast.sin_addr);
        n = sendto(ctx->sockfd_mcast, ctx->pkt, ctx->pkt_len, 0,
                   (struct sockaddr*)&dest_mcast, sizeof(dest_mcast));
        if (n < 0) DLOG("announce: sendto multicast FALLO errno=%d (sin ruta multicast?)", errno);
        else        DLOG("announce: multicast 233.89.188.1:%d → %zd bytes enviados", ANNOUNCE_PORT, n);
    }

    return ret;
}

void announce_close(announce_ctx_t *ctx)
{
    DLOG("announce: cerrando sockets");
    if (ctx->sockfd >= 0) { close(ctx->sockfd); ctx->sockfd=-1; }
    if (ctx->sockfd_mcast >= 0) { close(ctx->sockfd_mcast); ctx->sockfd_mcast=-1; }
    DLOG("announce: sockets cerrados");
}
