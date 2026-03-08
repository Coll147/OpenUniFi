/*
 * openuf - announce.c — Descubrimiento UDP UniFi puerto 10001.
 * Envía a broadcast 255.255.255.255 y multicast 233.89.188.1.
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

#define DBG_TAG "announce"

#define PKT_TYPE_HW_ADDR       0x01
#define PKT_TYPE_IP_ADDR       0x02
#define PKT_TYPE_FWVER_VERBOSE 0x03
#define PKT_TYPE_UPTIME        0x0a
#define PKT_TYPE_HOSTNAME      0x0b
#define PKT_TYPE_PLATFORM      0x0c
#define PKT_TYPE_INC_COUNTER   0x12
#define PKT_TYPE_HW_ADDR2      0x13
#define PKT_TYPE_PLATFORM2     0x15
#define PKT_TYPE_FWVER_SHORT   0x16
#define PKT_TYPE_FWVER_FACTORY 0x1b

static const unsigned char PKT_BLOB[] = {
    0x17,0x00,0x01,0x01, 0x18,0x00,0x01,0x00,
    0x19,0x00,0x01,0x01, 0x1a,0x00,0x01,0x00,
};

static int tlv_append(unsigned char *pkt, int pos, int max,
                      uint8_t type, const unsigned char *val, int vlen) {
    if (pos+3+vlen>max) { LOG_WARN("TLV 0x%02x no cabe (pos=%d)", type, pos); return pos; }
    pkt[pos++]=type; pkt[pos++]=(vlen>>8)&0xff; pkt[pos++]=vlen&0xff;
    memcpy(pkt+pos,val,vlen);
    LOG_TRACE("  TLV 0x%02x len=%-3d  [%d..%d]", type, vlen, pos-3, pos+vlen-1);
    return pos+vlen;
}
static int tlv_str(unsigned char *pkt, int pos, int max, uint8_t type, const char *str) {
    return tlv_append(pkt,pos,max,type,(const unsigned char*)str,(int)strlen(str));
}
static void put32be(unsigned char *p, uint32_t v) {
    p[0]=(v>>24)&0xff;p[1]=(v>>16)&0xff;p[2]=(v>>8)&0xff;p[3]=v&0xff;
}
static void parse_mac(const char *s, unsigned char o[6]) {
    unsigned int b[6]={0};
    sscanf(s,"%x:%x:%x:%x:%x:%x",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
    for(int i=0;i<6;i++) o[i]=(unsigned char)b[i];
}
static void parse_ip(const char *s, unsigned char o[4]) {
    unsigned int b[4]={0}; sscanf(s,"%u.%u.%u.%u",&b[0],&b[1],&b[2],&b[3]);
    for(int i=0;i<4;i++) o[i]=(unsigned char)b[i];
}

int announce_init(announce_ctx_t *ctx, const uf_model_t *m,
                  const char *mac_str, const char *ip_str) {
    memset(ctx,0,sizeof(*ctx)); ctx->sockfd=ctx->sockfd_mcast=-1;
    LOG_INFO("init: modelo=%s  MAC=%s  IP=%s", m->model, mac_str, ip_str);
    unsigned char mac[6],ip[4];
    parse_mac(mac_str,mac); parse_ip(ip_str,ip);
    LOG_TRACE("MAC bytes: %02x:%02x:%02x:%02x:%02x:%02x", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    unsigned char *p=ctx->pkt; int pos=0,max=(int)sizeof(ctx->pkt);
    p[pos++]=0x02;p[pos++]=0x06;p[pos++]=0x00;p[pos++]=0x00;

    { unsigned char v[10]; memcpy(v,mac,6); memcpy(v+6,ip,4);
      pos=tlv_append(p,pos,max,PKT_TYPE_IP_ADDR,v,10); }
    pos=tlv_append(p,pos,max,PKT_TYPE_HW_ADDR,mac,6);
    { unsigned char u4[4]={0,0,0,10}; ctx->uptime_offset=pos+3;
      pos=tlv_append(p,pos,max,PKT_TYPE_UPTIME,u4,4); }
    LOG_TRACE("uptime_offset=%d", ctx->uptime_offset);

    pos=tlv_str(p,pos,max,PKT_TYPE_HOSTNAME,m->display_name);
    pos=tlv_str(p,pos,max,PKT_TYPE_PLATFORM,m->platform);

    { char fwv[128]; snprintf(fwv,sizeof(fwv),"%s%s-openUF-%s.%s",
        m->fw_pre,m->fw_ver,OPENUF_VERSION,m->fw_buildtime);
      LOG_DBG("fw_verbose: %s", fwv);
      pos=tlv_str(p,pos,max,PKT_TYPE_FWVER_VERBOSE,fwv); }
    { char fws[64]; snprintf(fws,sizeof(fws),"%s-openUF-%s",m->fw_ver,OPENUF_VERSION);
      LOG_DBG("fw_short: %s", fws);
      pos=tlv_str(p,pos,max,PKT_TYPE_FWVER_SHORT,fws); }

    pos=tlv_str(p,pos,max,PKT_TYPE_PLATFORM2,m->platform);
    memcpy(p+pos,PKT_BLOB,sizeof(PKT_BLOB)); pos+=sizeof(PKT_BLOB);
    pos=tlv_append(p,pos,max,PKT_TYPE_HW_ADDR2,mac,6);
    { unsigned char c4[4]={0}; ctx->ctr_offset=pos+3;
      pos=tlv_append(p,pos,max,PKT_TYPE_INC_COUNTER,c4,4); }
    pos=tlv_str(p,pos,max,PKT_TYPE_FWVER_FACTORY,m->fw_factoryver);

    p[3]=(unsigned char)((pos-4)&0xff);
    ctx->pkt_len=pos; ctx->counter=0; ctx->uptime=10;
    LOG_INFO("paquete construido: %d bytes  (%d payload)", pos, pos-4);
    DBG_HEX("paquete announce inicial", p, pos);

    ctx->sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if (ctx->sockfd<0) { LOG_ERR("socket broadcast: %m"); return -1; }
    int on=1; setsockopt(ctx->sockfd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on));
    struct sockaddr_in ba={.sin_family=AF_INET,.sin_addr.s_addr=INADDR_ANY};
    bind(ctx->sockfd,(struct sockaddr*)&ba,sizeof(ba));
    LOG_DBG("socket broadcast listo (fd=%d)", ctx->sockfd);

    ctx->sockfd_mcast=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if (ctx->sockfd_mcast>=0) {
        int ttl=1,loop=0;
        setsockopt(ctx->sockfd_mcast,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl));
        setsockopt(ctx->sockfd_mcast,IPPROTO_IP,IP_MULTICAST_LOOP,&loop,sizeof(loop));
        bind(ctx->sockfd_mcast,(struct sockaddr*)&ba,sizeof(ba));
        LOG_DBG("socket multicast listo (fd=%d  TTL=1)", ctx->sockfd_mcast);
    } else {
        LOG_WARN("socket multicast no disponible — sólo broadcast");
    }
    return 0;
}

int announce_send(announce_ctx_t *ctx) {
    ctx->counter++; ctx->uptime+=ANNOUNCE_INTERVAL;
    put32be(ctx->pkt+ctx->ctr_offset,   ctx->counter);
    put32be(ctx->pkt+ctx->uptime_offset,ctx->uptime);
    LOG_DBG("enviando: contador=%u  uptime=%us  %d bytes",
            ctx->counter, ctx->uptime, ctx->pkt_len);
    DBG_HEX("paquete announce", ctx->pkt, ctx->pkt_len);
    int ret=0;
    struct sockaddr_in db={.sin_family=AF_INET,.sin_port=htons(ANNOUNCE_PORT),
                            .sin_addr.s_addr=INADDR_BROADCAST};
    ssize_t s=sendto(ctx->sockfd,ctx->pkt,ctx->pkt_len,0,(struct sockaddr*)&db,sizeof(db));
    if (s<0) { LOG_ERR("broadcast sendto: %m"); ret=-1; }
    else LOG_TRACE("broadcast → 255.255.255.255:%d  %zd bytes", ANNOUNCE_PORT, s);

    if (ctx->sockfd_mcast>=0) {
        struct sockaddr_in dm={.sin_family=AF_INET,.sin_port=htons(ANNOUNCE_PORT)};
        inet_pton(AF_INET,"233.89.188.1",&dm.sin_addr);
        ssize_t sm=sendto(ctx->sockfd_mcast,ctx->pkt,ctx->pkt_len,0,(struct sockaddr*)&dm,sizeof(dm));
        if (sm<0) LOG_TRACE("multicast 233.89.188.1: %m (sin ruta — normal sin red MC)");
        else      LOG_TRACE("multicast → 233.89.188.1:%d  %zd bytes", ANNOUNCE_PORT, sm);
    }
    return ret;
}

void announce_close(announce_ctx_t *ctx) {
    LOG_INFO("cerrando (total %u envíos)...", ctx->counter);
    if (ctx->sockfd     >=0) { close(ctx->sockfd);       ctx->sockfd=-1; }
    if (ctx->sockfd_mcast>=0){ close(ctx->sockfd_mcast); ctx->sockfd_mcast=-1; }
}
