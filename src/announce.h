#ifndef OPENUF_ANNOUNCE_H
#define OPENUF_ANNOUNCE_H

#include "ufmodel.h"

/* Announce context – keeps mutable state between sends */
typedef struct {
    int            sockfd;       /* socket broadcast */
    int            sockfd_mcast; /* socket multicast 233.89.188.1 */
    unsigned char  pkt[512];
    int            pkt_len;
    int            ctr_offset;   /* byte offset of counter field in pkt */
    int            uptime_offset;
    uint32_t       counter;
    uint32_t       uptime;
} announce_ctx_t;

/* Build the static part of the announce packet and open the UDP socket.
 * mac_str  : "aa:bb:cc:dd:ee:ff"
 * ip_str   : "192.168.1.x"
 * Returns 0 on success. */
int  announce_init(announce_ctx_t *ctx,
                   const uf_model_t *model,
                   const char *mac_str,
                   const char *ip_str);

/* Send one announce burst to 255.255.255.255:10001.
 * Increments counter and uptime. Returns 0 on success. */
int  announce_send(announce_ctx_t *ctx);

/* Close the socket */
void announce_close(announce_ctx_t *ctx);

#endif /* OPENUF_ANNOUNCE_H */
