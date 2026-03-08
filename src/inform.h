#ifndef OPENUF_INFORM_H
#define OPENUF_INFORM_H

#include "state.h"
#include "ufmodel.h"

/*
 * UniFi Inform protocol constants
 *
 * Binary packet layout (big-endian):
 *   [4]  Magic  "TNBU"
 *   [4]  Packet version = 0
 *   [6]  Device MAC
 *   [2]  Flags  (0x0001 = encrypted)
 *   [16] AES-CBC IV
 *   [4]  Data version = 1
 *   [4]  Payload length
 *   [N]  AES-128-CBC encrypted JSON payload
 */

#define INFORM_MAGIC        "TNBU"
#define INFORM_PKT_VERSION  0
#define INFORM_DATA_VERSION 1
#define INFORM_FLAG_ENCRYPTED 0x0001

/* Send one inform cycle.
 * Updates *st in place (adopted flag, auth key, inform_url, cfgversion).
 * Returns 0 on success, -1 on error (sets err_out[0..127]). */
int inform_send(openuf_state_t *st,
                const uf_model_t *model,
                long uptime,
                char *err_out);

#endif /* OPENUF_INFORM_H */
