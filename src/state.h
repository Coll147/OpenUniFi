#ifndef OPENUF_STATE_H
#define OPENUF_STATE_H

#include <stdbool.h>

typedef struct {
    bool  adopted;
    char  authkey[64];
    char  inform_url[256];
    char  cfgversion[32];
    char  mac[32];
    char  ip[64];
    char  hostname[64];
} openuf_state_t;

/* Load state from OPENUF_STATE_FILE.  Fills defaults if file missing. */
void state_load(openuf_state_t *st);

/* Persist state to OPENUF_STATE_FILE (creates /etc/openuf/ if needed). */
int  state_save(const openuf_state_t *st);

#endif /* OPENUF_STATE_H */
