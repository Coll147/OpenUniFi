#ifndef OPENUF_HTTP_H
#define OPENUF_HTTP_H

#include <stddef.h>

/*
 * Minimal HTTP/1.0 POST client (raw TCP sockets, no libcurl).
 *
 * Posts 'body' of 'body_len' bytes to the given URL.
 * Allocates *resp_out (caller must free) and sets *resp_len.
 * Returns HTTP status code (200, etc.) or -1 on error.
 */
int http_post(const char *url,
              const char *content_type,
              const unsigned char *body, size_t body_len,
              unsigned char **resp_out, size_t *resp_len);

#endif /* OPENUF_HTTP_H */
