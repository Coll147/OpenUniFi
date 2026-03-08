/*
 * openuf - http.c
 *
 * Tiny HTTP/1.0 POST over raw TCP.  Avoids libcurl dependency.
 * Handles chunked responses by reading until connection close.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "http.h"

#define RECV_CHUNK 4096

/* Parse "http://host:port/path" into components */
static int parse_url(const char *url,
                     char *host, size_t host_sz,
                     int  *port,
                     char *path, size_t path_sz)
{
    *port = 80;

    /* skip "http://" */
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    else if (strncmp(p, "https://", 8) == 0) {
        p += 8; *port = 443;
    }

    /* find end of host[:port] section */
    const char *slash = strchr(p, '/');
    size_t hp_len = slash ? (size_t)(slash - p) : strlen(p);

    /* split host and port */
    const char *colon = memchr(p, ':', hp_len);
    if (colon) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_sz) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        *port = atoi(colon + 1);
    } else {
        if (hp_len >= host_sz) return -1;
        memcpy(host, p, hp_len);
        host[hp_len] = '\0';
    }

    /* path */
    if (slash)
        snprintf(path, path_sz, "%s", slash);
    else
        snprintf(path, path_sz, "/");

    return 0;
}

int http_post(const char *url,
              const char *content_type,
              const unsigned char *body, size_t body_len,
              unsigned char **resp_out, size_t *resp_len)
{
    char host[128], path[256];
    int  port;

    *resp_out = NULL;
    *resp_len = 0;

    if (parse_url(url, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return -1;

    /* Resolve host */
    struct hostent *he = gethostbyname(host);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* 10-second connect timeout */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port),
    };
    memcpy(&sa.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd); return -1;
    }

    /* Build request */
    char hdr[512];
    int  hdr_len = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.0\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "User-Agent: AirControl Agent v1.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, port, content_type, body_len);

    if (write(fd, hdr, hdr_len) != hdr_len ||
        write(fd, body, body_len) != (ssize_t)body_len) {
        close(fd); return -1;
    }

    /* Read full response */
    size_t  total = 0, cap = RECV_CHUNK;
    unsigned char *buf = malloc(cap);
    if (!buf) { close(fd); return -1; }

    ssize_t n;
    while ((n = read(fd, buf + total, cap - total)) > 0) {
        total += n;
        if (total >= cap) {
            cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb) { free(buf); close(fd); return -1; }
            buf = nb;
        }
    }
    close(fd);

    if (total < 12) { free(buf); return -1; }

    /* Parse HTTP status line */
    int status = 0;
    sscanf((char *)buf, "HTTP/%*s %d", &status);

    /* Find body (after \r\n\r\n) */
    unsigned char *body_start = (unsigned char *)memmem(buf, total,
                                                         "\r\n\r\n", 4);
    if (!body_start) { free(buf); return status; }
    body_start += 4;

    size_t body_sz = total - (size_t)(body_start - buf);
    *resp_out = malloc(body_sz + 1);
    if (*resp_out) {
        memcpy(*resp_out, body_start, body_sz);
        (*resp_out)[body_sz] = '\0';
        *resp_len = body_sz;
    }
    free(buf);
    return status;
}
