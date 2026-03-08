/*
 * openuf - http.c
 * HTTP POST client sobre POSIX TCP raw (sin libcurl).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "http.h"
#include "debug.h"

/* Parsea "http://host:port/path" */
static int parse_url(const char *url,
                     char *host, int host_sz,
                     int  *port,
                     char *path, int path_sz)
{
    DLOG("http: parseando URL '%s'", url);
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    if (colon && (!slash || colon < slash)) {
        int hlen = (int)(colon - p);
        if (hlen >= host_sz) hlen = host_sz-1;
        strncpy(host, p, hlen); host[hlen] = '\0';
        *port = atoi(colon+1);
    } else {
        int hlen = slash ? (int)(slash-p) : (int)strlen(p);
        if (hlen >= host_sz) hlen = host_sz-1;
        strncpy(host, p, hlen); host[hlen] = '\0';
        *port = 8080;
    }

    if (slash) strncpy(path, slash, path_sz-1);
    else       strncpy(path, "/",   path_sz-1);

    DLOG("http: URL parseada — host=%s port=%d path=%s", host, *port, path);
    return 0;
}

int http_post(const char *url,
              const char *content_type,
              const unsigned char *body, size_t body_len,
              unsigned char **resp_out, size_t *resp_len_out)
{
    char host[256]={0}, path[256]={0};
    int  port = 8080;

    if (parse_url(url, host, sizeof(host), &port, path, sizeof(path)) != 0) {
        DLOG("http: parse_url FALLO");
        return -1;
    }

    DLOG("http: POST %s:%d%s body=%zu bytes ct=%s", host, port, path, body_len, content_type);

    /* Resolver host */
    DLOG("http: resolviendo hostname '%s'", host);
    struct addrinfo hints = {0};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%d", port);
    struct addrinfo *res;
    if (getaddrinfo(host, port_s, &hints, &res) != 0) {
        DLOG("http: getaddrinfo FALLO para '%s'", host);
        return -1;
    }

    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    DLOG("http: IP resuelta: %s", inet_ntoa(sa->sin_addr));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { DLOG("http: socket() FALLO errno=%d", errno); freeaddrinfo(res); return -1; }

    /* Timeout de 10s en connect y recv */
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    DLOG("http: conectando a %s:%d ...", host, port);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        DLOG("http: connect FALLO errno=%d (%s)", errno, strerror(errno));
        freeaddrinfo(res); close(fd); return -1;
    }
    freeaddrinfo(res);
    DLOG("http: conexion establecida");

    /* Construir peticion HTTP/1.1 */
    char headers[512];
    int hlen = snprintf(headers, sizeof(headers),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, content_type, body_len);
    DLOG("http: cabeceras (%d bytes):\n%s", hlen, headers);

    /* Enviar cabeceras + body */
    if (write(fd, headers, hlen) != hlen) {
        DLOG("http: write cabeceras FALLO");
        close(fd); return -1;
    }
    DLOG("http: cabeceras enviadas, enviando body (%zu bytes)...", body_len);
    DLOG_HEX("http body (primeros bytes)", body, body_len < 32 ? (int)body_len : 32);

    size_t sent = 0;
    while (sent < body_len) {
        ssize_t n = write(fd, body + sent, body_len - sent);
        if (n <= 0) { DLOG("http: write body FALLO en offset %zu errno=%d", sent, errno); close(fd); return -1; }
        sent += n;
        DLOG("http: enviados %zu/%zu bytes", sent, body_len);
    }
    DLOG("http: body enviado completamente (%zu bytes)", sent);

    /* Leer respuesta */
    size_t  rbuf_sz  = 8192;
    size_t  rbuf_len = 0;
    unsigned char *rbuf = malloc(rbuf_sz);
    if (!rbuf) { DLOG("http: OOM al leer respuesta"); close(fd); return -1; }

    DLOG("http: leyendo respuesta...");
    ssize_t n;
    while ((n = read(fd, rbuf + rbuf_len, rbuf_sz - rbuf_len - 1)) > 0) {
        rbuf_len += n;
        DLOG("http: leidos %zd bytes (total=%zu)", n, rbuf_len);
        if (rbuf_len >= rbuf_sz - 1) {
            rbuf_sz *= 2;
            unsigned char *tmp = realloc(rbuf, rbuf_sz);
            if (!tmp) { DLOG("http: realloc FALLO"); break; }
            rbuf = tmp;
        }
    }
    close(fd);
    DLOG("http: respuesta completa — total=%zu bytes", rbuf_len);

    if (rbuf_len == 0) { free(rbuf); DLOG("http: respuesta vacia"); return -1; }
    rbuf[rbuf_len] = '\0';

    /* Parsear status line: "HTTP/1.x NNN ..." */
    int status = 0;
    sscanf((char*)rbuf, "HTTP/%*s %d", &status);
    DLOG("http: status HTTP = %d", status);

    /* Localizar cuerpo tras \r\n\r\n */
    unsigned char *body_start = (unsigned char*)strstr((char*)rbuf, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        size_t blen = rbuf_len - (size_t)(body_start - rbuf);
        DLOG("http: cuerpo de respuesta = %zu bytes", blen);
        DLOG_HEX("http resp body (primeros bytes)", body_start, blen < 32 ? (int)blen : 32);
        unsigned char *copy = malloc(blen + 1);
        if (copy) {
            memcpy(copy, body_start, blen);
            copy[blen] = '\0';
            *resp_out     = copy;
            *resp_len_out = blen;
        }
    } else {
        DLOG("http: no se encontro separador cabecera/cuerpo");
    }

    free(rbuf);
    return status;
}
