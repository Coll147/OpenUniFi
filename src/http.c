/*
 * openuf - http.c — HTTP/1.0 POST sobre TCP raw, sin libcurl.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "http.h"
#include "debug.h"

#define DBG_TAG "http"
#define RECV_CHUNK 4096

static int parse_url(const char *url, char *host, size_t hsz, int *port, char *path, size_t psz) {
    *port = 80;
    const char *p = url;
    if      (strncmp(p,"http://",7)==0)  p+=7;
    else if (strncmp(p,"https://",8)==0) { p+=8; *port=443; }
    const char *slash=strchr(p,'/'); size_t hp=slash?(size_t)(slash-p):strlen(p);
    const char *colon=memchr(p,':',hp);
    if (colon) { size_t hl=(size_t)(colon-p); if(hl>=hsz)return -1; memcpy(host,p,hl); host[hl]='\0'; *port=atoi(colon+1); }
    else { if(hp>=hsz)return -1; memcpy(host,p,hp); host[hp]='\0'; }
    snprintf(path,psz,"%s",slash?slash:"/");
    LOG_TRACE("URL: host='%s' port=%d path='%s'", host, *port, path);
    return 0;
}

int http_post(const char *url, const char *ctype,
              const unsigned char *body, size_t blen,
              unsigned char **resp_out, size_t *resp_len) {
    char host[128], path[256]; int port;
    *resp_out=NULL; *resp_len=0;
    LOG_DBG("POST %s (%zu bytes)", url, blen);
    if (parse_url(url,host,sizeof(host),&port,path,sizeof(path))!=0) {
        LOG_ERR("URL inválida: '%s'", url); return -1;
    }
    LOG_DBG("resolviendo '%s'...", host);
    struct hostent *he = gethostbyname(host);
    if (!he) { LOG_ERR("gethostbyname('%s'): %s", host, hstrerror(h_errno)); return -1; }
    char resolved[INET_ADDRSTRLEN]={0};
    inet_ntop(AF_INET,he->h_addr_list[0],resolved,sizeof(resolved));
    LOG_DBG("'%s' → %s:%d", host, resolved, port);

    int fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) { LOG_ERR("socket(): %m"); return -1; }
    struct timeval tv={.tv_sec=10};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    struct sockaddr_in sa={.sin_family=AF_INET,.sin_port=htons((uint16_t)port)};
    memcpy(&sa.sin_addr,he->h_addr_list[0],he->h_length);
    if (connect(fd,(struct sockaddr*)&sa,sizeof(sa))!=0) {
        LOG_ERR("connect(%s:%d): %m", resolved, port); close(fd); return -1;
    }
    LOG_DBG("conectado a %s:%d (fd=%d)", resolved, port, fd);

    char hdr[512]; int hlen=snprintf(hdr,sizeof(hdr),
        "POST %s HTTP/1.0\r\nHost: %s:%d\r\nContent-Type: %s\r\n"
        "Content-Length: %zu\r\nUser-Agent: AirControl Agent v1.0\r\nConnection: close\r\n\r\n",
        path,host,port,ctype,blen);
    LOG_TRACE("cabeceras HTTP (%d bytes): %.*s", hlen, hlen-4, hdr);
    if (write(fd,hdr,hlen)!=hlen) { LOG_ERR("write(hdr): %m"); close(fd); return -1; }
    if (write(fd,body,blen)!=(ssize_t)blen) { LOG_ERR("write(body): %m"); close(fd); return -1; }
    LOG_DBG("request enviado: %d+%zu bytes", hlen, blen);

    size_t total=0, cap=RECV_CHUNK;
    unsigned char *buf=malloc(cap);
    if (!buf) { LOG_ERR("OOM"); close(fd); return -1; }
    ssize_t n;
    while ((n=read(fd,buf+total,cap-total))>0) {
        total+=n;
        LOG_TRACE("  read: %zd bytes (acum=%zu)", n, total);
        if (total>=cap) {
            cap*=2; unsigned char *nb=realloc(buf,cap);
            if (!nb) { LOG_ERR("OOM realloc(%zu)", cap); free(buf); close(fd); return -1; }
            buf=nb;
        }
    }
    if (n<0&&errno!=EAGAIN) LOG_WARN("read(): %m (leídos %zu)", total);
    close(fd);
    LOG_DBG("respuesta: %zu bytes totales", total);
    if (total<12) { LOG_ERR("respuesta demasiado corta (%zu)", total); free(buf); return -1; }

    int status=0; sscanf((char*)buf,"HTTP/%*s %d",&status);
    LOG_DBG("HTTP status: %d", status);
    unsigned char *bs=(unsigned char*)memmem(buf,total,"\r\n\r\n",4);
    if (!bs) { LOG_WARN("sin \\r\\n\\r\\n en respuesta"); free(buf); return status; }
    bs+=4; size_t bsz=total-(size_t)(bs-buf);
    LOG_DBG("body respuesta: %zu bytes", bsz);
    if (bsz>0) {
        DBG_HEX("body (primeros 64 bytes)", bs, bsz<64?bsz:64);
        *resp_out=malloc(bsz+1);
        if (*resp_out) { memcpy(*resp_out,bs,bsz); (*resp_out)[bsz]='\0'; *resp_len=bsz; }
    } else {
        LOG_DBG("respuesta sin body (noop implícito del controlador)");
    }
    free(buf); return status;
}
