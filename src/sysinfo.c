/* openuf - sysinfo.c  — /proc/stat, /proc/meminfo, /proc/net/dev, iw */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "sysinfo.h"
#include "debug.h"

#define DBG_TAG "sysinfo"

int sysinfo_mem(mem_stats_t *out) {
    memset(out,0,sizeof(*out));
    LOG_TRACE("leyendo /proc/meminfo...");
    FILE *f=fopen("/proc/meminfo","r");
    if (!f) { LOG_ERR("no se pudo abrir /proc/meminfo"); return -1; }
    char line[128];
    while (fgets(line,sizeof(line),f)) {
        long v=0;
        if      (sscanf(line,"MemTotal: %ld kB",&v)==1) out->total_kb =v;
        else if (sscanf(line,"MemFree: %ld kB", &v)==1) out->free_kb  =v;
        else if (sscanf(line,"Buffers: %ld kB", &v)==1) out->buffer_kb=v;
        else if (sscanf(line,"Cached: %ld kB",  &v)==1) out->cached_kb=v;
    }
    fclose(f);
    if (out->total_kb<=0) { LOG_ERR("MemTotal no encontrado"); return -1; }
    long used=out->total_kb-out->free_kb-out->buffer_kb-out->cached_kb;
    LOG_DBG("RAM: total=%.0fMB libre=%.0fMB usado=%.0fMB (%.0f%%)",
            out->total_kb/1024.0, out->free_kb/1024.0, used/1024.0,
            used*100.0/out->total_kb);
    return 0;
}

typedef struct { unsigned long long user,nice,sys,idle,iowait,irq,softirq,steal; } cpu_snap_t;
static cpu_snap_t g_prev={0}; static int g_valid=0;

static int read_cpu(cpu_snap_t *s) {
    FILE *f=fopen("/proc/stat","r");
    if (!f) { LOG_ERR("no se pudo abrir /proc/stat"); return -1; }
    int r=fscanf(f,"cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                 &s->user,&s->nice,&s->sys,&s->idle,&s->iowait,&s->irq,&s->softirq,&s->steal);
    fclose(f);
    if (r<4) { LOG_ERR("/proc/stat: formato inesperado"); return -1; }
    return 0;
}

int sysinfo_cpu_percent(void) {
    cpu_snap_t cur; if (read_cpu(&cur)!=0) return 0;
    if (!g_valid) { g_prev=cur; g_valid=1; LOG_TRACE("CPU: snapshot inicial tomada"); return 0; }
    unsigned long long da=(cur.user-g_prev.user)+(cur.nice-g_prev.nice)+(cur.sys-g_prev.sys)
                         +(cur.irq-g_prev.irq)+(cur.softirq-g_prev.softirq)+(cur.steal-g_prev.steal);
    unsigned long long di=(cur.idle-g_prev.idle)+(cur.iowait-g_prev.iowait);
    unsigned long long dt=da+di;
    g_prev=cur;
    int pct=(dt==0)?0:(int)((da*100)/dt);
    LOG_DBG("CPU: Δactivo=%llu Δtotal=%llu uso=%d%%", da, dt, pct);
    return pct;
}

static int sysfs_str(const char *iface, const char *file, char *out, size_t sz) {
    char path[128]; snprintf(path,sizeof(path),"/sys/class/net/%s/%s",iface,file);
    FILE *f=fopen(path,"r"); if(!f){LOG_TRACE("/sys/%s/%s: no existe",iface,file);return -1;}
    char buf[64]={0}; fgets(buf,sizeof(buf),f); fclose(f);
    buf[strcspn(buf,"\r\n")]='\0'; strncpy(out,buf,sz-1);
    return strlen(out)>0?0:-1;
}
static int sysfs_int(const char *iface, const char *file) {
    char buf[32]={0}; if(sysfs_str(iface,file,buf,sizeof(buf))!=0)return -1;
    int v=-1; sscanf(buf,"%d",&v); return v;
}
static void ip_ioctl(const char *iface, char *out, size_t sz) {
    int fd=socket(AF_INET,SOCK_DGRAM,0); if(fd<0)return;
    struct ifreq ifr; memset(&ifr,0,sizeof(ifr)); strncpy(ifr.ifr_name,iface,IFNAMSIZ-1);
    if (ioctl(fd,SIOCGIFADDR,&ifr)==0) {
        struct sockaddr_in *sa=(struct sockaddr_in*)&ifr.ifr_addr;
        strncpy(out,inet_ntoa(sa->sin_addr),sz-1);
        LOG_TRACE("%s IP(ioctl)=%s", iface, out);
    }
    close(fd);
}

int sysinfo_iface(const char *ifname, iface_stats_t *out) {
    memset(out,0,sizeof(*out)); strncpy(out->name,ifname,sizeof(out->name)-1);
    sysfs_str(ifname,"address",  out->mac,sizeof(out->mac));
    char ops[32]={0}; sysfs_str(ifname,"operstate",ops,sizeof(ops));
    out->up=(strcmp(ops,"up")==0||strcmp(ops,"unknown")==0);
    int sp=sysfs_int(ifname,"speed"); out->speed=(sp>0)?sp:1000;
    char dup[16]={0}; sysfs_str(ifname,"duplex",dup,sizeof(dup));
    out->full_duplex=(strncmp(dup,"full",4)==0);
    ip_ioctl(ifname,out->ip,sizeof(out->ip));

    FILE *f=fopen("/proc/net/dev","r"); if(!f){LOG_WARN("no se pudo abrir /proc/net/dev");return 0;}
    char line[512]; fgets(line,sizeof(line),f); fgets(line,sizeof(line),f);
    int found=0;
    while (fgets(line,sizeof(line),f)) {
        char *colon=strchr(line,':'); if(!colon)continue;
        size_t end=colon-line; while(end>0&&line[end-1]==' ')end--;
        size_t start=0; while(start<end&&line[start]==' ')start++;
        char name[32]={0}; size_t nlen=end-start; if(nlen>=sizeof(name))continue;
        strncpy(name,line+start,nlen); if(strcmp(name,ifname)!=0)continue;
        long long rb,rp,re,rd,rf,rframe,rcomp,rmulti,tb,tp,te,td,tf,tcol,tcomp,tcarr;
        sscanf(colon+1,"%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
               &rb,&rp,&re,&rd,&rf,&rframe,&rcomp,&rmulti,&tb,&tp,&te,&td,&tf,&tcol,&tcomp,&tcarr);
        out->rx_bytes=rb;out->rx_packets=rp;out->rx_errors=re;out->rx_dropped=rd;out->rx_multicast=rmulti;
        out->tx_bytes=tb;out->tx_packets=tp;out->tx_errors=te;out->tx_dropped=td;
        found=1; break;
    }
    fclose(f);
    if (!found) LOG_TRACE("%s: no en /proc/net/dev (normal para ifaces virtuales)", ifname);
    LOG_DBG("iface %-8s up=%-3s speed=%4dMbps dup=%-5s rx=%lldB/%lluP tx=%lldB/%lluP err=%lld/%lld",
            ifname,out->up?"sí":"no",out->speed,out->full_duplex?"full":"half",
            out->rx_bytes,out->rx_packets,out->tx_bytes,out->tx_packets,out->rx_errors,out->tx_errors);
    return 0;
}

int sysinfo_radio(const char *iface, radio_stats_t *out) {
    memset(out,0,sizeof(*out)); strncpy(out->iface,iface,sizeof(out->iface)-1); out->noise=-95;
    LOG_TRACE("leyendo radio %s...", iface);
    char cmd[128];

    snprintf(cmd,sizeof(cmd),"iw dev %s info 2>/dev/null",iface);
    FILE *p=popen(cmd,"r"); if(!p){LOG_WARN("popen('%s') falló",cmd);return -1;}
    char line[256];
    while (fgets(line,sizeof(line),p)) {
        int ch; float mhz;
        if (sscanf(line," channel %d (%f MHz)",&ch,&mhz)==2) {
            out->channel=ch; LOG_TRACE("  %s: canal=%d (%.0fMHz)",iface,ch,mhz); }
        float tp; if (sscanf(line," txpower %f dBm",&tp)==1) {
            out->tx_power=(int)tp; LOG_TRACE("  %s: txpower=%.1fdBm",iface,tp); }
    }
    pclose(p);

    snprintf(cmd,sizeof(cmd),"iw dev %s survey dump 2>/dev/null",iface);
    p=popen(cmd,"r"); if(!p) return 0;
    long long active=0,busy=0,tx_t=0,rx_t=0; int in_use=0;
    while (fgets(line,sizeof(line),p)) {
        if (strstr(line,"[in use]")) { in_use=1;active=busy=tx_t=rx_t=0;continue; }
        if (!in_use) continue;
        if (strstr(line,"frequency:")&&!strstr(line,"[in use]")){in_use=0;continue;}
        float noise; long long v;
        if (sscanf(line," noise: %f dBm",&noise)==1) out->noise=(int)noise;
        if (sscanf(line," channel active time: %lld ms",&v)==1)   active=v;
        if (sscanf(line," channel busy time: %lld ms",&v)==1)     busy=v;
        if (sscanf(line," channel transmit time: %lld ms",&v)==1) tx_t=v;
        if (sscanf(line," channel receive time: %lld ms",&v)==1)  rx_t=v;
    }
    pclose(p);
    if (active>0) {
        out->cu_total  =(int)(busy*100/active);
        out->cu_self_tx=(int)(tx_t*100/active);
        out->cu_self_rx=(int)(rx_t*100/active);
    } else LOG_TRACE("%s: survey sin [in use] (driver sin soporte)", iface);

    snprintf(cmd,sizeof(cmd),"iw dev %s station dump 2>/dev/null|grep -c '^Station'",iface);
    p=popen(cmd,"r"); if(p){fscanf(p,"%d",&out->num_sta);pclose(p);}

    LOG_DBG("radio %-8s ch=%-3d pwr=%ddBm CU=%d%%(tx=%d%%/rx=%d%%) noise=%ddBm sta=%d",
            iface,out->channel,out->tx_power,out->cu_total,out->cu_self_tx,out->cu_self_rx,
            out->noise,out->num_sta);
    return 0;
}
