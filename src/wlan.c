/*
 * openuf - wlan.c
 * Traduce config WiFi UniFi → UCI OpenWrt via libuci.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uci.h>
#include <json-c/json.h>
#include "wlan.h"
#include "ufmodel.h"
#define DBG_TAG "wlan"
#include "debug.h"

static const char *sec_to_uci(const char *uf)
{
    if (!uf||!strcmp(uf,"open"))            return "none";
    if (!strcmp(uf,"wpapsk"))               return "psk";
    if (!strcmp(uf,"wpa2psk"))              return "psk2";
    if (!strcmp(uf,"wpapskwpa2psk"))        return "psk-mixed";
    if (!strcmp(uf,"wpa3"))                 return "sae";
    if (!strcmp(uf,"wpa3transition"))       return "sae-mixed";
    if (!strcmp(uf,"wpa2enterprise"))       return "wpa2";
    if (!strcmp(uf,"wpa3enterprise"))       return "wpa3";
    return "psk2";
}

static const char *sec_to_unifi(const char *uci)
{
    if (!uci||!strcmp(uci,"none"))          return "open";
    if (!strcmp(uci,"psk"))                 return "wpapsk";
    if (!strcmp(uci,"psk2"))                return "wpa2psk";
    if (!strcmp(uci,"psk-mixed"))           return "wpapskwpa2psk";
    if (!strcmp(uci,"sae"))                 return "wpa3";
    if (!strcmp(uci,"sae-mixed"))           return "wpa3transition";
    if (!strcmp(uci,"wpa2"))                return "wpa2enterprise";
    if (!strcmp(uci,"wpa3"))                return "wpa3enterprise";
    return "wpa2psk";
}

static void safe_section_name(const char *ssid, char *out, size_t sz)
{
    size_t j=0;
    for(size_t i=0;ssid[i]&&j<sz-1&&j<15;i++){
        char c=ssid[i];
        if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-') out[j++]=c;
        else out[j++]='_';
    }
    out[j]='\0';
}

static int uci_set_val(struct uci_context *ctx, const char *path, const char *val)
{
    LOG_DBG("uci_set %s=%s", path, val);
    struct uci_ptr ptr;
    char *p=malloc(strlen(path)+strlen(val)+2);
    if (!p) return -1;
    sprintf(p,"%s=%s",path,val);
    int ret=uci_lookup_ptr(ctx,&ptr,p,true);
    free(p);
    if (ret!=UCI_OK) { LOG_DBG("uci_lookup_ptr FALLO para '%s'", path); return -1; }
    int r=(uci_set(ctx,&ptr)==UCI_OK)?0:-1;
    if (r!=0) LOG_DBG("uci_set FALLO para '%s'", path);
    return r;
}

#define UCI_SET(ctx,pkg,sec,opt,val) do { \
    char _p[256]; snprintf(_p,sizeof(_p),"%s.%s.%s",pkg,sec,opt); \
    uci_set_val(ctx,_p,val); \
} while(0)

#define UCI_SET_INT(ctx,pkg,sec,opt,ival) do { \
    char _v[32]; snprintf(_v,sizeof(_v),"%d",ival); \
    UCI_SET(ctx,pkg,sec,opt,_v); \
} while(0)

static int uci_ensure_section(struct uci_context *ctx, struct uci_package *pkg,
                               const char *sec_name, const char *sec_type)
{
    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s=uci_to_section(e);
        if (!strcmp(s->e.name,sec_name)&&!strcmp(s->type,sec_type)) {
            LOG_DBG("seccion '%s' ya existe", sec_name);
            return 0;
        }
    }
    LOG_DBG("creando nueva seccion '%s' tipo '%s'", sec_name, sec_type);
    struct uci_ptr ptr={0};
    ptr.package=(char*)pkg->e.name; ptr.section=(char*)sec_name;
    ptr.flags=UCI_LOOKUP_EXTENDED;
    if (uci_set(ctx,&ptr)!=UCI_OK) { LOG_DBG("uci_set seccion FALLO"); return -1; }
    char path[256]; snprintf(path,sizeof(path),"wireless.%s",sec_name);
    char *p=malloc(strlen(path)+strlen(sec_type)+2);
    if (!p) return -1;
    sprintf(p,"%s=%s",path,sec_type);
    struct uci_ptr tptr; uci_lookup_ptr(ctx,&tptr,p,true);
    free(p);
    return 0;
}

/* ─── wlan_clear ─────────────────────────────────────────────────── */
void wlan_clear(void)
{
    LOG_DBG("wlan_clear — borrando VAPs con prefijo openuf_");
    struct uci_context *ctx=uci_alloc_context();
    if (!ctx) { LOG_DBG("uci_alloc_context FALLO"); return; }

    struct uci_package *pkg=NULL;
    if (uci_load(ctx,"wireless",&pkg)!=UCI_OK) {
        LOG_DBG("uci_load wireless FALLO"); uci_free_context(ctx); return;
    }

    char *to_del[64]; int ndel=0;
    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s=uci_to_section(e);
        if (!strcmp(s->type,"wifi-iface")&&strncmp(s->e.name,"openuf_",7)==0&&ndel<64) {
            LOG_DBG("marcando para borrar: '%s'", s->e.name);
            to_del[ndel++]=strdup(s->e.name);
        }
    }
    LOG_DBG("%d secciones a borrar", ndel);

    for (int i=0;i<ndel;i++) {
        struct uci_ptr ptr; char path[128];
        snprintf(path,sizeof(path),"wireless.%s",to_del[i]);
        if (uci_lookup_ptr(ctx,&ptr,path,true)==UCI_OK) {
            uci_delete(ctx,&ptr);
            LOG_DBG("borrada seccion '%s'", to_del[i]);
        }
        free(to_del[i]);
    }

    if (ndel>0) {
        uci_commit(ctx,&pkg,false);
        LOG_DBG("commit UCI tras borrado de %d VAPs", ndel);
    }
    uci_unload(ctx,pkg); uci_free_context(ctx);
    printf("[openuf] wlan_clear: eliminadas %d VAPs\n",ndel);
}

/* ─── wlan_apply_radio ───────────────────────────────────────────── */
void wlan_apply_radio(struct json_object *radio_json, const char *device_name)
{
    LOG_DBG("apply_radio device=%s", device_name);

    struct uci_context *ctx=uci_alloc_context();
    if (!ctx) { LOG_DBG("apply_radio uci_alloc FALLO"); return; }
    struct uci_package *pkg=NULL;
    if (uci_load(ctx,"wireless",&pkg)!=UCI_OK) {
        LOG_DBG("apply_radio uci_load FALLO"); uci_free_context(ctx); return;
    }

    struct json_object *v;
    char path[256];

    if (json_object_object_get_ex(radio_json,"ht",&v)) {
        LOG_DBG("radio %s htmode=%s", device_name, json_object_get_string(v));
        snprintf(path,sizeof(path),"wireless.%s.htmode=%s",device_name,json_object_get_string(v));
        struct uci_ptr ptr; if (uci_lookup_ptr(ctx,&ptr,path,true)==UCI_OK) uci_set(ctx,&ptr);
    }

    if (json_object_object_get_ex(radio_json,"channel",&v)) {
        int ch=json_object_get_int(v);
        if (ch==0) snprintf(path,sizeof(path),"wireless.%s.channel=auto",device_name);
        else       snprintf(path,sizeof(path),"wireless.%s.channel=%d",device_name,ch);
        LOG_DBG("radio %s channel=%d (%s)", device_name, ch, ch==0?"auto":"fijo");
        struct uci_ptr ptr; if (uci_lookup_ptr(ctx,&ptr,path,true)==UCI_OK) uci_set(ctx,&ptr);
    }

    if (json_object_object_get_ex(radio_json,"tx_power",&v)) {
        int pwr=json_object_get_int(v);
        LOG_DBG("radio %s txpower=%d", device_name, pwr);
        snprintf(path,sizeof(path),"wireless.%s.txpower=%d",device_name,pwr);
        struct uci_ptr ptr; if (uci_lookup_ptr(ctx,&ptr,path,true)==UCI_OK) uci_set(ctx,&ptr);
    }

    snprintf(path,sizeof(path),"wireless.%s.disabled=0",device_name);
    LOG_DBG("habilitando radio %s", device_name);
    struct uci_ptr ptr; if (uci_lookup_ptr(ctx,&ptr,path,true)==UCI_OK) uci_set(ctx,&ptr);

    uci_commit(ctx,&pkg,false);
    LOG_DBG("apply_radio %s OK, commit realizado", device_name);
    uci_unload(ctx,pkg); uci_free_context(ctx);
}

/* ─── apply_vap (interno) ────────────────────────────────────────── */
static void apply_vap(struct uci_context *ctx, struct uci_package *pkg,
                      struct json_object *vap_json, const char *device_name,
                      const char *mac_str, int vap_idx)
{
    struct json_object *v;
    const char *essid="", *security="wpa2psk", *pass="";
    if (json_object_object_get_ex(vap_json,"essid",        &v)) essid    =json_object_get_string(v);
    if (json_object_object_get_ex(vap_json,"security",     &v)) security =json_object_get_string(v);
    if (json_object_object_get_ex(vap_json,"x_passphrase", &v)) pass     =json_object_get_string(v);

    char safe[16]={0};
    safe_section_name(essid,safe,sizeof(safe));
    char sec_name[48];
    snprintf(sec_name,sizeof(sec_name),"openuf_%d_%s",vap_idx,safe);

    LOG_DBG("apply_vap — essid='%s' sec='%s' device=%s security=%s",
         essid, sec_name, device_name, security);

    uci_ensure_section(ctx,pkg,sec_name,"wifi-iface");
    UCI_SET(ctx,"wireless",sec_name,"device",    device_name);
    UCI_SET(ctx,"wireless",sec_name,"mode",      "ap");
    UCI_SET(ctx,"wireless",sec_name,"ssid",      essid);
    UCI_SET(ctx,"wireless",sec_name,"network",   "lan");
    UCI_SET(ctx,"wireless",sec_name,"encryption",sec_to_uci(security));
    LOG_DBG("VAP '%s' encryption UniFi='%s' → UCI='%s'", essid, security, sec_to_uci(security));

    if (pass&&pass[0]&&strcmp(security,"open")!=0) {
        UCI_SET(ctx,"wireless",sec_name,"key",pass);
        LOG_DBG("VAP '%s' clave configurada (%.3s...)", essid, pass);
    }

    int hidden=0;
    if (json_object_object_get_ex(vap_json,"hide_ssid",&v)) hidden=json_object_get_boolean(v)?1:0;
    UCI_SET_INT(ctx,"wireless",sec_name,"hidden",hidden);
    LOG_DBG("VAP '%s' hidden=%d", essid, hidden);

    int isolate=0;
    if (json_object_object_get_ex(vap_json,"guest_policy",&v)) isolate=json_object_get_boolean(v)?1:0;
    UCI_SET_INT(ctx,"wireless",sec_name,"isolate",isolate);
    LOG_DBG("VAP '%s' isolate=%d (guest_policy)", essid, isolate);

    int uapsd=1;
    if (json_object_object_get_ex(vap_json,"uapsd",&v)) uapsd=json_object_get_boolean(v)?1:0;
    UCI_SET_INT(ctx,"wireless",sec_name,"uapsd",uapsd);
    LOG_DBG("VAP '%s' uapsd=%d", essid, uapsd);

    /* PMF */
    int pmf=0;
    if (json_object_object_get_ex(vap_json,"pmf_mode",&v)) {
        const char *pm=json_object_get_string(v);
        if (!strcmp(pm,"optional")) pmf=1;
        if (!strcmp(pm,"required")) pmf=2;
    }
    if (!strcmp(security,"wpa3")||!strcmp(security,"wpa3transition")||!strcmp(security,"wpa3enterprise")) pmf=2;
    UCI_SET_INT(ctx,"wireless",sec_name,"ieee80211w",pmf);
    LOG_DBG("VAP '%s' ieee80211w=%d (PMF)", essid, pmf);

    /* 802.11r Fast Roaming */
    int ft=0;
    if (json_object_object_get_ex(vap_json,"fast_roaming_enabled",&v)) ft=json_object_get_boolean(v)?1:0;
    if (ft) {
        UCI_SET_INT(ctx,"wireless",sec_name,"ieee80211r",           1);
        UCI_SET_INT(ctx,"wireless",sec_name,"ft_over_ds",           1);
        UCI_SET_INT(ctx,"wireless",sec_name,"ft_psk_generate_local",1);
        char mdomain[8]={0};
        if (mac_str&&strlen(mac_str)>=5) {
            char b0[3]={mac_str[0],mac_str[1],0},b1[3]={mac_str[3],mac_str[4],0};
            unsigned int v0=0,v1=0; sscanf(b0,"%x",&v0); sscanf(b1,"%x",&v1);
            snprintf(mdomain,sizeof(mdomain),"%02x%02x",v0,v1);
        } else { strcpy(mdomain,"1234"); }
        UCI_SET(ctx,"wireless",sec_name,"mobility_domain",mdomain);
        LOG_DBG("VAP '%s' 802.11r ACTIVADO mobility_domain=%s", essid, mdomain);
    } else {
        UCI_SET_INT(ctx,"wireless",sec_name,"ieee80211r",0);
        LOG_DBG("VAP '%s' 802.11r desactivado", essid);
    }

    /* 802.11k/v Band Steering */
    int bs=0;
    if (json_object_object_get_ex(vap_json,"band_steering",&v)) bs=json_object_get_boolean(v)?1:0;
    if (bs) {
        UCI_SET_INT(ctx,"wireless",sec_name,"ieee80211k",          1);
        UCI_SET_INT(ctx,"wireless",sec_name,"ieee80211v",          1);
        UCI_SET_INT(ctx,"wireless",sec_name,"rrm_neighbor_report", 1);
        UCI_SET_INT(ctx,"wireless",sec_name,"bss_transition",      1);
        LOG_DBG("VAP '%s' band steering (802.11k/v) ACTIVADO", essid);
    } else {
        UCI_SET_INT(ctx,"wireless",sec_name,"ieee80211k",0);
        UCI_SET_INT(ctx,"wireless",sec_name,"ieee80211v",0);
        LOG_DBG("VAP '%s' band steering desactivado", essid);
    }

    /* VLAN */
    if (json_object_object_get_ex(vap_json,"vlan_id",&v)) {
        int vid=json_object_get_int(v);
        if (vid>0) {
            UCI_SET_INT(ctx,"wireless",sec_name,"vlan_id",vid);
            char vlan_net[32]; snprintf(vlan_net,sizeof(vlan_net),"vlan%d",vid);
            UCI_SET(ctx,"wireless",sec_name,"network",vlan_net);
            LOG_DBG("VAP '%s' VLAN id=%d network=%s", essid, vid, vlan_net);
        }
    }

    LOG_DBG("apply_vap '%s' COMPLETADO — enc=%s ft=%d bs=%d pmf=%d",
         essid, sec_to_uci(security), ft, bs, pmf);
    printf("[openuf] VAP '%s' → %s enc=%s ft=%d bs=%d pmf=%d\n",
           essid,sec_name,sec_to_uci(security),ft,bs,pmf);
}

/* ─── wlan_apply_config ──────────────────────────────────────────── */
void wlan_apply_config(struct json_object *config_json, const uf_model_t *model)
{
    LOG_DBG("wlan_apply_config inicio");

    struct json_object *rt_arr=NULL, *vt_arr=NULL, *v;
    json_object_object_get_ex(config_json,"radio_table",&rt_arr);
    json_object_object_get_ex(config_json,"vap_table",&vt_arr);

    if (rt_arr) LOG_DBG("radio_table recibido (%d entradas)", json_object_array_length(rt_arr));
    else        LOG_DBG("sin radio_table en setstate");
    if (vt_arr) LOG_DBG("vap_table recibido (%d entradas)", json_object_array_length(vt_arr));
    else        LOG_DBG("sin vap_table en setstate");

    /* MAC para mobility_domain */
    char mac_str[32]="00:00:00:00:00:00";
    { FILE *f=fopen("/sys/class/net/eth0/address","r");
      if (f) { fgets(mac_str,sizeof(mac_str),f); fclose(f); mac_str[strcspn(mac_str,"\r\n")]='\0'; }
      LOG_DBG("MAC del AP para mobility_domain: %s", mac_str); }

    wlan_clear();

    struct uci_context *ctx=uci_alloc_context();
    if (!ctx) { LOG_DBG("uci_alloc FALLO"); return; }
    struct uci_package *pkg=NULL;
    if (uci_load(ctx,"wireless",&pkg)!=UCI_OK) {
        LOG_DBG("uci_load FALLO"); uci_free_context(ctx); return;
    }
    LOG_DBG("UCI wireless cargado");

    /* Aplicar radios */
    if (rt_arr&&json_object_is_type(rt_arr,json_type_array)) {
        int nr=json_object_array_length(rt_arr);
        LOG_DBG("aplicando %d radios", nr);
        for (int i=0;i<nr;i++) {
            struct json_object *r=json_object_array_get_idx(rt_arr,i);
            if (!r) continue;
            const char *radio_band="";
            if (json_object_object_get_ex(r,"radio",&v)) radio_band=json_object_get_string(v);
            const char *device_name="radio0";
            for (int j=0;j<model->radio_map_len;j++) {
                if (!strcmp(model->radio_map[j].band,radio_band)) {
                    device_name=model->radio_map[j].device; break;
                }
            }
            LOG_DBG("radio[%d] band=%s → device=%s", i, radio_band, device_name);
            wlan_apply_radio(r,device_name);
        }
    }

    /* Crear VAPs */
    if (vt_arr&&json_object_is_type(vt_arr,json_type_array)) {
        int nv=json_object_array_length(vt_arr);
        LOG_DBG("creando %d VAPs", nv);
        for (int i=0;i<nv;i++) {
            struct json_object *vap=json_object_array_get_idx(vt_arr,i);
            if (!vap) continue;
            const char *radio_band="ng";
            if (json_object_object_get_ex(vap,"radio",&v)) radio_band=json_object_get_string(v);
            const char *device_name="radio0";
            for (int j=0;j<model->radio_map_len;j++) {
                if (!strcmp(model->radio_map[j].band,radio_band)) {
                    device_name=model->radio_map[j].device; break;
                }
            }
            LOG_DBG("vap[%d] band=%s → device=%s", i, radio_band, device_name);
            apply_vap(ctx,pkg,vap,device_name,mac_str,i);
        }
    }

    uci_commit(ctx,&pkg,false);
    LOG_DBG("commit UCI realizado");
    uci_unload(ctx,pkg); uci_free_context(ctx);

    LOG_DBG("ejecutando 'wifi reload'...");
    printf("[openuf] Ejecutando wifi reload...\n");
    system("wifi reload 2>/dev/null &");
    LOG_DBG("wlan_apply_config COMPLETADO");
}

/* ─── wlan_get_vap_table ─────────────────────────────────────────── */
struct json_object *wlan_get_vap_table(const uf_model_t *model)
{
    LOG_DBG("leyendo vap_table desde UCI");
    struct json_object *arr=json_object_new_array();

    struct uci_context *ctx=uci_alloc_context();
    if (!ctx) { LOG_DBG("get_vap_table uci_alloc FALLO"); return arr; }
    struct uci_package *pkg=NULL;
    if (uci_load(ctx,"wireless",&pkg)!=UCI_OK) {
        LOG_DBG("get_vap_table uci_load FALLO"); uci_free_context(ctx); return arr;
    }

    int count=0;
    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec=uci_to_section(e);
        if (strcmp(sec->type,"wifi-iface")!=0) continue;
        if (strncmp(sec->e.name,"openuf_",7)!=0) continue;

        LOG_DBG("encontrada VAP UCI: '%s'", sec->e.name);

#define UCI_GET(opt) uci_lookup_option_string(ctx,sec,opt)
        const char *ssid   =UCI_GET("ssid");
        const char *device =UCI_GET("device");
        const char *enc    =UCI_GET("encryption");
        const char *dis    =UCI_GET("disabled");
        const char *r11    =UCI_GET("ieee80211r");
        const char *k11    =UCI_GET("ieee80211k");
        const char *w11    =UCI_GET("ieee80211w");
        const char *hidden =UCI_GET("hidden");

        if (!ssid)   ssid   ="";
        if (!device) device ="radio0";
        if (!enc)    enc    ="none";

        LOG_DBG("VAP '%s' — ssid='%s' device=%s enc=%s dis=%s r11=%s k11=%s w11=%s hidden=%s",
             sec->e.name, ssid, device, enc,
             dis?dis:"0", r11?r11:"0", k11?k11:"0", w11?w11:"0", hidden?hidden:"0");

        const char *radio_band="ng";
        for (int j=0;j<model->radio_map_len;j++) {
            if (!strcmp(model->radio_map[j].device,device)) {
                radio_band=model->radio_map[j].band; break;
            }
        }
        LOG_DBG("VAP '%s' band=%s", sec->e.name, radio_band);

        char wlan_iface[32]="wlan0";
        int ridx=0; sscanf(device,"radio%d",&ridx);
        snprintf(wlan_iface,sizeof(wlan_iface),"wlan%d",ridx);

        char bssid[32]="00:00:00:00:00:00";
        { char path[128]; snprintf(path,sizeof(path),"/sys/class/net/%s/address",wlan_iface);
          FILE *f=fopen(path,"r");
          if (f) { fgets(bssid,sizeof(bssid),f); fclose(f); bssid[strcspn(bssid,"\r\n")]='\0'; }
          LOG_DBG("VAP '%s' bssid=%s (desde %s)", sec->e.name, bssid, wlan_iface); }

        const char *pmf="disabled";
        if (w11) { if (!strcmp(w11,"1")) pmf="optional"; if (!strcmp(w11,"2")) pmf="required"; }
        bool ft_on =(r11&&!strcmp(r11,"1"));
        bool bs_on =(k11&&!strcmp(k11,"1"));
        bool hid   =(hidden&&!strcmp(hidden,"1"));
        bool up    =!(dis&&!strcmp(dis,"1"));

        LOG_DBG("VAP '%s' estado final — up=%d hidden=%d ft=%d bs=%d pmf=%s band=%s",
             sec->e.name, up, hid, ft_on, bs_on, pmf, radio_band);

        struct json_object *o=json_object_new_object();
        json_object_object_add(o,"essid",               json_object_new_string(ssid));
        json_object_object_add(o,"bssid",               json_object_new_string(bssid));
        json_object_object_add(o,"name",                json_object_new_string(sec->e.name));
        json_object_object_add(o,"radio",               json_object_new_string(radio_band));
        json_object_object_add(o,"security",            json_object_new_string(sec_to_unifi(enc)));
        json_object_object_add(o,"up",                  json_object_new_boolean(up));
        json_object_object_add(o,"hide_ssid",           json_object_new_boolean(hid));
        json_object_object_add(o,"fast_roaming_enabled",json_object_new_boolean(ft_on));
        json_object_object_add(o,"band_steering",       json_object_new_boolean(bs_on));
        json_object_object_add(o,"pmf_mode",            json_object_new_string(pmf));
        json_object_object_add(o,"num_sta",             json_object_new_int(0));
        json_object_array_add(arr,o);
        count++;
#undef UCI_GET
    }
    uci_unload(ctx,pkg); uci_free_context(ctx);
    LOG_DBG("get_vap_table completado — %d VAPs encontradas", count);
    return arr;
}
