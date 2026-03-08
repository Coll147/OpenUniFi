# UniFi Protocol — Documentación Técnica Completa

## 1. Descubrimiento L2 (Discovery)

El controlador busca dispositivos mediante paquetes UDP en capa 2.
El AP envía broadcasts periódicos a **dos** destinos:

| Destino        | Dirección          | Puerto |
|----------------|--------------------|--------|
| Broadcast L2   | 255.255.255.255    | 10001  |
| Multicast L2   | 233.89.188.1       | 10001  |

### Formato del paquete de anuncio (TLV)

```
[0x02][0x06][0x00][total_len]   ← header fijo (4 bytes)
[type:1][len_hi:1][len_lo:1][value:len]  ← TLV (repite N veces)
```

Los tipos TLV conocidos:

| Tipo  | Nombre            | Contenido                          |
|-------|-------------------|------------------------------------|
| 0x01  | HW_ADDR           | MAC (6 bytes)                      |
| 0x02  | IP_ADDR           | MAC(6) + IP(4) = 10 bytes          |
| 0x03  | FWVER_VERBOSE     | String versión larga               |
| 0x0a  | UPTIME            | uint32 BE (segundos)               |
| 0x0b  | HOSTNAME          | String nombre del dispositivo      |
| 0x0c  | PLATFORM          | String plataforma (ej. "U6IW")     |
| 0x12  | INC_COUNTER       | uint32 BE (contador incremental)   |
| 0x13  | HW_ADDR2          | MAC (6 bytes) – segunda MAC        |
| 0x15  | PLATFORM2         | String plataforma (repetido)       |
| 0x16  | FWVER_SHORT       | String versión corta               |
| 0x1b  | FWVER_FACTORY     | String versión factory             |
| 0x17–0x1a | BLOB        | 4 bytes fijos de capacidades       |

**Implementación en código:** `announce.c` → `announce_init()` construye el paquete
estático una sola vez. `announce_send()` sólo actualiza los 8 bytes variables
(contador e uptime) con `memcpy` antes de cada envío.

---

## 2. Protocolo Inform (HTTP Binary)

### 2.1 Formato del paquete TNBU

```
Offset  Tamaño  Campo
------  ------  -----
0       4       Magic "TNBU"
4       4       Versión paquete (=0), uint32 BE
8       6       MAC del dispositivo
14      2       Flags: bit0=encrypted, bit1=zlib-compressed
16      16      IV AES (cuando cifrado)
32      4       Versión de datos (=1), uint32 BE
36      4       Longitud del payload cifrado, uint32 BE
40      N       Payload (JSON cifrado con AES-128-CBC)
```

**Clave de cifrado (x_authkey):**
- Antes de adopción: `ba86f2bbe107c7c57eb5f2690775c712` (MD5 de "ubnt")
- Tras adopción: clave aleatoria de 32 hex chars enviada por el controlador en `set-adopt`
- La clave se guarda en `/etc/openuf/state.json`

**Implementación:** `crypto.c` usa mbedTLS directamente. El IV se genera aleatoriamente
con `mbedtls_ctr_drbg_random()` en cada envío. No hay archivos temporales.

### 2.2 Payload JSON completo del AP → Controlador

```json
{
  /* Identidad */
  "mac":           "aa:bb:cc:dd:ee:ff",
  "serial":        "AABBCCDDEEFF",
  "model":         "U6IW",
  "model_display": "U6 IW",
  "hostname":      "U6-IW",
  "version":       "U6IW.mt7622_5_4.v6.6.55.14430",
  "ip":            "192.168.1.5",
  "uptime":        3600,
  "state":         4,            /* 1=default/unadopted, 4=connected */
  "default":       false,
  "cfgversion":    "abc123",

  /* Sistema */
  "sys_stats": {
    "mem_total":   262144000,    /* bytes totales RAM */
    "mem_used":    45678912,     /* bytes RAM usada */
    "mem_buffer":  12345678,     /* bytes en buffers */
    "cpu":         12            /* uso CPU en % (media 5s) */
  },

  /* Interfaces de red */
  "if_table": [
    {
      "name":        "eth0",
      "mac":         "aa:bb:cc:dd:ee:ff",
      "ip":          "192.168.1.5",
      "up":          true,
      "speed":       1000,
      "full_duplex": true,
      "num_port":    1,
      "rx_bytes":    123456789,
      "tx_bytes":    98765432,
      "rx_packets":  100000,
      "tx_packets":  90000,
      "rx_errors":   0,
      "tx_errors":   0,
      "rx_dropped":  0,
      "tx_dropped":  0
    }
  ],

  /* Radios (estadísticas en tiempo real) */
  "radio_table_stats": [
    {
      "name":       "wifi0",
      "channel":    6,
      "cu_self_tx": 5,     /* % tiempo transmitiendo */
      "cu_self_rx": 3,     /* % tiempo recibiendo */
      "cu_total":   8,     /* % uso total canal */
      "num_sta":    3,
      "tx_power":   23
    }
  ],

  /* VAPs con clientes conectados */
  "vap_table": [
    {
      "essid":    "MiRed",
      "bssid":    "aa:bb:cc:dd:ee:01",
      "radio":    "ng",
      "name":     "ath0",
      "up":       true,
      "channel":  6,
      "tx_power": 23,
      "num_sta":  2,
      "rx_bytes": 1234567,
      "tx_bytes": 9876543,
      "sta_table": [
        {
          "mac":      "11:22:33:44:55:66",
          "ip":       "192.168.1.100",
          "hostname": "mi-movil",
          "signal":   -62,          /* RSSI en dBm */
          "rssi":     48,           /* SNR estimado */
          "noise":    -95,
          "tx_rate":  144000,       /* kbps */
          "rx_rate":  108000,
          "tx_bytes": 5000000,
          "rx_bytes": 2000000,
          "tx_packets": 5000,
          "rx_packets": 2000,
          "uptime":   1800,         /* segundos conectado */
          "radio":    "ng",
          "channel":  6,
          "vap_name": "ath0",
          "is_11r":   false,
          "ccq":      900           /* Client Connection Quality 0-1000 */
        }
      ]
    }
  ],

  /* Topología LLDP */
  "lldp_table": [
    {
      "local_port":   "eth0",
      "chassis_id":   "aa:bb:cc:dd:ee:ff",
      "port_id":      "GigabitEthernet1/0/3",
      "sys_name":     "switch-piso1",
      "sys_desc":     "Cisco Catalyst 2960",
      "port_desc":    "Connection to AP",
      "port_table":   []
    }
  ]
}
```

### 2.3 Comandos del Controlador → AP (respuesta inform)

| `_type`    | Descripción                                    |
|------------|------------------------------------------------|
| `noop`     | No hacer nada                                  |
| `setstate` | Aplicar config: radio_table + vap_table         |
| `cmd`      | Comando: `set-adopt`, `reboot`, `reset`        |
| `setparam` | Cambiar un parámetro: `inform_url`, `authkey`  |

**Flujo de adopción:**
```
AP envía inform (key=DEFAULT_KEY, default=true)
    → Controller responde: {_type:"cmd", cmd:"set-adopt", key:"nueva_clave", uri:"http://..."}
AP guarda nueva clave, adopted=true
AP reenvía inform (key=NUEVA_CLAVE, state=4)
    → Controller responde: {_type:"setstate", radio_table:[...], vap_table:[...]}
AP aplica configuración WiFi via UCI
```

---

## 3. Configuración WiFi (setstate)

El controlador envía `radio_table` y `vap_table` en la respuesta `setstate`.

### 3.1 Campos de radio_table (controlador → AP)

```json
{
  "radio":     "ng",     /* "ng"=2.4GHz "na"=5GHz "6g"=6GHz */
  "channel":   6,        /* 0=auto */
  "tx_power":  20,       /* dBm */
  "ht":        "HT40",   /* ancho de banda */
  "min_rssi":  -80,      /* RSSI mínimo para expulsar cliente */
  "min_rssi_enabled": true,
  "band_steering_mode": "prefer_5g"
}
```

**UCI aplicado por wlan.c:**
```
wireless.<device>.channel   = 6
wireless.<device>.txpower   = 20
wireless.<device>.htmode    = HT40
wireless.<device>.disabled  = 0
```

### 3.2 Campos de vap_table (controlador → AP)

```json
{
  "essid":              "MiRed",
  "radio":              "ng",
  "security":           "wpa2psk",   /* ver tabla de mapeo */
  "x_passphrase":       "contraseña",
  "hide_ssid":          false,
  "guest_policy":       false,       /* aislamiento de clientes */
  "fast_roaming_enabled": true,      /* 802.11r */
  "band_steering":      true,        /* 802.11k/v */
  "uapsd":              true,        /* U-APSD ahorro energía */
  "wpa3_support":       false,
  "pmf_mode":           "disabled",  /* Protected Management Frames */
  "vlan_id":            0            /* 0=no VLAN */
}
```

**Mapeo seguridad UniFi → OpenWrt:**
| UniFi            | OpenWrt     |
|------------------|-------------|
| open             | none        |
| wpapsk           | psk         |
| wpa2psk          | psk2        |
| wpapskwpa2psk    | psk-mixed   |
| wpa3             | sae         |
| wpa3transition   | sae-mixed   |
| wpa2enterprise   | wpa2        |

---

## 4. Clientes Conectados (sta_table)

### 4.1 WiFi — leer desde hostapd / iw

```bash
# Por VAP:
iw dev wlan0 station dump
```

Cada cliente retorna:
```
Station aa:bb:cc:dd:ee:ff (on wlan0)
    signal:             -62 dBm
    tx bitrate:         144.4 MBit/s MCS 15
    rx bitrate:         108.0 MBit/s
    tx bytes:           5000000
    rx bytes:           2000000
    connected time:     1800 seconds
```

**Implementación:** `clients.c` → `clients_read_wifi()` parsea la salida de
`iw dev <iface> station dump` con popen()/fgets().

### 4.2 Ethernet — leer bridge FDB + ARP

```bash
# MACs en cada puerto del bridge:
bridge fdb show | grep "dev eth0"

# IPs asociadas:
cat /proc/net/arp
```

**Implementación:** `clients.c` → `clients_read_wired()` combina FDB + ARP.

---

## 5. Estadísticas de Sistema (sys_stats)

### 5.1 CPU — /proc/stat

```
cpu  user nice system idle iowait irq softirq steal
```

Uso = (user+nice+system+irq+softirq) / total × 100

Se mide dos veces con intervalo de 1s para obtener uso reciente (no acumulado).

**Implementación:** `sysinfo.c` → `sysinfo_cpu_percent()` — primer llamada
guarda la snapshot; la segunda calcula el delta.

### 5.2 RAM — /proc/meminfo

```
MemTotal:       262144 kB
MemFree:         45678 kB  
Buffers:         12345 kB
Cached:          23456 kB
```

**Implementación:** `sysinfo.c` → `sysinfo_mem()` — parseo línea a línea.

### 5.3 Interfaces — /proc/net/dev

```
  eth0: rx_bytes rx_packets rx_errs ... tx_bytes tx_packets ...
```

Velocidad del enlace: `/sys/class/net/<iface>/speed`
Duplex: `/sys/class/net/<iface>/duplex`
MAC: `/sys/class/net/<iface>/address`
Operstate: `/sys/class/net/<iface>/operstate`

**Implementación:** `sysinfo.c` → `sysinfo_iface()`.

---

## 6. LLDP — Topología Visual

UniFi construye el mapa de topología leyendo vecinos LLDP.
El AP debe:
1. **Enviar** frames LLDP propios (para que el switch lo vea)
2. **Leer** vecinos LLDP recibidos (de `lldpctl`) y reportarlos en inform

### 6.1 Frame LLDP (IEEE 802.1AB)

```
Ethernet frame:
  dst: 01:80:c2:00:00:0e  (multicast LLDP)
  src: MAC del AP
  type: 0x88cc

Payload TLV:
  [Chassis ID TLV]  type=1, subtype=4(MAC), value=MAC
  [Port ID TLV]     type=2, subtype=5(ifname), value="eth0"
  [TTL TLV]         type=3, value=120 (segundos)
  [System Name TLV] type=5, value="hostname"
  [System Desc TLV] type=6, value="modelo + versión"
  [Capabilities]    type=7, cap=0x0010(WLAN-AP), enabled=0x0010
  [End TLV]         type=0, len=0
```

**Implementación:** `lldp.c` → `lldp_send_frame()` usa raw socket `AF_PACKET`.

### 6.2 Leer vecinos con lldpctl

```bash
lldpctl -f json
```

Retorna JSON con todos los vecinos. Se parsea y se incluye en `lldp_table`
del payload inform.

**Implementación:** `lldp.c` → `lldp_read_neighbors()` ejecuta lldpctl con
popen() y parsea el JSON con json-c.

---

## 7. Band Steering & Fast Roaming

Cuando el controlador activa estas funciones en un VAP:

### Band Steering (802.11k/v)
```
wireless.<sec>.ieee80211k = 1      # Neighbor Reports
wireless.<sec>.ieee80211v = 1      # BSS Transition Management
wireless.<sec>.bss_transition = 1
wireless.<sec>.rrm_neighbor_report = 1
```

### Fast Roaming (802.11r)
```
wireless.<sec>.ieee80211r = 1
wireless.<sec>.ft_over_ds = 1
wireless.<sec>.mobility_domain = "1234"  # mismo en todos los APs del site
wireless.<sec>.ft_psk_generate_local = 1
```

### PMF (Protected Management Frames)
```
wireless.<sec>.ieee80211w = 0  # disabled
wireless.<sec>.ieee80211w = 1  # optional
wireless.<sec>.ieee80211w = 2  # required
```

---

## 8. Lectura de parámetros en código

### Del controlador → AP (setstate)

```c
/* En inform.c → handle_response() → case "setstate": */
struct json_object *vap_table;
json_object_object_get_ex(resp, "vap_table", &vap_table);
// Se pasa a wlan_apply_config() que llama a libuci

/* Cada VAP: */
const char *essid    = json_object_get_string(json_object_object_get(vap, "essid"));
const char *security = json_object_get_string(json_object_object_get(vap, "security"));
int hide_ssid        = json_object_get_boolean(json_object_object_get(vap, "hide_ssid"));
```

### Del sistema → AP (status report)

```c
/* En sysinfo.c: */
FILE *f = fopen("/proc/stat", "r");
fscanf(f, "cpu %lu %lu %lu %lu", &user, &nice, &sys, &idle);

/* En clients.c: */
FILE *p = popen("iw dev wlan0 station dump", "r");
// parsear: "Station aa:bb:cc ... signal: -62 dBm"

/* En lldp.c: */
FILE *p = popen("lldpctl -f json 2>/dev/null", "r");
// parsear JSON de vecinos
```
