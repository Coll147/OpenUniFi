# openUF — C

Daemon que hace pasar un router OpenWrt como un **UniFi U6 InWall** ante el controlador UniFi Network.

## Funciones implementadas

| Función | Descripción | Implementación |
|---------|-------------|----------------|
| **Descubrimiento L2** | UDP broadcast + multicast cada 10s | `announce.c` → puerto 10001 |
| **Adopción** | Handshake AES-128-CBC con el controlador | `inform.c` → `handle_response()` |
| **Config WiFi** | Crea redes WiFi desde el controlador via UCI | `wlan.c` → `wlan_apply_config()` |
| **Band Steering** | 802.11k/v Neighbor Reports + BSS Transition | `wlan.c` → `apply_vap()` |
| **Fast Roaming** | 802.11r FT con mobility_domain derivado del MAC | `wlan.c` → `apply_vap()` |
| **WPA3 / PMF** | SAE, SAE-mixed, 802.11w 0/1/2 | `wlan.c` → `sec_to_uci()` |
| **Clientes WiFi** | MAC, señal, bitrate, bytes por VAP | `clients.c` → `iw station dump` |
| **Clientes cableados** | MACs del bridge FDB | `clients.c` → `bridge fdb` |
| **CPU / RAM** | Uso en tiempo real | `sysinfo.c` → `/proc/stat` + `/proc/meminfo` |
| **Interfaces** | Velocidad, duplex, contadores rx/tx | `sysinfo.c` → `/proc/net/dev` |
| **Canal / RF** | Utilización del canal, noise, tx_power | `sysinfo.c` → `iw survey dump` |
| **LLDP envío** | Frames propios por AF_PACKET raw socket | `lldp.c` → `lldp_send_frame()` |
| **LLDP lectura** | Vecinos para topología UniFi | `lldp.c` → `lldpctl -f json` |

## Instalación rápida

```sh
# En el dispositivo OpenWrt:
opkg update
opkg install gcc make libmbedtls-dev libuci-dev libjson-c-dev

# Compilar e instalar
make -f Makefile.standalone install

# Configurar
vi /etc/openuf/openuf.conf   # ajustar controller_ip y lan_if

# Iniciar
/etc/init.d/openuf start
/etc/init.d/openuf enable    # arrancar al boot
```

## Configuración

```ini
controller_ip   = 192.168.1.1   # IP del controlador UniFi
lan_if          = br-lan         # interfaz LAN (para MAC e IP)
ufmodel         = u6-inwall      # modelo emulado
inform_interval = 10             # segundos entre inform
enable_announce = 1
enable_inform   = 1
```

## Modelo U6 InWall

Se emula un **U6 IW** porque tiene 5 puertos GbE, cubriendo la mayoría de routers OpenWrt. El modelo reporta:

- 5 puertos ethernet (eth0-eth4)
- Radio 2.4 GHz WiFi 6 (HE/802.11ax)
- Radio 5 GHz WiFi 6 (HE/802.11ax)

## LLDP

Para topología visual en UniFi:

```sh
opkg install lldpd
/etc/init.d/lldpd start
/etc/init.d/lldpd enable
```

openuf envía frames LLDP propios incluso sin lldpd (raw socket).
Con lldpd instalado también reporta los vecinos upstream (switches).

## Adopción

El proceso es automático:

1. El AP aparece como "Pendiente" en UniFi
2. Click en "Adoptar" → el controlador envía una clave nueva
3. El AP aplica la clave y queda "Conectado"
4. El controlador empuja la configuración WiFi (SSIDs, canales, etc.)

Para resetear: `rm /etc/openuf/state.json && reboot`

## Dependencias

```sh
opkg install libmbedtls libuci libjson-c
opkg install lldpd   # opcional, para topología
```
