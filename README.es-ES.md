# usque-rs

Cliente de Cloudflare WARP implementado en Rust, con soporte para modos de túnel MASQUE y WireGuard.

## Características

- Proxy SOCKS5 con soporte para TCP CONNECT, BIND y UDP ASSOCIATE
- Modos de túnel duales: MASQUE (HTTP/3 sobre QUIC) y WireGuard (UDP)
- Pila TCP/IP en espacio de usuario (smoltcp) - no requiere root/TUN
- Resolución DNS a través del túnel
- Happy Eyeballs (consultas A/AAAA paralelas)
- Pinning de clave pública TLS (modo MASQUE)
- Autenticación SOCKS5 opcional

## Inicio Rápido

### Modo MASQUE

```bash
# 1. Registrar un nuevo dispositivo
usque-rs register masque --accept-tos

# 2. Iniciar proxy SOCKS5
usque-rs socks masque

# 3. Probar la conexión
curl -x socks5://127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

### Modo WireGuard

```bash
# 1. Registrar un nuevo dispositivo (genera warp.conf)
usque-rs register wg --accept-tos

# 2. Iniciar proxy SOCKS5
usque-rs socks wg

# 3. Probar la conexión
curl -x socks5://127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

## Comandos

### register masque

Registra un nuevo dispositivo para el modo de túnel MASQUE.

```bash
usque-rs register masque [OPTIONS]
```

| Opción | Corto | Predeterminado | Descripción |
|--------|-------|----------------|-------------|
| `--config` | `-c` | `config.json` | Ruta del archivo de configuración |
| `--model` | `-m` | `PC` | Modelo del dispositivo |
| `--locale` | `-l` | `en_US` | Idioma/Región |
| `--name` | `-n` | - | Nombre del dispositivo |
| `--jwt` | - | - | Token de equipo ZeroTrust |
| `--accept-tos` | `-a` | `false` | Aceptar los TOS de Cloudflare |

### register wg

Registra un nuevo dispositivo para el modo de túnel WireGuard. Genera un par de claves Curve25519 y guarda la configuración como un archivo INI.

```bash
usque-rs register wg [OPTIONS]
```

| Opción | Corto | Predeterminado | Descripción |
|--------|-------|----------------|-------------|
| `--config` | `-c` | `warp.conf` | Ruta del archivo de configuración (formato INI) |
| `--model` | `-m` | `PC` | Modelo del dispositivo |
| `--locale` | `-l` | `en_US` | Idioma/Región |
| `--jwt` | - | - | Token de equipo ZeroTrust |
| `--accept-tos` | `-a` | `false` | Aceptar los TOS de Cloudflare |

### enroll

Vuelve a inscribir la clave del dispositivo (modo MASQUE, útil para rotación de claves).

```bash
usque-rs enroll [OPTIONS]
```

| Opción | Corto | Predeterminado | Descripción |
|--------|-------|----------------|-------------|
| `--config` | `-c` | `config.json` | Ruta del archivo de configuración |
| `--name` | `-n` | - | Nombre del dispositivo |
| `--regen-key` | `-r` | `false` | Regenerar el par de claves |

### socks masque

Inicia el proxy SOCKS5 con túnel MASQUE (HTTP/3 sobre QUIC).

```bash
usque-rs socks masque [OPTIONS]
```

#### Opciones Comunes

| Opción | Corto | Predeterminado | Descripción |
|--------|-------|----------------|-------------|
| `--bind` | `-b` | `0.0.0.0` | Dirección de enlace (bind) |
| `--port` | `-p` | `1080` | Puerto de escucha |
| `--config` | `-c` | `config.json` | Ruta del archivo de configuración |
| `--username` | `-u` | - | Usuario de SOCKS5 |
| `--password` | `-w` | - | Contraseña de SOCKS5 (requerida si se define el usuario) |
| `--dns` | `-d` | `9.9.9.10,149.112.112.10` | Servidores DNS (se pueden especificar varios) |
| `--mtu` | `-m` | `1280` | MTU |

#### Opciones de MASQUE

| Opción | Corto | Predeterminado | Descripción |
|--------|-------|----------------|-------------|
| `--sni-address` | `-s` | `consumer-masque.cloudflareclient.com` | SNI para la conexión MASQUE |
| `--connect-port` | `-P` | `443` | Puerto del servidor MASQUE |
| `--keepalive-period` | `-k` | `30` | Intervalo de keepalive en segundos |
| `--initial-packet-size` | `-i` | `1242` | Tamaño inicial del paquete QUIC |

### socks wg

Inicia el proxy SOCKS5 con túnel WireGuard (UDP).

```bash
usque-rs socks wg [OPTIONS]
```

| Opción | Corto | Predeterminado | Descripción |
|--------|-------|----------------|-------------|
| `--bind` | `-b` | `0.0.0.0` | Dirección de enlace (bind) |
| `--port` | `-p` | `1080` | Puerto de escucha |
| `--config` | `-c` | `warp.conf` | Ruta del archivo de configuración |
| `--username` | `-u` | - | Usuario de SOCKS5 |
| `--password` | `-w` | - | Contraseña de SOCKS5 (requerida si se define el usuario) |
| `--dns` | `-d` | `9.9.9.10,149.112.112.10` | Servidores DNS (se pueden especificar varios) |
| `--mtu` | `-m` | `1280` | MTU |

## Variables de Entorno

### Parámetros de Ajuste (Tuning)

| Variable | Predeterminado | Descripción |
|----------|----------------|-------------|
| `USQUE_CC` | `cubic` | Algoritmo de control de congestión (reno/cubic/bbr/bbr2) |
| `USQUE_TCP_BUFFER_SIZE` | `65536` | Tamaño del búfer TCP por dirección en bytes |
| `USQUE_QUIC_IDLE_TIMEOUT_MS` | `90000` | Tiempo de espera de inactividad de QUIC en ms (debe ser > 2x keepalive) |
| `USQUE_TUNNEL_WORKERS` | `1` | Número de workers (0=auto, predeterminado 1 para evitar abusos al upstream) |

### Otros

| Variable | Predeterminado | Descripción |
|----------|----------------|-------------|
| `RUST_LOG` | - | Nivel de log (error/warn/info/debug/trace) |
| `USQUE_MAX_CONNECTIONS` | `1024` | Máximo de conexiones SOCKS5 concurrentes |

### Ajuste del Sistema (Recomendado)

Para escenarios de alto rendimiento, aumente el tamaño del búfer UDP del sistema:

```bash
# macOS
sudo sysctl -w kern.ipc.maxsockbuf=8441037

# Linux
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

## Ejemplos

### Uso Básico

```bash
# Iniciar proxy MASQUE con ajustes predeterminados
usque-rs socks masque

# Iniciar en puerto personalizado con logs de depuración (debug)
RUST_LOG=debug usque-rs socks masque -p 8080
```

### Modo WireGuard

```bash
# Registrar e iniciar proxy WG
usque-rs register wg --accept-tos
usque-rs socks wg

# Modo WG con puerto y DNS personalizados
usque-rs socks wg -p 8080 -d 1.1.1.1
```

### Modo de Alto Rendimiento

```bash
# Habilitar conteo automático de workers y búferes más grandes
USQUE_TUNNEL_WORKERS=0 USQUE_TCP_BUFFER_SIZE=2097152 usque-rs socks masque
```

### Con Autenticación

```bash
usque-rs socks masque -u miusuario -w mimisena
```

### Modo ZeroTrust

```bash
# Registrar con token de equipo
usque-rs register masque --jwt <tu-token-de-equipo>

# Usar SNI de ZeroTrust
usque-rs socks masque --sni-address <tu-equipo>.cloudflareaccess.com
```

### Docker

```bash
# Modo MASQUE (predeterminado)
docker run -e SOCKS_BIND=0.0.0.0 -p 1080:1080 usque-rs

# Modo WireGuard
docker run -e TUNNEL_MODE=wg -e SOCKS_BIND=0.0.0.0 -p 1080:1080 usque-rs

# Con autenticación
docker run -e SOCKS_USER=user -e SOCKS_PASS=pass -e SOCKS_BIND=0.0.0.0 -p 1080:1080 usque-rs
```

#### Variables de Entorno de Docker

| Variable | Predeterminado | Descripción |
|----------|----------------|-------------|
| `TUNNEL_MODE` | `masque` | Modo de túnel: `masque` o `wg` (también acepta `wireguard`) |
| `SOCKS_BIND` | `127.0.0.1` | Dirección de enlace de SOCKS5 |
| `SOCKS_PORT` | `1080` | Puerto de escucha de SOCKS5 |
| `SOCKS_USER` | - | Usuario de SOCKS5 |
| `SOCKS_PASS` | - | Contraseña de SOCKS5 |
| `DNS_SERVERS` | `1.1.1.1,1.0.0.1` | Servidores DNS (separados por comas) |

## Formato del Archivo de Configuración

### Modo MASQUE (`config.json`)

```json
{
  "private_key": "<base64-encoded-ecdsa-private-key>",
  "endpoint_v4": "162.159.198.1:2408",
  "endpoint_v6": "",
  "endpoint_pub_key": "<base64-encoded-server-public-key>",
  "license": "",
  "id": "<device-id>",
  "access_token": "<access-token>",
  "ipv4": "172.16.0.2",
  "ipv6": ""
}
```

### Modo WireGuard (`warp.conf`)

Formato INI, generado por el comando `register wg`:

```ini
[Account]
Device = <device-id>
PrivateKey = <base64 Curve25519 private key>
Token = <access-token>
ClientId = <base64 client_id, 3 bytes>
Type = free

[Device]
MTU = 1280

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 162.159.193.10:2408
Endpoint6 = [2606:4700:d0::a29f:c001]:2408
KeepAlive = 30

[Interface]
Address = 172.16.0.2/32
Address6 = 2606:4700:110:xxxx:xxxx:xxxx:xxxx:xxxx/128
DNS = 1.1.1.1
```

## Construcción (Building)

```bash
# Build de depuración (debug)
cargo build

# Build de lanzamiento (release)
cargo build --release
```
