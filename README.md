# usque-rs

Cloudflare WARP client implemented in Rust, supporting both MASQUE and WireGuard tunnel modes.

## Features

- SOCKS5 proxy with TCP CONNECT, BIND, and UDP ASSOCIATE support
- Dual tunnel modes: MASQUE (HTTP/3 over QUIC) and WireGuard (UDP)
- Userspace TCP/IP stack (smoltcp) - no root/TUN required
- DNS resolution through tunnel
- Happy Eyeballs (parallel A/AAAA queries)
- TLS public key pinning (MASQUE mode)
- Optional SOCKS5 authentication

## Quick Start

### MASQUE mode

```bash
# 1. Register a new device
usque-rs register masque --accept-tos

# 2. Start SOCKS5 proxy
usque-rs socks masque

# 3. Test connection
curl -x socks5://127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

### WireGuard mode

```bash
# 1. Register a new device (generates warp.conf)
usque-rs register wg --accept-tos

# 2. Start SOCKS5 proxy
usque-rs socks wg

# 3. Test connection
curl -x socks5://127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

## Commands

### register masque

Register a new device for MASQUE tunnel mode.

```bash
usque-rs register masque [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--config` | `-c` | `config.json` | Config file path |
| `--model` | `-m` | `PC` | Device model |
| `--locale` | `-l` | `en_US` | Locale |
| `--name` | `-n` | - | Device name |
| `--jwt` | - | - | ZeroTrust team token |
| `--accept-tos` | `-a` | `false` | Accept Cloudflare TOS |

### register wg

Register a new device for WireGuard tunnel mode. Generates a Curve25519 key pair and saves the configuration as an INI file.

```bash
usque-rs register wg [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--config` | `-c` | `warp.conf` | Config file path (INI format) |
| `--model` | `-m` | `PC` | Device model |
| `--locale` | `-l` | `en_US` | Locale |
| `--jwt` | - | - | ZeroTrust team token |
| `--accept-tos` | `-a` | `false` | Accept Cloudflare TOS |

### enroll

Re-enroll device key (MASQUE mode, useful for key rotation).

```bash
usque-rs enroll [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--config` | `-c` | `config.json` | Config file path |
| `--name` | `-n` | - | Device name |
| `--regen-key` | `-r` | `false` | Regenerate key pair |

### socks masque

Start SOCKS5 proxy with MASQUE tunnel (HTTP/3 over QUIC).

```bash
usque-rs socks masque [OPTIONS]
```

#### Common Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--bind` | `-b` | `0.0.0.0` | Bind address |
| `--port` | `-p` | `1080` | Listen port |
| `--config` | `-c` | `config.json` | Config file path |
| `--username` | `-u` | - | SOCKS5 username |
| `--password` | `-w` | - | SOCKS5 password (required if username set) |
| `--dns` | `-d` | `9.9.9.10,149.112.112.10` | DNS servers (can specify multiple) |
| `--mtu` | `-m` | `1280` | MTU |

#### MASQUE Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--sni-address` | `-s` | `consumer-masque.cloudflareclient.com` | SNI for MASQUE connection |
| `--connect-port` | `-P` | `443` | MASQUE server port |
| `--keepalive-period` | `-k` | `30` | Keepalive interval in seconds |
| `--initial-packet-size` | `-i` | `1242` | Initial QUIC packet size |

### socks wg

Start SOCKS5 proxy with WireGuard tunnel (UDP).

```bash
usque-rs socks wg [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--bind` | `-b` | `0.0.0.0` | Bind address |
| `--port` | `-p` | `1080` | Listen port |
| `--config` | `-c` | `warp.conf` | Config file path |
| `--username` | `-u` | - | SOCKS5 username |
| `--password` | `-w` | - | SOCKS5 password (required if username set) |
| `--dns` | `-d` | `9.9.9.10,149.112.112.10` | DNS servers (can specify multiple) |
| `--mtu` | `-m` | `1280` | MTU |

## Environment Variables

### Tuning Parameters

| Variable | Default | Description |
|----------|---------|-------------|
| `USQUE_CC` | `cubic` | Congestion control algorithm (reno/cubic/bbr/bbr2) |
| `USQUE_TCP_BUFFER_SIZE` | `65536` | TCP buffer size per direction in bytes |
| `USQUE_QUIC_IDLE_TIMEOUT_MS` | `90000` | QUIC idle timeout in ms (should be > 2x keepalive) |
| `USQUE_TUNNEL_WORKERS` | `1` | Worker count (0=auto, default 1 to avoid abusing upstream) |

### Other

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | - | Log level (error/warn/info/debug/trace) |
| `USQUE_MAX_CONNECTIONS` | `1024` | Maximum concurrent SOCKS5 connections |

### System Tuning (Recommended)

For high-throughput scenarios, increase system UDP buffer size:

```bash
# macOS
sudo sysctl -w kern.ipc.maxsockbuf=8441037

# Linux
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

## Examples

### Basic Usage

```bash
# Start MASQUE proxy with default settings
usque-rs socks masque

# Start on custom port with debug logging
RUST_LOG=debug usque-rs socks masque -p 8080
```

### WireGuard Mode

```bash
# Register and start WG proxy
usque-rs register wg --accept-tos
usque-rs socks wg

# WG mode with custom port and DNS
usque-rs socks wg -p 8080 -d 1.1.1.1
```

### High Performance Mode

```bash
# Enable auto worker count and larger buffers
USQUE_TUNNEL_WORKERS=0 USQUE_TCP_BUFFER_SIZE=2097152 usque-rs socks masque
```

### With Authentication

```bash
usque-rs socks masque -u myuser -w mypassword
```

### ZeroTrust Mode

```bash
# Register with team token
usque-rs register masque --jwt <your-team-token>

# Use ZeroTrust SNI
usque-rs socks masque --sni-address <your-team>.cloudflareaccess.com
```

### Docker

```bash
# MASQUE mode (default)
docker run -e SOCKS_BIND=0.0.0.0 -p 1080:1080 usque-rs

# WireGuard mode
docker run -e TUNNEL_MODE=wg -e SOCKS_BIND=0.0.0.0 -p 1080:1080 usque-rs

# With authentication
docker run -e SOCKS_USER=user -e SOCKS_PASS=pass -e SOCKS_BIND=0.0.0.0 -p 1080:1080 usque-rs
```

#### Docker Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNEL_MODE` | `masque` | Tunnel mode: `masque` or `wg` (also accepts `wireguard`) |
| `SOCKS_BIND` | `127.0.0.1` | SOCKS5 bind address |
| `SOCKS_PORT` | `1080` | SOCKS5 listen port |
| `SOCKS_USER` | - | SOCKS5 username |
| `SOCKS_PASS` | - | SOCKS5 password |
| `DNS_SERVERS` | `1.1.1.1,1.0.0.1` | DNS servers (comma-separated) |

## Config File Format

### MASQUE mode (`config.json`)

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

### WireGuard mode (`warp.conf`)

INI format, generated by `register wg` command:

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

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release
```
