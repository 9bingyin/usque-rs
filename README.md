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
usque-rs register

# 2. Start SOCKS5 proxy
usque-rs socks

# 3. Test connection
curl -x socks5://127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

### WireGuard mode

```bash
# 1. Register a new device (generates warp.conf)
usque-rs register-wg --accept-tos

# 2. Start SOCKS5 proxy in WG mode
usque-rs socks --mode wg --config warp.conf

# 3. Test connection
curl -x socks5://127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

## Commands

### register

Register a new device with Cloudflare WARP.

```bash
usque-rs register [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--config` | `-c` | `config.json` | Config file path |
| `--model` | `-m` | `PC` | Device model |
| `--locale` | `-l` | `en_US` | Locale |
| `--name` | `-n` | - | Device name |
| `--jwt` | - | - | ZeroTrust team token |
| `--accept-tos` | `-a` | `false` | Accept Cloudflare TOS |

### register-wg

Register a new device with Cloudflare WARP for WireGuard mode. Generates a Curve25519 key pair and saves the configuration as an INI file.

```bash
usque-rs register-wg [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--config` | `-c` | `warp.conf` | Config file path (INI format) |
| `--model` | `-m` | `PC` | Device model |
| `--locale` | `-l` | `en_US` | Locale |
| `--jwt` | - | - | ZeroTrust team token |
| `--accept-tos` | `-a` | `false` | Accept Cloudflare TOS |

### enroll

Re-enroll device key (useful for key rotation).

```bash
usque-rs enroll [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--config` | `-c` | `config.json` | Config file path |
| `--name` | `-n` | - | Device name |
| `--regen-key` | `-r` | `false` | Regenerate key pair |

### socks

Start SOCKS5 proxy server.

```bash
usque-rs socks [OPTIONS]
```

#### Network Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--bind` | `-b` | `0.0.0.0` | Bind address |
| `--port` | `-p` | `1080` | Listen port |
| `--config` | `-c` | `config.json` | Config file path (`config.json` for MASQUE, `warp.conf` for WG) |
| `--mode` | - | `masque` | Tunnel mode: `masque` or `wg` |
| `--sni-address` | `-s` | `consumer-masque.cloudflareclient.com` | SNI for MASQUE (MASQUE mode only) |
| `--connect-port` | `-P` | `443` | MASQUE server port (MASQUE mode only) |
| `--dns` | `-d` | `9.9.9.10,149.112.112.10` | DNS servers (can specify multiple) |

#### Authentication Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--username` | `-u` | - | SOCKS5 username |
| `--password` | `-w` | - | SOCKS5 password (required if username set) |

#### Performance Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--mtu` | `-m` | `1280` | MTU for MASQUE connection |
| `--initial-packet-size` | `-i` | `1242` | Initial QUIC packet size |
| `--keepalive-period` | `-k` | `30` | Keepalive interval in seconds |

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
# Start with default settings
usque-rs socks

# Start on custom port with debug logging
RUST_LOG=debug usque-rs socks -p 8080
```

### WireGuard Mode

```bash
# Register and start WG proxy
usque-rs register-wg --accept-tos
usque-rs socks --mode wg --config warp.conf

# WG mode with custom port and DNS
usque-rs socks --mode wg --config warp.conf -p 8080 -d 1.1.1.1
```

### High Performance Mode

```bash
# Enable auto worker count and larger buffers
USQUE_TUNNEL_WORKERS=0 USQUE_TCP_BUFFER_SIZE=2097152 usque-rs socks
```

### With Authentication

```bash
usque-rs socks -u myuser -w mypassword
```

### ZeroTrust Mode

```bash
# Register with team token
usque-rs register --jwt <your-team-token>

# Use ZeroTrust SNI
usque-rs socks --sni-address <your-team>.cloudflareaccess.com
```

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

INI format, generated by `register-wg` command:

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
