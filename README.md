# usque-rs

Cloudflare WARP MASQUE client implemented in Rust.

## Features

- SOCKS5 proxy with TCP CONNECT, BIND, and UDP ASSOCIATE support
- MASQUE protocol over HTTP/3 (QUIC)
- DNS resolution through tunnel
- Happy Eyeballs (parallel A/AAAA queries)
- TLS public key pinning
- Optional SOCKS5 authentication

## Quick Start

```bash
# 1. Register a new device
usque-rs register

# 2. Start SOCKS5 proxy
usque-rs socks

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
| `--config` | `-c` | `config.json` | Config file path |
| `--sni-address` | `-s` | `consumer-masque.cloudflareclient.com` | SNI for MASQUE |
| `--connect-port` | `-P` | `443` | MASQUE server port |
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
| `USQUE_TCP_BUFFER_SIZE` | `1048576` | TCP buffer size per direction in bytes |
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

`config.json` structure:

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

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release
```
