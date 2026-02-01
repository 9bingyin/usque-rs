#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::{Parser, Subcommand};
use std::net::SocketAddr;

mod api;

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            log::error!("Failed to install Ctrl+C handler: {}", e);
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                log::error!("Failed to install SIGTERM handler: {}", e);
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
mod config;
mod crypto;
mod proxy;
mod tunnel;
mod wg_config;

#[derive(Parser)]
#[command(name = "usque-rs")]
#[command(about = "Cloudflare WARP MASQUE client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Register {
        #[arg(short, long, default_value = "config.json")]
        config: String,
        #[arg(short, long, default_value = "PC")]
        model: String,
        #[arg(short, long, default_value = "en_US")]
        locale: String,
        /// Device name (optional)
        #[arg(short, long)]
        name: Option<String>,
        /// ZeroTrust team token (optional)
        #[arg(long)]
        jwt: Option<String>,
        /// Accept Cloudflare TOS (non-interactive setup)
        #[arg(short, long)]
        accept_tos: bool,
    },
    Enroll {
        #[arg(short, long, default_value = "config.json")]
        config: String,
        /// Device name (optional)
        #[arg(short, long)]
        name: Option<String>,
        /// Regenerate key pair
        #[arg(short, long)]
        regen_key: bool,
    },
    RegisterWg {
        #[arg(short, long, default_value = "warp.conf")]
        config: String,
        #[arg(short, long, default_value = "PC")]
        model: String,
        #[arg(short, long, default_value = "en_US")]
        locale: String,
        /// ZeroTrust team token (optional)
        #[arg(long)]
        jwt: Option<String>,
        /// Accept Cloudflare TOS (non-interactive setup)
        #[arg(short, long)]
        accept_tos: bool,
    },
    Socks {
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,
        #[arg(short, long, default_value = "1080")]
        port: u16,
        #[arg(short, long, default_value = "config.json")]
        config: String,
        /// Tunnel mode: masque (default) or wg
        #[arg(long, default_value = "masque")]
        mode: String,
        /// Username for SOCKS5 authentication (optional)
        #[arg(short, long)]
        username: Option<String>,
        /// Password for SOCKS5 authentication (required if username is set)
        #[arg(short = 'w', long)]
        password: Option<String>,
        /// SNI address for MASQUE connection
        #[arg(
            short,
            long = "sni-address",
            default_value = "consumer-masque.cloudflareclient.com"
        )]
        sni: String,
        /// DNS servers to use (can be specified multiple times)
        #[arg(short, long, default_values_t = vec!["9.9.9.10".to_string(), "149.112.112.10".to_string()])]
        dns: Vec<String>,
        /// Port for MASQUE connection
        #[arg(short = 'P', long = "connect-port", default_value = "443")]
        connect_port: u16,
        /// Keepalive period in seconds
        #[arg(short = 'k', long = "keepalive-period", default_value = "30")]
        keepalive: u64,
        /// Initial packet size for MASQUE connection
        #[arg(short = 'i', long = "initial-packet-size", default_value = "1242")]
        initial_packet_size: u16,
        /// MTU for MASQUE connection
        #[arg(short = 'm', long, default_value = "1280")]
        mtu: u16,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Register {
            config,
            model,
            locale,
            name,
            jwt,
            accept_tos,
        } => {
            register_device(
                &config,
                &model,
                &locale,
                name.as_deref(),
                jwt.as_deref(),
                accept_tos,
            )
            .await?;
        }
        Commands::RegisterWg {
            config,
            model,
            locale,
            jwt,
            accept_tos,
        } => {
            register_wg_device(
                &config,
                &model,
                &locale,
                jwt.as_deref(),
                accept_tos,
            )
            .await?;
        }
        Commands::Enroll {
            config,
            name,
            regen_key,
        } => {
            enroll_device(&config, name.as_deref(), regen_key).await?;
        }
        Commands::Socks {
            bind,
            port,
            config,
            mode,
            username,
            password,
            sni,
            dns,
            connect_port,
            keepalive,
            initial_packet_size,
            mtu,
        } => {
            match mode.as_str() {
                "wg" | "wireguard" => {
                    let options = SocksServerWgOptions {
                        bind,
                        port,
                        config_path: config,
                        username,
                        password,
                        dns_servers: dns,
                        mtu,
                    };
                    run_socks_server_wg(options).await?;
                }
                _ => {
                    let options = SocksServerOptions {
                        bind,
                        port,
                        config_path: config,
                        username,
                        password,
                        sni,
                        dns_servers: dns,
                        connect_port,
                        keepalive,
                        initial_packet_size,
                        mtu,
                    };
                    run_socks_server(options).await?;
                }
            }
        }
    }

    Ok(())
}

async fn register_device(
    config_path: &str,
    model: &str,
    locale: &str,
    device_name: Option<&str>,
    jwt: Option<&str>,
    _accept_tos: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;

    println!("Registering new device...");
    if jwt.is_some() {
        println!("Using ZeroTrust authentication");
    }

    let client = api::CloudflareClient::new();

    // Step 1: Register with random WG key
    let account = client.register(model, locale, jwt).await?;
    println!("Account created: {}", account.id);

    let token = account.token.clone().ok_or("No token in response")?;

    // Step 2: Generate ECDSA key pair
    let key_pair = crypto::generate_ec_key_pair()?;
    println!("Generated ECDSA key pair");

    // Step 3: Enroll MASQUE key
    let name = device_name.unwrap_or("usque-rs");
    let updated = client
        .enroll_key(&account.id, &token, &key_pair.public_key_der, Some(name))
        .await?;
    println!("MASQUE key enrolled");

    // Step 4: Build and save config
    let endpoint_v4 = updated
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v4.clone());

    let endpoint_v6 = updated
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v6.clone());

    let endpoint_pub_key = updated
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .map(|p| p.public_key.clone());

    let ipv4 = updated
        .config
        .interface_config
        .as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v4.clone());

    let ipv6 = updated
        .config
        .interface_config
        .as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v6.clone());

    let license = updated.account.license.clone().unwrap_or_default();

    if endpoint_v4.as_deref().unwrap_or("").is_empty()
        && endpoint_v6.as_deref().unwrap_or("").is_empty()
    {
        return Err("No endpoint info in response".into());
    }

    let endpoint_pub_key = endpoint_pub_key
        .filter(|k| !k.trim().is_empty())
        .ok_or("No endpoint public key in response")?;

    if ipv4.as_deref().unwrap_or("").is_empty() && ipv6.as_deref().unwrap_or("").is_empty() {
        return Err("No interface addresses in response".into());
    }

    let cfg = config::Config {
        private_key: base64::engine::general_purpose::STANDARD.encode(&key_pair.private_key_der),
        endpoint_v4: endpoint_v4.unwrap_or_default(),
        endpoint_v6: endpoint_v6.unwrap_or_default(),
        endpoint_pub_key,
        license,
        id: updated.id.clone(),
        access_token: token,
        ipv4: ipv4.unwrap_or_default(),
        ipv6: ipv6.unwrap_or_default(),
    };

    cfg.save(config_path)?;
    println!("Config saved to {}", config_path);

    Ok(())
}

async fn enroll_device(
    config_path: &str,
    device_name: Option<&str>,
    regen_key: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;
    use p256::pkcs8::EncodePublicKey;

    println!("Enrolling device key...");

    // Load existing config
    let cfg = config::Config::load(config_path)?;
    println!("Config loaded from {}", config_path);

    // Get or regenerate key pair
    let (private_key_der, public_key_der) = if regen_key {
        println!("Regenerating key pair...");
        let key_pair = crypto::generate_ec_key_pair()?;
        (key_pair.private_key_der, key_pair.public_key_der)
    } else {
        let signing_key = cfg.get_signing_key()?;
        let public_key = signing_key.verifying_key();
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| format!("Failed to encode public key: {}", e))?
            .to_vec();
        let private_key_der = cfg.get_private_key_der()?;
        (private_key_der, public_key_der)
    };

    // Call API to re-enroll
    let client = api::CloudflareClient::new();
    let updated = client
        .enroll_key(&cfg.id, &cfg.access_token, &public_key_der, device_name)
        .await?;
    println!("MASQUE key enrolled");

    // Build updated config
    let endpoint_v4 = updated
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v4.clone());

    let endpoint_v6 = updated
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v6.clone());

    let endpoint_pub_key = updated
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .map(|p| p.public_key.clone());

    let ipv4 = updated
        .config
        .interface_config
        .as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v4.clone());

    let ipv6 = updated
        .config
        .interface_config
        .as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v6.clone());

    let license = updated
        .account
        .license
        .clone()
        .unwrap_or(cfg.license.clone());

    let endpoint_v4 = endpoint_v4.unwrap_or(cfg.endpoint_v4.clone());
    let endpoint_v6 = endpoint_v6.unwrap_or(cfg.endpoint_v6.clone());
    if endpoint_v4.trim().is_empty() && endpoint_v6.trim().is_empty() {
        return Err("No endpoint info in response or existing config".into());
    }

    let endpoint_pub_key = endpoint_pub_key.unwrap_or(cfg.endpoint_pub_key.clone());
    if endpoint_pub_key.trim().is_empty() {
        return Err("No endpoint public key in response or existing config".into());
    }

    let ipv4 = ipv4.unwrap_or(cfg.ipv4.clone());
    let ipv6 = ipv6.unwrap_or(cfg.ipv6.clone());
    if ipv4.trim().is_empty() && ipv6.trim().is_empty() {
        return Err("No interface addresses in response or existing config".into());
    }

    let new_cfg = config::Config {
        private_key: base64::engine::general_purpose::STANDARD.encode(&private_key_der),
        endpoint_v4,
        endpoint_v6,
        endpoint_pub_key,
        license,
        id: updated.id.clone(),
        access_token: cfg.access_token.clone(),
        ipv4,
        ipv6,
    };

    new_cfg.save(config_path)?;
    println!("Config saved to {}", config_path);

    Ok(())
}

struct SocksServerOptions {
    bind: String,
    port: u16,
    config_path: String,
    username: Option<String>,
    password: Option<String>,
    sni: String,
    dns_servers: Vec<String>,
    connect_port: u16,
    keepalive: u64,
    initial_packet_size: u16,
    mtu: u16,
}

async fn run_socks_server(options: SocksServerOptions) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    let SocksServerOptions {
        bind,
        port,
        config_path,
        username,
        password,
        sni,
        dns_servers,
        connect_port,
        keepalive,
        initial_packet_size,
        mtu,
    } = options;

    // Read tuning parameters from environment variables
    let congestion_control: String =
        std::env::var("USQUE_CC").unwrap_or_else(|_| "cubic".to_string());

    let tcp_buffer_size: usize = std::env::var("USQUE_TCP_BUFFER_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(65536);

    let quic_idle_timeout_ms: u64 = std::env::var("USQUE_QUIC_IDLE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90000);

    let tunnel_workers: usize = std::env::var("USQUE_TUNNEL_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    let cfg = config::Config::load(&config_path)?;
    println!("Config loaded from {}", config_path);

    let signing_key = cfg.get_signing_key()?;
    let (cert_der, key_der) = crypto::generate_self_signed_cert(&signing_key)?;
    println!("Generated self-signed certificate");

    let endpoint_raw = if !cfg.endpoint_v4.trim().is_empty() {
        cfg.endpoint_v4.as_str()
    } else {
        cfg.endpoint_v6.as_str()
    };
    if endpoint_raw.trim().is_empty() {
        return Err("No endpoint configured".into());
    }
    let endpoint = if let Ok(addr) = endpoint_raw.parse::<SocketAddr>() {
        SocketAddr::new(addr.ip(), connect_port)
    } else if let Ok(ip) = endpoint_raw.parse::<std::net::IpAddr>() {
        SocketAddr::new(ip, connect_port)
    } else {
        return Err(format!("Invalid endpoint address: {}", endpoint_raw).into());
    };
    println!("Will connect to endpoint: {}", endpoint);
    println!("Using SNI: {}", sni);

    let endpoint_pub_key = if cfg.endpoint_pub_key.trim().is_empty() {
        return Err("Endpoint public key is required for security".into());
    } else {
        Some(cfg.get_endpoint_pub_key_der()?)
    };

    // Parse DNS servers
    let dns_addrs = tunnel::dns::parse_dns_servers(&dns_servers)?;
    println!("Using DNS servers: {:?}", dns_servers);

    // Parse congestion control algorithm
    let cc: tunnel::CongestionControl = congestion_control.parse().map_err(|e: String| e)?;
    println!("Using congestion control: {}", cc);

    let keepalive_ms = keepalive.saturating_mul(1000);
    if keepalive_ms >= quic_idle_timeout_ms {
        log::warn!(
            "Keepalive period {}ms >= QUIC idle timeout {}ms; connection may time out",
            keepalive_ms,
            quic_idle_timeout_ms
        );
    }

    let params = tunnel::ConnectionParams {
        endpoint,
        cert_der,
        key_der,
        sni,
        endpoint_pub_key,
        ipv4: cfg.ipv4.clone(),
        ipv6: if cfg.ipv6.trim().is_empty() {
            None
        } else {
            Some(cfg.ipv6.clone())
        },
        dns_servers: dns_addrs,
        keepalive,
        initial_packet_size,
        mtu,
        congestion_control: cc,
        tcp_buffer_size,
        quic_idle_timeout_ms,
        tunnel_mode: tunnel::TunnelMode::Masque,
        wg_private_key: None,
        wg_peer_public_key: None,
        wg_client_id: None,
    };

    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let worker_count = if tunnel_workers == 0 {
        available.clamp(1, 4)
    } else {
        tunnel_workers.max(1)
    };

    let tunnel_pool = Arc::new(tunnel::TunnelManagerPool::new(params, worker_count));
    println!("Tunnel manager pool started (workers: {})", worker_count);

    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;

    let server = match (username, password) {
        (Some(user), Some(pass)) => {
            println!("SOCKS5 authentication enabled");
            proxy::Socks5Server::with_auth(addr, tunnel_pool, user, pass)
        }
        (Some(_), None) => {
            return Err("Password is required when username is set".into());
        }
        _ => proxy::Socks5Server::new(addr, tunnel_pool),
    };

    println!("Starting SOCKS5 server on {}:{}", bind, port);
    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                log::error!("Server error: {}", e);
            }
        }
        _ = shutdown_signal() => {
            log::info!("Shutdown signal received, exiting");
        }
    }

    Ok(())
}

struct SocksServerWgOptions {
    bind: String,
    port: u16,
    config_path: String,
    username: Option<String>,
    password: Option<String>,
    dns_servers: Vec<String>,
    mtu: u16,
}

async fn run_socks_server_wg(
    options: SocksServerWgOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    let SocksServerWgOptions {
        bind,
        port,
        config_path,
        username,
        password,
        dns_servers,
        mtu,
    } = options;

    let tcp_buffer_size: usize = std::env::var("USQUE_TCP_BUFFER_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(65536);

    let tunnel_workers: usize = std::env::var("USQUE_TUNNEL_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    let wg_cfg = wg_config::WgConfig::load(&config_path)?;
    println!("WireGuard config loaded from {}", config_path);

    let private_key = wg_cfg.get_private_key_bytes()?;
    let peer_public_key = wg_cfg.get_peer_public_key_bytes()?;
    let client_id = wg_cfg.get_client_id_bytes()?;
    let mut endpoint = wg_cfg.get_endpoint_addr()?;
    if endpoint.port() == 0 {
        log::warn!("Endpoint port is 0, using default WG port 2408");
        endpoint.set_port(2408);
    }
    let keepalive = wg_cfg.keepalive as u64;

    println!("Will connect to WG endpoint: {}", endpoint);
    println!(
        "Client ID (reserved): [{}, {}, {}]",
        client_id[0], client_id[1], client_id[2]
    );

    // Use DNS from config if CLI didn't override defaults,
    // otherwise use the CLI-provided DNS servers
    let dns_addrs = if !wg_cfg.dns.trim().is_empty() {
        tunnel::dns::parse_dns_servers(std::slice::from_ref(&wg_cfg.dns))?
    } else {
        tunnel::dns::parse_dns_servers(&dns_servers)?
    };
    println!("Using DNS servers: {:?}", dns_addrs);

    let wg_mtu = if mtu == 0 {
        wg_cfg.mtu
    } else {
        mtu
    };

    let params = tunnel::ConnectionParams {
        endpoint,
        cert_der: Vec::new(),
        key_der: Vec::new(),
        sni: String::new(),
        endpoint_pub_key: None,
        ipv4: wg_cfg.ipv4_address().to_string(),
        ipv6: wg_cfg.ipv6_address().map(|s| s.to_string()),
        dns_servers: dns_addrs,
        keepalive,
        initial_packet_size: 0,
        mtu: wg_mtu,
        congestion_control: tunnel::CongestionControl::default(),
        tcp_buffer_size,
        quic_idle_timeout_ms: 0,
        tunnel_mode: tunnel::TunnelMode::Wireguard,
        wg_private_key: Some(private_key),
        wg_peer_public_key: Some(peer_public_key),
        wg_client_id: Some(client_id),
    };

    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let worker_count = if tunnel_workers == 0 {
        available.clamp(1, 4)
    } else {
        tunnel_workers.max(1)
    };

    let tunnel_pool = Arc::new(tunnel::TunnelManagerPool::new(params, worker_count));
    println!("WireGuard tunnel manager pool started (workers: {})", worker_count);

    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;

    let server = match (username, password) {
        (Some(user), Some(pass)) => {
            println!("SOCKS5 authentication enabled");
            proxy::Socks5Server::with_auth(addr, tunnel_pool, user, pass)
        }
        (Some(_), None) => {
            return Err("Password is required when username is set".into());
        }
        _ => proxy::Socks5Server::new(addr, tunnel_pool),
    };

    println!("Starting SOCKS5 server (WireGuard mode) on {}:{}", bind, port);
    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                log::error!("Server error: {}", e);
            }
        }
        _ = shutdown_signal() => {
            log::info!("Shutdown signal received, exiting");
        }
    }

    Ok(())
}

async fn register_wg_device(
    config_path: &str,
    model: &str,
    locale: &str,
    jwt: Option<&str>,
    _accept_tos: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;

    println!("Registering new WireGuard device...");
    if jwt.is_some() {
        println!("Using ZeroTrust authentication");
    }

    // Step 1: Generate Curve25519 key pair
    let wg_keys = crypto::generate_wg_key_pair()?;
    println!("Generated WireGuard key pair");

    // Step 2: Register with real WG public key
    let client = api::CloudflareClient::new();
    let account = client
        .register_wg(&wg_keys.public_key_base64, model, locale, jwt)
        .await?;
    println!("Account created: {}", account.id);

    let token = account.token.clone().ok_or("No token in response")?;

    // Step 3: Extract peer config
    let peer = account
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .ok_or("No peer info in response")?;

    let peer_public_key = peer.public_key.clone();
    let endpoint_v4 = peer
        .endpoint
        .as_ref()
        .and_then(|e| e.v4.clone())
        .unwrap_or_default();
    let endpoint_v6 = peer
        .endpoint
        .as_ref()
        .and_then(|e| e.v6.clone());

    let interface = account
        .config
        .interface_config
        .as_ref()
        .and_then(|i| i.addresses.as_ref())
        .ok_or("No interface addresses in response")?;

    let ipv4 = interface.v4.clone().unwrap_or_default();
    let ipv6 = interface.v6.clone();

    let client_id = account
        .config
        .client_id
        .clone()
        .ok_or("No client_id in response")?;

    if endpoint_v4.is_empty() {
        return Err("No endpoint v4 in response".into());
    }
    if ipv4.is_empty() {
        return Err("No IPv4 address in response".into());
    }

    // Step 4: Build endpoint string (IP:port, default port 2408)
    // Cloudflare API may return port 0; replace with default WG port 2408.
    let endpoint_str = match endpoint_v4.parse::<SocketAddr>() {
        Ok(addr) if addr.port() == 0 => {
            SocketAddr::new(addr.ip(), 2408).to_string()
        }
        Ok(_) => endpoint_v4.clone(),
        Err(_) => {
            if let Ok(ip) = endpoint_v4.parse::<std::net::IpAddr>() {
                SocketAddr::new(ip, 2408).to_string()
            } else {
                format!("{}:2408", endpoint_v4)
            }
        }
    };

    let endpoint6_str = endpoint_v6.map(|v6| {
        let trimmed = v6.trim_matches(|c| c == '[' || c == ']');
        match trimmed.parse::<SocketAddr>().or_else(|_| v6.parse::<SocketAddr>()) {
            Ok(addr) if addr.port() == 0 => {
                SocketAddr::new(addr.ip(), 2408).to_string()
            }
            Ok(addr) => addr.to_string(),
            Err(_) => {
                let ip_str = trimmed.split("]:").next().unwrap_or(trimmed);
                if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
                    SocketAddr::new(std::net::IpAddr::V6(ip), 2408).to_string()
                } else {
                    format!("[{}]:2408", ip_str)
                }
            }
        }
    });

    // Step 5: Build and save WG config
    let private_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(wg_keys.private_key);

    let wg_cfg = wg_config::WgConfig {
        device_id: account.id.clone(),
        private_key: private_key_b64,
        token,
        client_id: client_id.clone(),
        account_type: "free".to_string(),
        mtu: 1280,
        peer_public_key,
        endpoint: endpoint_str,
        endpoint6: endpoint6_str,
        keepalive: 30,
        address: format!("{}/32", ipv4),
        address6: ipv6.map(|v6| format!("{}/128", v6)),
        dns: "1.1.1.1".to_string(),
    };

    wg_cfg.save(config_path)?;
    println!("WireGuard config saved to {}", config_path);

    // Print reserved value for reference
    let client_id_bytes = base64::engine::general_purpose::STANDARD
        .decode(&client_id)
        .unwrap_or_default();
    println!(
        "reserved: {:?} (base64: {})",
        client_id_bytes, client_id
    );

    Ok(())
}
