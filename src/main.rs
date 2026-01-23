use clap::{Parser, Subcommand};
use std::net::SocketAddr;

mod api;
mod config;
mod crypto;
mod proxy;
mod tunnel;

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
    Socks {
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,
        #[arg(short, long, default_value = "1080")]
        port: u16,
        #[arg(short, long, default_value = "config.json")]
        config: String,
        /// Username for SOCKS5 authentication (optional)
        #[arg(short, long)]
        username: Option<String>,
        /// Password for SOCKS5 authentication (required if username is set)
        #[arg(short = 'w', long)]
        password: Option<String>,
        /// SNI address for MASQUE connection
        #[arg(short, long = "sni-address", default_value = "consumer-masque.cloudflareclient.com")]
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
        /// Congestion control algorithm (reno, cubic, bbr, bbr2)
        #[arg(long = "cc", default_value = "bbr2")]
        congestion_control: String,
        /// TCP socket buffer size per direction in bytes
        #[arg(long = "tcp-buffer-size", default_value = "262144")]
        tcp_buffer_size: usize,
        /// QUIC idle timeout in milliseconds
        #[arg(long = "quic-idle-timeout-ms", default_value = "30000")]
        quic_idle_timeout_ms: u64,
        /// Tunnel worker count (0 = auto)
        #[arg(long = "tunnel-workers", default_value = "0")]
        tunnel_workers: usize,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Register { config, model, locale, name, jwt, accept_tos } => {
            register_device(&config, &model, &locale, name.as_deref(), jwt.as_deref(), accept_tos).await?;
        }
        Commands::Enroll { config, name, regen_key } => {
            enroll_device(&config, name.as_deref(), regen_key).await?;
        }
        Commands::Socks { bind, port, config, username, password, sni, dns, connect_port, keepalive, initial_packet_size, mtu, congestion_control, tcp_buffer_size, quic_idle_timeout_ms, tunnel_workers } => {
            run_socks_server(
                &bind,
                port,
                &config,
                username,
                password,
                &sni,
                dns,
                connect_port,
                keepalive,
                initial_packet_size,
                mtu,
                &congestion_control,
                tcp_buffer_size,
                quic_idle_timeout_ms,
                tunnel_workers,
            )
            .await?;
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

    let token = account.token.clone()
        .ok_or("No token in response")?;

    // Step 2: Generate ECDSA key pair
    let key_pair = crypto::generate_ec_key_pair()?;
    println!("Generated ECDSA key pair");

    // Step 3: Enroll MASQUE key
    let name = device_name.unwrap_or("usque-rs");
    let updated = client.enroll_key(
        &account.id,
        &token,
        &key_pair.public_key_der,
        Some(name),
    ).await?;
    println!("MASQUE key enrolled");

    // Step 4: Build and save config
    let endpoint_v4 = updated.config.peers.as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v4.clone());

    let endpoint_v6 = updated.config.peers.as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v6.clone());

    let endpoint_pub_key = updated.config.peers.as_ref()
        .and_then(|p| p.first())
        .map(|p| p.public_key.clone());

    let ipv4 = updated.config.interface_config.as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v4.clone());

    let ipv6 = updated.config.interface_config.as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v6.clone());

    let license = updated.account.license.clone()
        .unwrap_or_default();

    if endpoint_v4.as_deref().unwrap_or("").is_empty()
        && endpoint_v6.as_deref().unwrap_or("").is_empty()
    {
        return Err("No endpoint info in response".into());
    }

    let endpoint_pub_key = endpoint_pub_key
        .filter(|k| !k.trim().is_empty())
        .ok_or("No endpoint public key in response")?;

    if ipv4.as_deref().unwrap_or("").is_empty()
        && ipv6.as_deref().unwrap_or("").is_empty()
    {
        return Err("No interface addresses in response".into());
    }

    let cfg = config::Config {
        private_key: base64::engine::general_purpose::STANDARD
            .encode(&key_pair.private_key_der),
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
        let public_key_der = public_key.to_public_key_der()
            .map_err(|e| format!("Failed to encode public key: {}", e))?
            .to_vec();
        let private_key_der = cfg.get_private_key_der()?;
        (private_key_der, public_key_der)
    };

    // Call API to re-enroll
    let client = api::CloudflareClient::new();
    let updated = client.enroll_key(
        &cfg.id,
        &cfg.access_token,
        &public_key_der,
        device_name,
    ).await?;
    println!("MASQUE key enrolled");

    // Build updated config
    let endpoint_v4 = updated.config.peers.as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v4.clone());

    let endpoint_v6 = updated.config.peers.as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v6.clone());

    let endpoint_pub_key = updated.config.peers.as_ref()
        .and_then(|p| p.first())
        .map(|p| p.public_key.clone());

    let ipv4 = updated.config.interface_config.as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v4.clone());

    let ipv6 = updated.config.interface_config.as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v6.clone());

    let license = updated.account.license.clone()
        .unwrap_or(cfg.license.clone());

    let endpoint_v4 = endpoint_v4.unwrap_or(cfg.endpoint_v4.clone());
    let endpoint_v6 = endpoint_v6.unwrap_or(cfg.endpoint_v6.clone());
    if endpoint_v4.trim().is_empty() && endpoint_v6.trim().is_empty() {
        return Err("No endpoint info in response or existing config".into());
    }

    let endpoint_pub_key = endpoint_pub_key
        .unwrap_or(cfg.endpoint_pub_key.clone());
    if endpoint_pub_key.trim().is_empty() {
        return Err("No endpoint public key in response or existing config".into());
    }

    let ipv4 = ipv4.unwrap_or(cfg.ipv4.clone());
    let ipv6 = ipv6.unwrap_or(cfg.ipv6.clone());
    if ipv4.trim().is_empty() && ipv6.trim().is_empty() {
        return Err("No interface addresses in response or existing config".into());
    }

    let new_cfg = config::Config {
        private_key: base64::engine::general_purpose::STANDARD
            .encode(&private_key_der),
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

async fn run_socks_server(
    bind: &str,
    port: u16,
    config_path: &str,
    username: Option<String>,
    password: Option<String>,
    sni: &str,
    dns_servers: Vec<String>,
    connect_port: u16,
    keepalive: u64,
    initial_packet_size: u16,
    mtu: u16,
    congestion_control: &str,
    tcp_buffer_size: usize,
    quic_idle_timeout_ms: u64,
    tunnel_workers: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    let cfg = config::Config::load(config_path)?;
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
    let cc: tunnel::CongestionControl = congestion_control.parse()
        .map_err(|e: String| e)?;
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
        sni: sni.to_string(),
        endpoint_pub_key,
        ipv4: cfg.ipv4.clone(),
        ipv6: if cfg.ipv6.trim().is_empty() { None } else { Some(cfg.ipv6.clone()) },
        dns_servers: dns_addrs,
        keepalive,
        initial_packet_size,
        mtu,
        congestion_control: cc,
        tcp_buffer_size,
        quic_idle_timeout_ms,
    };

    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let worker_count = if tunnel_workers == 0 {
        available.min(4).max(1)
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
        _ => {
            proxy::Socks5Server::new(addr, tunnel_pool)
        }
    };

    println!("Starting SOCKS5 server on {}:{}", bind, port);
    server.run().await?;

    Ok(())
}
