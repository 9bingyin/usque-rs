use crate::core::config::{Config, WgConfig};
use crate::core::crypto;
use crate::net::{proxy, tunnel};
use std::net::SocketAddr;

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            log::error!("failed to install Ctrl+C handler: {}", e);
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                log::error!("failed to install SIGTERM handler: {}", e);
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

pub struct SocksServerOptions {
    pub bind: String,
    pub port: u16,
    pub config_path: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub sni: String,
    pub dns_servers: Vec<String>,
    pub connect_port: u16,
    pub keepalive: u64,
    pub initial_packet_size: u16,
    pub mtu: u16,
}

pub struct SocksServerWgOptions {
    pub bind: String,
    pub port: u16,
    pub config_path: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub dns_servers: Vec<String>,
    pub mtu: u16,
}

pub async fn run_socks_server(
    options: SocksServerOptions,
) -> Result<(), Box<dyn std::error::Error>> {
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
        .unwrap_or(256 * 1024);

    let quic_idle_timeout_ms: u64 = std::env::var("USQUE_QUIC_IDLE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90000);

    let tunnel_workers: usize = std::env::var("USQUE_TUNNEL_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let perf_enabled = env_bool("USQUE_PERF", false);
    let perf_interval_secs = env_u64("USQUE_PERF_INTERVAL_SECS", 5);
    let manager_tunables = tunnel::ManagerTunables::from_env();
    let stack_tunables = tunnel::StackTunables::from_env();

    let cfg = Config::load(&config_path)?;
    log::debug!("config loaded from {}", config_path);

    let signing_key = cfg.get_signing_key()?;
    let (cert_der, key_der) = crypto::generate_self_signed_cert(&signing_key)?;
    log::debug!("self-signed certificate generated");

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
    log::debug!("endpoint: {}, SNI: {}", endpoint, sni);

    let endpoint_pub_key = if cfg.endpoint_pub_key.trim().is_empty() {
        return Err("Endpoint public key is required for security".into());
    } else {
        Some(cfg.get_endpoint_pub_key_der()?)
    };

    // Parse DNS servers
    let dns_addrs = tunnel::dns::parse_dns_servers(&dns_servers)?;

    // Parse congestion control algorithm
    let cc: tunnel::CongestionControl = congestion_control.parse().map_err(|e: String| e)?;
    log::debug!("congestion control: {}", cc);

    let keepalive_ms = keepalive.saturating_mul(1000);
    if keepalive_ms >= quic_idle_timeout_ms {
        log::warn!(
            "keepalive period {}ms >= QUIC idle timeout {}ms; connection may time out",
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
        perf_enabled,
        perf_interval_secs,
        manager_tunables: manager_tunables.clone(),
        stack_tunables: stack_tunables.clone(),
    };

    log::info!(
        "tunables: tcp_buf={}KB pending_tx={}KB pending_rx={}KB cmd_q={} udp_q={} in_q={} stack_ingress={} targeted_tcp={} masque_io_q={} masque_send_batch={} tcp_ack_delay_ms={} wg_udp_recvbuf={}KB wg_udp_sendbuf={}KB",
        tcp_buffer_size / 1024,
        manager_tunables.max_pending_data / 1024,
        manager_tunables.max_pending_to_client / 1024,
        manager_tunables.cmd_channel_capacity,
        manager_tunables.udp_data_channel_capacity,
        manager_tunables.incoming_dgram_capacity,
        manager_tunables.stack_ingress_budget,
        manager_tunables.targeted_tcp_sweep_budget,
        manager_tunables.masque_io_channel_capacity,
        manager_tunables.masque_send_batch_size,
        stack_tunables
            .tcp_ack_delay
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|| "disabled".to_string()),
        manager_tunables.wg_udp_recv_buffer_size / 1024,
        manager_tunables.wg_udp_send_buffer_size / 1024,
    );

    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let worker_count = if tunnel_workers == 0 {
        available.clamp(1, 4)
    } else {
        tunnel_workers.max(1)
    };

    let tunnel_pool = Arc::new(tunnel::TunnelManagerPool::new(params, worker_count));
    log::debug!("tunnel pool started (workers: {})", worker_count);

    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;

    let has_auth = username.is_some();
    let server = match (username, password) {
        (Some(user), Some(pass)) => proxy::Socks5Server::with_auth(addr, tunnel_pool, user, pass),
        (Some(_), None) => {
            return Err("Password is required when username is set".into());
        }
        _ => proxy::Socks5Server::new(addr, tunnel_pool),
    };

    log::info!("starting SOCKS5 proxy on {} (masque mode)", addr);
    if has_auth {
        log::info!("SOCKS5 authentication: enabled");
    } else {
        log::info!("SOCKS5 authentication: disabled");
    }
    log::info!("DNS servers: {}", dns_servers.join(", "));

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                log::error!("server error: {}", e);
            }
        }
        _ = shutdown_signal() => {
            log::info!("shutdown signal received, exiting");
        }
    }

    Ok(())
}

pub async fn run_socks_server_wg(
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
        .unwrap_or(256 * 1024);

    let tunnel_workers: usize = std::env::var("USQUE_TUNNEL_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let perf_enabled = env_bool("USQUE_PERF", false);
    let perf_interval_secs = env_u64("USQUE_PERF_INTERVAL_SECS", 5);
    let manager_tunables = tunnel::ManagerTunables::from_env();
    let stack_tunables = tunnel::StackTunables::from_env();

    let wg_cfg = WgConfig::load(&config_path)?;
    log::debug!("config loaded from {}", config_path);

    let private_key = wg_cfg.get_private_key_bytes()?;
    let peer_public_key = wg_cfg.get_peer_public_key_bytes()?;
    let client_id = wg_cfg.get_client_id_bytes()?;
    let mut endpoint = wg_cfg.get_endpoint_addr()?;
    if endpoint.port() == 0 {
        log::warn!("endpoint port is 0, using default WG port 2408");
        endpoint.set_port(2408);
    }
    let keepalive = wg_cfg.keepalive as u64;

    log::debug!("endpoint: {}", endpoint);
    log::trace!(
        "client_id: [{}, {}, {}]",
        client_id[0],
        client_id[1],
        client_id[2]
    );

    // Use DNS from config if available, otherwise use CLI-provided servers
    let (dns_addrs, dns_display) = if !wg_cfg.dns.trim().is_empty() {
        let addrs = tunnel::dns::parse_dns_servers(std::slice::from_ref(&wg_cfg.dns))?;
        (addrs, wg_cfg.dns.clone())
    } else {
        let addrs = tunnel::dns::parse_dns_servers(&dns_servers)?;
        (addrs, dns_servers.join(", "))
    };

    let wg_mtu = if mtu == 0 { wg_cfg.mtu } else { mtu };

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
        perf_enabled,
        perf_interval_secs,
        manager_tunables: manager_tunables.clone(),
        stack_tunables: stack_tunables.clone(),
    };

    log::info!(
        "tunables: tcp_buf={}KB pending_tx={}KB pending_rx={}KB cmd_q={} udp_q={} in_q={} stack_ingress={} targeted_tcp={} masque_io_q={} masque_send_batch={} tcp_ack_delay_ms={} wg_udp_recvbuf={}KB wg_udp_sendbuf={}KB",
        tcp_buffer_size / 1024,
        manager_tunables.max_pending_data / 1024,
        manager_tunables.max_pending_to_client / 1024,
        manager_tunables.cmd_channel_capacity,
        manager_tunables.udp_data_channel_capacity,
        manager_tunables.incoming_dgram_capacity,
        manager_tunables.stack_ingress_budget,
        manager_tunables.targeted_tcp_sweep_budget,
        manager_tunables.masque_io_channel_capacity,
        manager_tunables.masque_send_batch_size,
        stack_tunables
            .tcp_ack_delay
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|| "disabled".to_string()),
        manager_tunables.wg_udp_recv_buffer_size / 1024,
        manager_tunables.wg_udp_send_buffer_size / 1024,
    );

    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let worker_count = if tunnel_workers == 0 {
        available.clamp(1, 4)
    } else {
        tunnel_workers.max(1)
    };

    let tunnel_pool = Arc::new(tunnel::TunnelManagerPool::new(params, worker_count));
    log::debug!("tunnel pool started (workers: {})", worker_count);

    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;

    let has_auth = username.is_some();
    let server = match (username, password) {
        (Some(user), Some(pass)) => proxy::Socks5Server::with_auth(addr, tunnel_pool, user, pass),
        (Some(_), None) => {
            return Err("Password is required when username is set".into());
        }
        _ => proxy::Socks5Server::new(addr, tunnel_pool),
    };

    log::info!("starting SOCKS5 proxy on {} (wireguard mode)", addr);
    if has_auth {
        log::info!("SOCKS5 authentication: enabled");
    } else {
        log::info!("SOCKS5 authentication: disabled");
    }
    log::info!("DNS servers: {}", dns_display);

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                log::error!("server error: {}", e);
            }
        }
        _ = shutdown_signal() => {
            log::info!("shutdown signal received, exiting");
        }
    }

    Ok(())
}
