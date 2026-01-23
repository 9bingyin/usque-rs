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
    },
    Socks {
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(short, long, default_value = "1080")]
        port: u16,
        #[arg(short, long, default_value = "config.json")]
        config: String,
        /// Username for SOCKS5 authentication (optional)
        #[arg(short, long)]
        username: Option<String>,
        /// Password for SOCKS5 authentication (required if username is set)
        #[arg(long)]
        password: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Register { config, model, locale } => {
            register_device(&config, &model, &locale).await?;
        }
        Commands::Socks { bind, port, config, username, password } => {
            run_socks_server(&bind, port, &config, username, password).await?;
        }
    }

    Ok(())
}

async fn register_device(
    config_path: &str,
    model: &str,
    locale: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;

    println!("Registering new device...");

    let client = api::CloudflareClient::new();

    // Step 1: Register with random WG key
    let account = client.register(model, locale, None).await?;
    println!("Account created: {}", account.id);

    let token = account.token.clone()
        .ok_or("No token in response")?;

    // Step 2: Generate ECDSA key pair
    let key_pair = crypto::generate_ec_key_pair()?;
    println!("Generated ECDSA key pair");

    // Step 3: Enroll MASQUE key
    let updated = client.enroll_key(
        &account.id,
        &token,
        &key_pair.public_key_der,
        Some("usque-rs"),
    ).await?;
    println!("MASQUE key enrolled");

    // Step 4: Build and save config
    let endpoint_v4 = updated.config.peers.as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v4.clone())
        .unwrap_or_default();

    let endpoint_v6 = updated.config.peers.as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v6.clone())
        .unwrap_or_default();

    let endpoint_pub_key = updated.config.peers.as_ref()
        .and_then(|p| p.first())
        .map(|p| p.public_key.clone())
        .unwrap_or_default();

    let ipv4 = updated.config.interface_config.as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v4.clone())
        .unwrap_or_default();

    let ipv6 = updated.config.interface_config.as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v6.clone())
        .unwrap_or_default();

    let license = updated.account.license.clone()
        .unwrap_or_default();

    let cfg = config::Config {
        private_key: base64::engine::general_purpose::STANDARD
            .encode(&key_pair.private_key_der),
        endpoint_v4,
        endpoint_v6,
        endpoint_pub_key,
        license,
        id: updated.id.clone(),
        access_token: token,
        ipv4,
        ipv6,
    };

    cfg.save(config_path)?;
    println!("Config saved to {}", config_path);

    Ok(())
}

async fn run_socks_server(
    bind: &str,
    port: u16,
    config_path: &str,
    username: Option<String>,
    password: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    let cfg = config::Config::load(config_path)?;
    println!("Config loaded from {}", config_path);

    let signing_key = cfg.get_signing_key()?;
    let (cert_der, key_der) = crypto::generate_self_signed_cert(&signing_key)?;
    println!("Generated self-signed certificate");

    let endpoint_ip = cfg.endpoint_v4
        .split(':')
        .next()
        .unwrap_or(&cfg.endpoint_v4);
    let endpoint: SocketAddr = format!("{}:443", endpoint_ip).parse()?;
    println!("Will connect to endpoint: {}", endpoint);

    let endpoint_pub_key = cfg.get_endpoint_pub_key_der().ok();

    let params = tunnel::ConnectionParams {
        endpoint,
        cert_der,
        key_der,
        sni: tunnel::quic::CONNECT_SNI.to_string(),
        endpoint_pub_key,
        ipv4: cfg.ipv4.clone(),
        ipv6: Some(cfg.ipv6.clone()),
    };

    let tunnel_manager = Arc::new(tunnel::TunnelManager::new(params));
    println!("Tunnel manager started (will auto-reconnect)");

    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;

    let server = match (username, password) {
        (Some(user), Some(pass)) => {
            println!("SOCKS5 authentication enabled");
            proxy::Socks5Server::with_auth(addr, tunnel_manager, user, pass)
        }
        (Some(_), None) => {
            return Err("Password is required when username is set".into());
        }
        _ => {
            proxy::Socks5Server::new(addr, tunnel_manager)
        }
    };

    println!("Starting SOCKS5 server on {}:{}", bind, port);
    server.run().await?;

    Ok(())
}
