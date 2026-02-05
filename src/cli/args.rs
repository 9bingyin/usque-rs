use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "usque-rs")]
#[command(about = "Cloudflare WARP client (MASQUE / WireGuard)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Register device with Cloudflare WARP
    Register {
        #[command(subcommand)]
        mode: RegisterMode,
    },
    /// Re-enroll device key (MASQUE mode)
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
    /// Start SOCKS5 proxy
    Socks {
        #[command(subcommand)]
        mode: SocksMode,
    },
}

#[derive(Subcommand)]
pub enum RegisterMode {
    /// Register for MASQUE tunnel mode
    Masque {
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
    /// Register for WireGuard tunnel mode
    Wg {
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
}

#[derive(Subcommand)]
pub enum SocksMode {
    /// MASQUE tunnel (HTTP/3 over QUIC)
    Masque {
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
        /// DNS servers to use (can be specified multiple times)
        #[arg(
            short,
            long,
            default_values_t = vec!["9.9.9.10".to_string(), "149.112.112.10".to_string()]
        )]
        dns: Vec<String>,
        /// MTU
        #[arg(short = 'm', long, default_value = "1280")]
        mtu: u16,
        /// SNI address for MASQUE connection
        #[arg(
            short,
            long = "sni-address",
            default_value = "consumer-masque.cloudflareclient.com"
        )]
        sni: String,
        /// MASQUE server port
        #[arg(short = 'P', long = "connect-port", default_value = "443")]
        connect_port: u16,
        /// Keepalive period in seconds
        #[arg(short = 'k', long = "keepalive-period", default_value = "30")]
        keepalive: u64,
        /// Initial QUIC packet size
        #[arg(short = 'i', long = "initial-packet-size", default_value = "1242")]
        initial_packet_size: u16,
    },
    /// WireGuard tunnel (UDP)
    Wg {
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,
        #[arg(short, long, default_value = "1080")]
        port: u16,
        #[arg(short, long, default_value = "warp.conf")]
        config: String,
        /// Username for SOCKS5 authentication (optional)
        #[arg(short, long)]
        username: Option<String>,
        /// Password for SOCKS5 authentication (required if username is set)
        #[arg(short = 'w', long)]
        password: Option<String>,
        /// DNS servers to use (can be specified multiple times)
        #[arg(
            short,
            long,
            default_values_t = vec!["9.9.9.10".to_string(), "149.112.112.10".to_string()]
        )]
        dns: Vec<String>,
        /// MTU
        #[arg(short = 'm', long, default_value = "1280")]
        mtu: u16,
    },
}
