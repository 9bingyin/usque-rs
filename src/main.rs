#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use usque_rs::app::{enroll, register, socks};
use usque_rs::cli::{Cli, Commands, LogLevel, RegisterMode, SocksMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    init_logger(cli.log, cli.disable_color, cli.timestamp);

    match cli.command {
        Commands::Register { mode } => match mode {
            RegisterMode::Masque {
                config,
                model,
                locale,
                name,
                jwt,
                accept_tos,
            } => {
                register::register_device(
                    &config,
                    &model,
                    &locale,
                    name.as_deref(),
                    jwt.as_deref(),
                    accept_tos,
                )
                .await?;
            }
            RegisterMode::Wg {
                config,
                model,
                locale,
                jwt,
                accept_tos,
            } => {
                register::register_wg_device(&config, &model, &locale, jwt.as_deref(), accept_tos)
                    .await?;
            }
        },
        Commands::Enroll {
            config,
            name,
            regen_key,
        } => {
            enroll::enroll_device(&config, name.as_deref(), regen_key).await?;
        }
        Commands::Socks { mode } => match mode {
            SocksMode::Masque {
                bind,
                port,
                config,
                username,
                password,
                dns,
                mtu,
                sni,
                connect_port,
                keepalive,
                initial_packet_size,
            } => {
                let options = socks::SocksServerOptions {
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
                socks::run_socks_server(options).await?;
            }
            SocksMode::Wg {
                bind,
                port,
                config,
                username,
                password,
                dns,
                mtu,
            } => {
                let options = socks::SocksServerWgOptions {
                    bind,
                    port,
                    config_path: config,
                    username,
                    password,
                    dns_servers: dns,
                    mtu,
                };
                socks::run_socks_server_wg(options).await?;
            }
        },
    }

    Ok(())
}

fn init_logger(level: LogLevel, disable_color: bool, full_timestamp: bool) {
    use colored::Colorize;
    use colored::control::set_override;
    use env_logger::Builder;
    use log::{Level, LevelFilter};
    use std::io::Write;
    use std::sync::OnceLock;
    use std::time::Instant;

    static START_TIME: OnceLock<Instant> = OnceLock::new();

    let filter = match level {
        LogLevel::Silent => LevelFilter::Off,
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warning => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Trace,
    };

    if filter == LevelFilter::Off {
        Builder::new().filter_level(LevelFilter::Off).init();
        return;
    }

    set_override(!disable_color);
    START_TIME.get_or_init(Instant::now);

    Builder::new()
        .filter_level(filter)
        .format(move |buf, record| {
            let level = record.level();
            let level_str = match level {
                Level::Error => "ERROR".red().bold().to_string(),
                Level::Warn => "WARN".yellow().bold().to_string(),
                Level::Info => "INFO".cyan().bold().to_string(),
                Level::Debug => "DEBUG".white().to_string(),
                Level::Trace => "TRACE".white().dimmed().to_string(),
            };

            if full_timestamp {
                let now = chrono::Local::now();
                writeln!(
                    buf,
                    "{} {} {}",
                    now.format("%Y-%m-%d %H:%M:%S%.3f %z"),
                    level_str,
                    record.args()
                )
            } else {
                let elapsed = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);
                writeln!(buf, "{}[{:04}] {}", level_str, elapsed, record.args())
            }
        })
        .init();
}
