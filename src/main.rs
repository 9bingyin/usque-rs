#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use usque_rs::app::{enroll, register, socks};
use usque_rs::cli::{Cli, Commands, RegisterMode, SocksMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

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
