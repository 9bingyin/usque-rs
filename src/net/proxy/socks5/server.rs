use super::{AuthConfig, Socks5Error, format_target_addr};
use super::{max_concurrent_connections, resolve, tcp, udp};
use crate::net::tunnel::manager::TunnelManagerPool;
use fast_socks5::Socks5Command;
use fast_socks5::server::Socks5ServerProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

pub struct Socks5Server {
    bind_addr: SocketAddr,
    manager_pool: Arc<TunnelManagerPool>,
    auth: Option<AuthConfig>,
}

impl Socks5Server {
    pub fn new(bind_addr: SocketAddr, manager_pool: Arc<TunnelManagerPool>) -> Self {
        Self {
            bind_addr,
            manager_pool,
            auth: None,
        }
    }

    pub fn with_auth(
        bind_addr: SocketAddr,
        manager_pool: Arc<TunnelManagerPool>,
        username: String,
        password: String,
    ) -> Self {
        Self {
            bind_addr,
            manager_pool,
            auth: Some(AuthConfig { username, password }),
        }
    }

    pub async fn run(&self) -> Result<(), Socks5Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        log::debug!("TCP listener bound on {}", self.bind_addr);
        log::debug!(
            "max concurrent connections: {}",
            max_concurrent_connections()
        );

        let max_conns = max_concurrent_connections();
        let semaphore = Arc::new(Semaphore::new(max_conns));

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("accepted connection from {}", addr);

            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    log::warn!("connection limit reached, rejected {}", addr);
                    continue;
                }
            };

            let manager_pool = self.manager_pool.clone();
            let local_addr = self.bind_addr;
            let auth = self.auth.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_client(stream, manager_pool, local_addr, auth, addr).await {
                    log::debug!("connection closed: {}", e);
                }
            });
        }
    }
}

async fn handle_client(
    socket: tokio::net::TcpStream,
    manager_pool: Arc<TunnelManagerPool>,
    local_addr: SocketAddr,
    auth: Option<AuthConfig>,
    client_addr: SocketAddr,
) -> Result<(), Socks5Error> {
    let manager = manager_pool.pick();
    // Use fast-socks5 for protocol handling with optional authentication
    let (proto, cmd, target_addr) = if let Some(auth_config) = auth {
        let username = auth_config.username;
        let password = auth_config.password;
        Socks5ServerProtocol::accept_password_auth(socket, move |user, pass| {
            user == username && pass == password
        })
        .await?
        .0
    } else {
        Socks5ServerProtocol::accept_no_auth(socket).await?
    }
    .read_command()
    .await?;

    match cmd {
        Socks5Command::TCPConnect => {
            log::info!("CONNECT to {}", format_target_addr(&target_addr));
            tcp::handle_tcp_connect(proto, manager, &target_addr, client_addr).await
        }
        Socks5Command::TCPBind => {
            log::info!("BIND to {}", format_target_addr(&target_addr));
            let resolved_addr = resolve::resolve_target_addr(&manager, &target_addr).await?;
            tcp::handle_tcp_bind(proto, manager, local_addr, resolved_addr).await
        }
        Socks5Command::UDPAssociate => {
            log::info!("UDP ASSOCIATE from {}", client_addr);
            udp::handle_udp_associate(proto, manager, local_addr).await
        }
    }
}
