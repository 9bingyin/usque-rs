use crate::tunnel::manager::{ManagerCommand, SocketChannels, TcpSocketState, TunnelManager};
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{parse_udp_request, new_udp_header, Socks5Command};
use smoltcp::iface::SocketHandle;
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

static LOCAL_PORT_COUNTER: AtomicU16 = AtomicU16::new(0);

const PORT_RANGE_START: u16 = 49152;
const PORT_RANGE_SIZE: u16 = 16384; // 65536 - 49152 (RFC 6335)
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn get_local_port() -> u16 {
    let offset = LOCAL_PORT_COUNTER.fetch_add(1, Ordering::Relaxed) % PORT_RANGE_SIZE;
    PORT_RANGE_START + offset
}

async fn wait_for_connection(
    manager: &TunnelManager,
    handle: SocketHandle,
) -> Result<(), Socks5Error> {
    let start = Instant::now();

    loop {
        let state = manager.get_socket_state(handle).await;

        match state {
            TcpSocketState::Established => return Ok(()),
            TcpSocketState::Closed => {
                return Err(Socks5Error::ConnectionFailed("Connection closed".into()));
            }
            TcpSocketState::Connecting => {
                if start.elapsed() > CONNECT_TIMEOUT {
                    return Err(Socks5Error::Timeout);
                }
                let elapsed = start.elapsed().as_millis() as u64;
                let wait = if elapsed < 1000 { 10 } else { 50 };
                tokio::time::sleep(Duration::from_millis(wait)).await;
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum Socks5Error {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("timeout")]
    Timeout,
    #[error("channel error: {0}")]
    ChannelError(String),
    #[error("socks error: {0}")]
    SocksError(#[from] fast_socks5::SocksError),
    #[error("socks server error: {0}")]
    SocksServerError(#[from] fast_socks5::server::SocksServerError),
}

/// Authentication configuration for SOCKS5 server
#[derive(Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

pub struct Socks5Server {
    bind_addr: SocketAddr,
    manager: Arc<TunnelManager>,
    auth: Option<AuthConfig>,
}

impl Socks5Server {
    pub fn new(bind_addr: SocketAddr, manager: Arc<TunnelManager>) -> Self {
        Self { bind_addr, manager, auth: None }
    }

    pub fn with_auth(bind_addr: SocketAddr, manager: Arc<TunnelManager>, username: String, password: String) -> Self {
        Self {
            bind_addr,
            manager,
            auth: Some(AuthConfig { username, password }),
        }
    }

    pub async fn run(&self) -> Result<(), Socks5Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("SOCKS5 server listening on {}", self.bind_addr);
        if self.auth.is_some() {
            log::info!("SOCKS5 authentication enabled");
        }

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("New connection from {}", addr);

            let manager = self.manager.clone();
            let local_addr = self.bind_addr;
            let auth = self.auth.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, manager, local_addr, auth).await {
                    log::error!("Error handling client {}: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_client(
    socket: TcpStream,
    manager: Arc<TunnelManager>,
    local_addr: SocketAddr,
    auth: Option<AuthConfig>,
) -> Result<(), Socks5Error> {
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

    // Resolve DNS through tunnel if needed
    let resolved_addr = resolve_target_addr(&manager, &target_addr).await?;

    match cmd {
        Socks5Command::TCPConnect => {
            handle_tcp_connect(proto, manager, resolved_addr).await
        }
        Socks5Command::TCPBind => {
            handle_tcp_bind(proto, manager, local_addr, resolved_addr).await
        }
        Socks5Command::UDPAssociate => {
            handle_udp_associate(proto, manager, local_addr).await
        }
    }
}

async fn resolve_target_addr(
    manager: &TunnelManager,
    target: &TargetAddr,
) -> Result<(IpAddress, u16), Socks5Error> {
    match target {
        TargetAddr::Ip(addr) => {
            let ip = match addr.ip() {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3]))
                }
                IpAddr::V6(v6) => {
                    let s = v6.segments();
                    IpAddress::Ipv6(Ipv6Address::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]))
                }
            };
            Ok((ip, addr.port()))
        }
        TargetAddr::Domain(domain, port) => {
            log::debug!("Resolving {} through tunnel", domain);
            let ip = manager.resolve(domain, false).await
                .map_err(|e| Socks5Error::ProtocolError(format!("DNS resolution failed: {:?}", e)))?;
            log::debug!("Resolved {} -> {:?}", domain, ip);
            Ok((ip, *port))
        }
    }
}

async fn handle_tcp_connect<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, fast_socks5::server::states::CommandRead>,
    manager: Arc<TunnelManager>,
    target: (IpAddress, u16),
) -> Result<(), Socks5Error> {
    let (remote_ip, remote_port) = target;
    log::debug!("TCP CONNECT to {:?}:{}", remote_ip, remote_port);

    // Create connection through tunnel
    let local_port = get_local_port();
    let channels = manager
        .connect(remote_ip, remote_port, local_port)
        .await
        .map_err(Socks5Error::ConnectionFailed)?;

    // Wait for connection with adaptive polling
    let handle = channels.handle;
    if let Err(e) = wait_for_connection(&manager, handle).await {
        manager.close(handle).await;
        return Err(e);
    }

    // Send success reply
    let reply_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
    let mut stream = proto.reply_success(reply_addr).await?;

    // Forward data
    let result = forward_tcp_data(&mut stream, channels).await;

    // Cleanup
    manager.close(handle).await;
    result
}

/// Handle SOCKS5 BIND command (RFC 1928)
/// BIND is used for protocols that require the server to accept incoming connections
/// (e.g., FTP active mode). The flow is:
/// 1. Server binds a local port and sends first reply with bind address
/// 2. Server waits for incoming connection from target
/// 3. Server sends second reply when connection is established
/// 4. Data is forwarded bidirectionally
async fn handle_tcp_bind<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, fast_socks5::server::states::CommandRead>,
    _manager: Arc<TunnelManager>,
    local_addr: SocketAddr,
    _target: (IpAddress, u16),
) -> Result<(), Socks5Error> {
    log::debug!("TCP BIND requested");

    // Bind a local TCP listener
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let bind_addr = listener.local_addr()?;
    log::debug!("TCP BIND: listening on {}", bind_addr);

    // First reply: tell client the bind address
    let reply_addr = SocketAddr::new(local_addr.ip(), bind_addr.port());
    let mut client_stream = proto.reply_success(reply_addr).await?;

    // Wait for incoming connection with timeout
    let accept_result = tokio::time::timeout(
        Duration::from_secs(60),
        listener.accept()
    ).await;

    let (incoming_stream, peer_addr) = match accept_result {
        Ok(Ok((stream, addr))) => (stream, addr),
        Ok(Err(e)) => {
            log::error!("TCP BIND: accept error: {}", e);
            return Err(Socks5Error::IoError(e));
        }
        Err(_) => {
            log::debug!("TCP BIND: timeout waiting for connection");
            return Err(Socks5Error::Timeout);
        }
    };

    log::debug!("TCP BIND: accepted connection from {}", peer_addr);

    // Second reply: tell client the peer address (using same format as first reply)
    // Note: In standard SOCKS5, we should send a second reply here, but fast-socks5
    // doesn't provide a direct way to do this. We'll write the reply manually.
    let second_reply = build_bind_reply(peer_addr);
    client_stream.write_all(&second_reply).await?;

    // Forward data between client and incoming connection
    forward_bind_data(client_stream, incoming_stream).await
}

fn build_bind_reply(addr: SocketAddr) -> Vec<u8> {
    let mut reply = vec![0x05, 0x00, 0x00]; // VER, REP (success), RSV

    match addr {
        SocketAddr::V4(v4) => {
            reply.push(0x01); // ATYP: IPv4
            reply.extend_from_slice(&v4.ip().octets());
            reply.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            reply.push(0x04); // ATYP: IPv6
            reply.extend_from_slice(&v6.ip().octets());
            reply.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    reply
}

async fn forward_bind_data<C, I>(mut client: C, mut incoming: I) -> Result<(), Socks5Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_reader, mut client_writer) = tokio::io::split(&mut client);
    let (mut incoming_reader, mut incoming_writer) = tokio::io::split(&mut incoming);

    let client_to_incoming = async {
        let mut buf = [0u8; 65535];
        loop {
            match client_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if incoming_writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let incoming_to_client = async {
        let mut buf = [0u8; 65535];
        loop {
            match incoming_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if client_writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = client_to_incoming => {}
        _ = incoming_to_client => {}
    }

    Ok(())
}

async fn forward_tcp_data<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    mut channels: SocketChannels,
) -> Result<(), Socks5Error> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut client_buf = [0u8; 65535];

    loop {
        tokio::select! {
            result = channels.from_stack.recv() => {
                match result {
                    Some(data) => {
                        if let Err(e) = writer.write_all(&data).await {
                            log::debug!("Error writing to client: {}", e);
                            break;
                        }
                    }
                    None => {
                        log::debug!("Tunnel channel closed");
                        break;
                    }
                }
            }

            result = reader.read(&mut client_buf) => {
                match result {
                    Ok(0) => {
                        log::debug!("Client closed connection");
                        break;
                    }
                    Ok(n) => {
                        if channels.to_stack.send(client_buf[..n].to_vec()).await.is_err() {
                            log::debug!("Tunnel channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        log::debug!("Error reading from client: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_udp_associate<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    proto: Socks5ServerProtocol<T, fast_socks5::server::states::CommandRead>,
    manager: Arc<TunnelManager>,
    local_addr: SocketAddr,
) -> Result<(), Socks5Error> {
    // Bind UDP socket for client
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let udp_addr = udp_socket.local_addr()?;
    log::debug!("UDP ASSOCIATE: relay socket bound to {}", udp_addr);

    // Register UDP session with manager
    let local_port = get_local_port();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    manager.cmd_sender()
        .send(ManagerCommand::UdpRegister {
            local_port,
            response: response_tx,
        })
        .await
        .map_err(|_| Socks5Error::ChannelError("Failed to register UDP session".into()))?;

    let mut from_tunnel = response_rx
        .await
        .map_err(|_| Socks5Error::ChannelError("Failed to get UDP receiver".into()))?
        .map_err(Socks5Error::ConnectionFailed)?;

    // Send success reply with UDP relay address
    let reply_ip = local_addr.ip();
    let reply_addr = SocketAddr::new(reply_ip, udp_addr.port());
    let mut tcp_stream = proto.reply_success(reply_addr).await?;

    // Forward UDP data
    let cmd_sender = manager.cmd_sender();
    let result = forward_udp_data(
        &mut tcp_stream,
        udp_socket,
        &mut from_tunnel,
        cmd_sender,
        local_port,
        &manager,
    ).await;

    // Cleanup
    if let Err(e) = manager.cmd_sender()
        .send(ManagerCommand::UdpUnregister { local_port })
        .await
    {
        log::debug!("Failed to unregister UDP session: {}", e);
    }

    result
}

async fn forward_udp_data<T: AsyncRead + AsyncWrite + Unpin>(
    tcp_stream: &mut T,
    udp_socket: UdpSocket,
    from_tunnel: &mut tokio::sync::mpsc::Receiver<(IpAddress, u16, Vec<u8>)>,
    cmd_sender: tokio::sync::mpsc::Sender<ManagerCommand>,
    local_port: u16,
    manager: &TunnelManager,
) -> Result<(), Socks5Error> {
    let mut buf = [0u8; 65535];
    let mut tcp_buf = [0u8; 1];
    let mut client_addr: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            // Check if TCP control connection is closed
            result = tcp_stream.read(&mut tcp_buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        log::debug!("UDP ASSOCIATE: TCP control connection closed");
                        break;
                    }
                    Ok(_) => {}
                }
            }

            // Receive UDP from client, forward to tunnel
            result = udp_socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        client_addr = Some(addr);
                        if let Ok((frag, target, payload)) = parse_udp_request(&buf[..len]).await {
                            if frag != 0 {
                                log::debug!("UDP fragmentation not supported");
                                continue;
                            }
                            if let Some((remote_ip, remote_port)) = target_addr_to_ip(&target, manager).await
                                && let Err(e) = cmd_sender.send(ManagerCommand::UdpSend {
                                    remote_ip,
                                    remote_port,
                                    local_port,
                                    data: payload.to_vec(),
                                }).await
                            {
                                log::debug!("Failed to send UDP data to tunnel: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("UDP recv error: {}", e);
                    }
                }
            }

            // Receive UDP from tunnel, forward to client
            Some((remote_ip, remote_port, data)) = from_tunnel.recv() => {
                if let Some(addr) = client_addr
                    && let Ok(packet) = build_udp_response(remote_ip, remote_port, &data)
                    && let Err(e) = udp_socket.send_to(&packet, addr).await
                {
                    log::debug!("Failed to send UDP response to client: {}", e);
                }
            }
        }
    }

    Ok(())
}

async fn target_addr_to_ip(target: &TargetAddr, manager: &TunnelManager) -> Option<(IpAddress, u16)> {
    match target {
        TargetAddr::Ip(addr) => {
            let ip = match addr.ip() {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3]))
                }
                IpAddr::V6(v6) => {
                    let s = v6.segments();
                    IpAddress::Ipv6(Ipv6Address::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]))
                }
            };
            Some((ip, addr.port()))
        }
        TargetAddr::Domain(domain, port) => {
            match manager.resolve(domain, false).await {
                Ok(ip) => Some((ip, *port)),
                Err(e) => {
                    log::warn!("UDP DNS resolution failed for {}: {:?}", domain, e);
                    None
                }
            }
        }
    }
}

fn build_udp_response(remote_ip: IpAddress, remote_port: u16, data: &[u8]) -> Result<Vec<u8>, Socks5Error> {
    let addr = match remote_ip {
        IpAddress::Ipv4(v4) => {
            let bytes: [u8; 4] = [v4.octets()[0], v4.octets()[1], v4.octets()[2], v4.octets()[3]];
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(bytes)), remote_port)
        }
        IpAddress::Ipv6(v6) => {
            let bytes = v6.octets();
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(bytes)), remote_port)
        }
    };

    let mut packet = new_udp_header(addr)
        .map_err(|e| Socks5Error::ProtocolError(format!("Failed to build UDP header: {:?}", e)))?;
    packet.extend_from_slice(data);
    Ok(packet)
}
