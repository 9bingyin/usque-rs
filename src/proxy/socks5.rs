use crate::tunnel::manager::{ManagerCommand, ManagerError, SocketChannels, TcpSocketState, TunnelManager, TunnelManagerPool};
use bytes::{Bytes, BytesMut};
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{parse_udp_request, new_udp_header, ReplyError, Socks5Command};
use smoltcp::iface::SocketHandle;
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

static LOCAL_PORT_COUNTER: AtomicU16 = AtomicU16::new(0);

const PORT_RANGE_START: u16 = 49152;
const PORT_RANGE_SIZE: u16 = 16384; // 65536 - 49152 (RFC 6335)
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 1024;
const TCP_READ_BUFFER_SIZE: usize = 64 * 1024;
const UDP_FRAG_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_FRAG_MAX_COUNT: usize = 128;

struct FragBuffer {
    fragments: Vec<Option<Bytes>>,
    highest_seq: u8,
    end_seq: Option<u8>,
    last_update: Instant,
}

impl FragBuffer {
    fn new(now: Instant) -> Self {
        Self {
            fragments: vec![None; UDP_FRAG_MAX_COUNT],
            highest_seq: 0,
            end_seq: None,
            last_update: now,
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_update) > UDP_FRAG_TIMEOUT
    }

    fn reset(&mut self, now: Instant) {
        self.fragments.fill(None);
        self.highest_seq = 0;
        self.end_seq = None;
        self.last_update = now;
    }

    fn insert(&mut self, seq: u8, is_last: bool, data: Bytes, now: Instant) -> Option<Bytes> {
        if seq == 0 || seq as usize >= self.fragments.len() {
            return None;
        }

        if let Some(end_seq) = self.end_seq {
            if seq > end_seq {
                self.reset(now);
            }
        }

        if seq < self.highest_seq {
            self.reset(now);
        }

        self.last_update = now;
        if self.fragments[seq as usize].is_none() {
            self.fragments[seq as usize] = Some(data);
        }

        if seq > self.highest_seq {
            self.highest_seq = seq;
        }

        if is_last {
            self.end_seq = Some(seq);
        }

        let end_seq = self.end_seq?;
        for idx in 1..=end_seq {
            if self.fragments[idx as usize].is_none() {
                return None;
            }
        }

        let total_len: usize = (1..=end_seq)
            .map(|idx| self.fragments[idx as usize].as_ref().map(|b| b.len()).unwrap_or(0))
            .sum();
        let mut merged = BytesMut::with_capacity(total_len);
        for idx in 1..=end_seq {
            if let Some(chunk) = self.fragments[idx as usize].as_ref() {
                merged.extend_from_slice(chunk);
            }
        }
        Some(merged.freeze())
    }
}

fn get_local_port() -> u16 {
    let offset = LOCAL_PORT_COUNTER.fetch_add(1, Ordering::Relaxed) % PORT_RANGE_SIZE;
    PORT_RANGE_START + offset
}

fn max_concurrent_connections() -> usize {
    std::env::var("USQUE_MAX_CONNECTIONS")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .filter(|val| *val > 0)
        .unwrap_or(DEFAULT_MAX_CONCURRENT_CONNECTIONS)
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
    #[error("tunnel error: {0}")]
    TunnelError(#[from] ManagerError),
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
    manager_pool: Arc<TunnelManagerPool>,
    auth: Option<AuthConfig>,
}

impl Socks5Server {
    pub fn new(bind_addr: SocketAddr, manager_pool: Arc<TunnelManagerPool>) -> Self {
        Self { bind_addr, manager_pool, auth: None }
    }

    pub fn with_auth(bind_addr: SocketAddr, manager_pool: Arc<TunnelManagerPool>, username: String, password: String) -> Self {
        Self {
            bind_addr,
            manager_pool,
            auth: Some(AuthConfig { username, password }),
        }
    }

    pub async fn run(&self) -> Result<(), Socks5Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("SOCKS5 server listening on {}", self.bind_addr);
        if self.auth.is_some() {
            log::info!("SOCKS5 authentication enabled");
        }

        let max_conns = max_concurrent_connections();
        let semaphore = Arc::new(Semaphore::new(max_conns));

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("New connection from {}", addr);

            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    log::warn!(
                        "Connection limit reached ({}), dropping {}",
                        max_conns,
                        addr
                    );
                    continue;
                }
            };

            let manager_pool = self.manager_pool.clone();
            let local_addr = self.bind_addr;
            let auth = self.auth.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_client(stream, manager_pool, local_addr, auth).await {
                    log::error!("Error handling client {}: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_client(
    socket: TcpStream,
    manager_pool: Arc<TunnelManagerPool>,
    local_addr: SocketAddr,
    auth: Option<AuthConfig>,
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
    let channels = match manager.connect(remote_ip, remote_port, local_port).await {
        Ok(channels) => channels,
        Err(err) => {
            let reply = map_manager_error_to_reply(&err);
            if let Err(rep_err) = proto.reply_error(&reply).await {
                log::debug!("Failed to send connect error reply: {}", rep_err);
            }
            return Err(Socks5Error::TunnelError(err));
        }
    };

    // Wait for connection with adaptive polling
    let handle = channels.handle;
    if let Err(e) = wait_for_connection(&manager, handle).await {
        let reply = map_connect_error_to_reply(&e);
        if let Err(rep_err) = proto.reply_error(&reply).await {
            log::debug!("Failed to send connect error reply: {}", rep_err);
        }
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
    let mut client_buf = BytesMut::with_capacity(TCP_READ_BUFFER_SIZE);

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
                        log::trace!("Tunnel channel closed");
                        break;
                    }
                }
            }

            result = reader.read_buf(&mut client_buf) => {
                match result {
                    Ok(0) => {
                        log::debug!("Client closed connection");
                        break;
                    }
                    Ok(n) => {
                        let data = client_buf.split_to(n).freeze();
                        if channels.to_stack.send(data).await.is_err() {
                            log::trace!("Tunnel channel closed");
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
        .map_err(|_| Socks5Error::ChannelError("Failed to get UDP receiver".into()))??;

    // Send success reply with UDP relay address
    let reply_ip = local_addr.ip();
    let reply_addr = SocketAddr::new(reply_ip, udp_addr.port());
    let mut tcp_stream = proto.reply_success(reply_addr).await?;

    // Forward UDP data
    let result = forward_udp_data(
        &mut tcp_stream,
        udp_socket,
        &mut from_tunnel,
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
    from_tunnel: &mut tokio::sync::mpsc::Receiver<(IpAddress, u16, Bytes)>,
    local_port: u16,
    manager: &TunnelManager,
) -> Result<(), Socks5Error> {
    let mut buf = [0u8; 65535];
    let mut tcp_buf = [0u8; 1];
    let mut client_addr: Option<SocketAddr> = None;
    let mut frag_buffers: HashMap<TargetAddr, FragBuffer> = HashMap::new();

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
                            cleanup_fragments(&mut frag_buffers);

                            if frag == 0 {
                                frag_buffers.remove(&target);
                                if let Some((remote_ip, remote_port)) = target_addr_to_ip(&target, manager).await {
                                    let data = Bytes::copy_from_slice(payload);
                                    if let Err(e) = manager.send_udp(remote_ip, remote_port, local_port, data).await {
                                        log::debug!("Failed to send UDP data to tunnel: {}", e);
                                    }
                                }
                                continue;
                            }

                            let is_last = (frag & 0x80) != 0;
                            let seq = frag & 0x7f;
                            if seq == 0 {
                                log::debug!("Invalid UDP fragment sequence 0");
                                continue;
                            }

                            let now = Instant::now();
                            let buffer = frag_buffers
                                .entry(target.clone())
                                .or_insert_with(|| FragBuffer::new(now));

                            if buffer.is_expired(now) {
                                buffer.reset(now);
                            }

                            if let Some(assembled) = buffer.insert(seq, is_last, Bytes::copy_from_slice(payload), now) {
                                frag_buffers.remove(&target);
                                if let Some((remote_ip, remote_port)) = target_addr_to_ip(&target, manager).await {
                                    if let Err(e) = manager.send_udp(remote_ip, remote_port, local_port, assembled).await {
                                        log::debug!("Failed to send UDP data to tunnel: {}", e);
                                    }
                                }
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
                    && let Ok(packet) = build_udp_response(remote_ip, remote_port, data.as_ref())
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

fn cleanup_fragments(frag_buffers: &mut HashMap<TargetAddr, FragBuffer>) {
    let now = Instant::now();
    frag_buffers.retain(|_, buffer| !buffer.is_expired(now));
}

fn map_manager_error_to_reply(err: &ManagerError) -> ReplyError {
    match err {
        ManagerError::NotConnected => ReplyError::GeneralFailure,
        ManagerError::Dns(_) => ReplyError::HostUnreachable,
        ManagerError::Stack(_) => ReplyError::GeneralFailure,
        ManagerError::ChannelClosed => ReplyError::GeneralFailure,
        ManagerError::ResponseChannelClosed => ReplyError::GeneralFailure,
    }
}

fn map_connect_error_to_reply(err: &Socks5Error) -> ReplyError {
    match err {
        Socks5Error::Timeout => ReplyError::ConnectionTimeout,
        Socks5Error::ConnectionFailed(_) => ReplyError::HostUnreachable,
        Socks5Error::TunnelError(inner) => map_manager_error_to_reply(inner),
        _ => ReplyError::GeneralFailure,
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
