use crate::tunnel::dns::{
    DnsError, DnsRecord, DnsRecordType, build_dns_query, dns_port, get_dns_local_port,
    parse_dns_response_with_id,
};
use crate::tunnel::masque::MasqueTunnel;
use crate::tunnel::quic;
use crate::tunnel::wireguard::WgTunnel;
use crate::tunnel::stack::{NetworkStack, StackError};
use bytes::{Bytes, BytesMut};
use quick_cache::unsync::Cache;
use rand::Rng;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpAddress;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant as TokioInstant;

use crate::tunnel::quic::CongestionControl;

// Exponential backoff with jitter for reconnection
struct ExponentialBackoff {
    base: Duration,
    max: Duration,
    current: Duration,
    jitter_factor: f64,
}

impl ExponentialBackoff {
    fn new() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
            current: Duration::from_secs(1),
            jitter_factor: 0.5,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = std::cmp::min(self.current * 2, self.max);
        let mut rng = rand::rng();
        let jitter = rng.random_range(-self.jitter_factor..self.jitter_factor);
        let jittered = delay.as_secs_f64() * (1.0 + jitter);
        Duration::from_secs_f64(jittered.max(0.1))
    }

    fn reset(&mut self) {
        self.current = self.base;
    }
}

// Connection parameters for establishing and reconnecting tunnel
#[derive(Clone)]
pub struct ConnectionParams {
    pub endpoint: SocketAddr,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub sni: String,
    pub endpoint_pub_key: Option<Vec<u8>>,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub dns_servers: Vec<IpAddress>,
    pub keepalive: u64,
    pub initial_packet_size: u16,
    pub mtu: u16,
    pub congestion_control: CongestionControl,
    pub tcp_buffer_size: usize,
    pub quic_idle_timeout_ms: u64,
    pub tunnel_mode: TunnelMode,
    pub wg_private_key: Option<[u8; 32]>,
    pub wg_peer_public_key: Option<[u8; 32]>,
    pub wg_client_id: Option<[u8; 3]>,
}

#[derive(Clone, Copy, Default, PartialEq)]
pub enum TunnelMode {
    #[default]
    Masque,
    Wireguard,
}

#[derive(Error, Debug)]
pub enum ManagerError {
    #[error("manager channel closed")]
    ChannelClosed,
    #[error("manager response channel closed")]
    ResponseChannelClosed,
    #[error("tunnel not connected")]
    NotConnected,
    #[error("dns error: {0}")]
    Dns(#[from] DnsError),
    #[error("stack error: {0}")]
    Stack(#[from] StackError),
}

type UdpSessionReceiver = mpsc::Receiver<(IpAddress, u16, Bytes)>;
type UdpSessionResponse = oneshot::Sender<Result<UdpSessionReceiver, ManagerError>>;

// Commands sent from SOCKS5 connections to the manager
pub enum ManagerCommand {
    // Create a new TCP connection
    Connect {
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
        response: oneshot::Sender<Result<SocketChannels, ManagerError>>,
    },
    // Close a TCP connection
    Close {
        handle: SocketHandle,
    },
    // DNS resolution through tunnel
    DnsResolve {
        domain: String,
        prefer_ipv6: bool,
        response: oneshot::Sender<Result<IpAddress, ManagerError>>,
    },
    // DNS resolution returning all addresses (for Happy Eyeballs connection racing)
    DnsResolveAll {
        domain: String,
        response: oneshot::Sender<Result<Vec<IpAddress>, ManagerError>>,
    },
    // Register UDP session for receiving data from tunnel
    UdpRegister {
        local_port: u16,
        response: UdpSessionResponse,
    },
    // Unregister UDP session
    UdpUnregister {
        local_port: u16,
    },
    // Get TCP socket state
    GetSocketState {
        handle: SocketHandle,
        response: oneshot::Sender<TcpSocketState>,
    },
    // Wait for socket to become ready (established or closed)
    WaitSocketReady {
        handle: SocketHandle,
        response: oneshot::Sender<TcpSocketState>,
    },
}

// TCP socket connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpSocketState {
    Connecting,
    Established,
    Closed,
}

// Channels for a single TCP socket
pub struct SocketChannels {
    pub handle: SocketHandle,
    pub to_stack: mpsc::Sender<Bytes>,
    pub from_stack: mpsc::Receiver<Bytes>,
}

// Internal state for each socket
struct SocketState {
    to_client: mpsc::Sender<Bytes>,
    from_client: mpsc::Receiver<Bytes>,
    pending_from_client: VecDeque<Bytes>,
    pending_from_client_bytes: usize,
    pending_to_client: VecDeque<Bytes>,
    pending_to_client_bytes: usize,
    // Waiters for socket ready notification (event-driven instead of polling)
    ready_waiters: Vec<oneshot::Sender<TcpSocketState>>,
}

// DNS query state for a single query (A or AAAA)
struct DnsQueryState {
    group_id: u32,
    query_type: DnsRecordType,
}

struct DnsSockets {
    v4: Option<SocketHandle>,
    v6: Option<SocketHandle>,
}

impl DnsSockets {
    fn new() -> Self {
        Self { v4: None, v6: None }
    }

    fn ensure_socket(
        &mut self,
        stack: &mut NetworkStack,
        server: IpAddress,
    ) -> Result<SocketHandle, DnsError> {
        let slot = match server {
            IpAddress::Ipv4(_) => &mut self.v4,
            IpAddress::Ipv6(_) => &mut self.v6,
        };

        if let Some(handle) = *slot {
            return Ok(handle);
        }

        let local_port = get_dns_local_port();
        let handle = stack
            .create_udp_socket_for(local_port, server)
            .map_err(|e| DnsError::SocketError(format!("{}", e)))?;
        *slot = Some(handle);
        Ok(handle)
    }

    fn handles(&self) -> impl Iterator<Item = SocketHandle> {
        self.v4.iter().copied().chain(self.v6.iter().copied())
    }
}

// Happy Eyeballs: tracks paired A/AAAA queries
struct DnsQueryGroup {
    domain: String,
    response: Option<oneshot::Sender<Result<IpAddress, ManagerError>>>, // Option to allow early response
    response_all: Option<oneshot::Sender<Result<Vec<IpAddress>, ManagerError>>>, // For resolve_all
    ipv4_result: Option<Result<Vec<DnsRecord>, DnsError>>,
    ipv6_result: Option<Result<Vec<DnsRecord>, DnsError>>,
    created_at: Instant,
    prefer_ipv6: bool,
}

// DNS cache value: stores multiple IPs with their expiration times
struct DnsCacheValue {
    records: Vec<(IpAddress, Instant)>, // (ip, expires_at)
}

// DNS cache capacity
const DNS_CACHE_CAPACITY: usize = 1024;

// Helper functions for DNS cache operations
fn dns_cache_get(
    cache: &Cache<String, DnsCacheValue>,
    domain: &str,
    prefer_ipv6: bool,
) -> Option<IpAddress> {
    let value = cache.get(domain)?;
    let now = Instant::now();

    // Count valid records by type without allocation
    let mut v6_count = 0usize;
    let mut v4_count = 0usize;
    for (ip, exp) in &value.records {
        if *exp > now {
            match ip {
                IpAddress::Ipv6(_) => v6_count += 1,
                IpAddress::Ipv4(_) => v4_count += 1,
            }
        }
    }

    let total = v6_count + v4_count;
    if total == 0 {
        return None;
    }

    // Select target type and index for load balancing
    let (target_v6, target_count) = if prefer_ipv6 {
        if v6_count > 0 {
            (true, v6_count)
        } else {
            (false, v4_count)
        }
    } else if v4_count > 0 {
        (false, v4_count)
    } else {
        (true, v6_count)
    };

    let target_idx = rand::rng().random_range(0..target_count);

    // Find the target record
    let mut idx = 0usize;
    for (ip, exp) in &value.records {
        if *exp > now {
            let is_v6 = matches!(ip, IpAddress::Ipv6(_));
            if is_v6 == target_v6 {
                if idx == target_idx {
                    return Some(*ip);
                }
                idx += 1;
            }
        }
    }

    None
}

// Get all valid IP addresses from cache (for Happy Eyeballs connection racing)
fn dns_cache_get_all(cache: &Cache<String, DnsCacheValue>, domain: &str) -> Option<Vec<IpAddress>> {
    let value = cache.get(domain)?;
    let now = Instant::now();

    let valid_ips: Vec<IpAddress> = value
        .records
        .iter()
        .filter(|(_, exp)| *exp > now)
        .map(|(ip, _)| *ip)
        .collect();

    if valid_ips.is_empty() {
        None
    } else {
        Some(valid_ips)
    }
}

fn dns_cache_insert(
    cache: &mut Cache<String, DnsCacheValue>,
    domain: String,
    records: &[DnsRecord],
) {
    let now = Instant::now();
    let entries: Vec<(IpAddress, Instant)> = records
        .iter()
        .map(|r| (r.address, now + Duration::from_secs(r.ttl as u64)))
        .collect();
    cache.insert(domain, DnsCacheValue { records: entries });
}

// UDP session state for SOCKS5 UDP ASSOCIATE
struct UdpSessionState {
    handle: SocketHandle,
    to_client: mpsc::Sender<(IpAddress, u16, Bytes)>,
    last_activity: Instant,
}

struct UdpSend {
    remote_ip: IpAddress,
    remote_port: u16,
    local_port: u16,
    data: Bytes,
}

struct IncomingDatagram {
    data: BytesMut,
    from: SocketAddr,
}

struct RuntimeState {
    stack: NetworkStack,
    sockets: HashMap<SocketHandle, SocketState>,
    dns_queries: HashMap<u16, DnsQueryState>,
    dns_groups: HashMap<u32, DnsQueryGroup>,
    dns_sockets: DnsSockets,
    dns_cache: Cache<String, DnsCacheValue>,
    udp_sessions: HashMap<u16, UdpSessionState>,
    read_buffer: BytesMut,
}

impl RuntimeState {
    fn new(stack: NetworkStack) -> Self {
        Self {
            stack,
            sockets: HashMap::new(),
            dns_queries: HashMap::new(),
            dns_groups: HashMap::new(),
            dns_sockets: DnsSockets::new(),
            dns_cache: Cache::new(DNS_CACHE_CAPACITY),
            udp_sessions: HashMap::new(),
            read_buffer: BytesMut::zeroed(MAX_TCP_READ_CHUNK),
        }
    }
}

const CMD_CHANNEL_CAPACITY: usize = 256;
const UDP_DATA_CHANNEL_CAPACITY: usize = 2048;
// Increased for high-concurrency scenarios (64+ parallel connections)
const INCOMING_DGRAM_CAPACITY: usize = 4096;
const UDP_RECV_BUFFER_SIZE: usize = 65535;
const MAX_TCP_READ_CHUNK: usize = 64 * 1024;

const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
// Backpressure: from_client uses small channel (32) so send().await naturally blocks SOCKS5 reads
const MAX_PENDING_DATA: usize = 128 * 1024; // 128KB per socket (for partial writes)
// Backpressure: to_client uses try_send + pending queue, must never block manager
const MAX_PENDING_TO_CLIENT: usize = 256 * 1024; // 256KB per socket
const UDP_BATCH_READ_BUDGET: usize = 128;

enum DeliverError {
    Backpressure,
    Closed,
}

static DNS_GROUP_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
static DNS_SERVER_INDEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub struct TunnelManager {
    cmd_tx: mpsc::Sender<ManagerCommand>,
    udp_tx: mpsc::Sender<UdpSend>,
}

pub struct TunnelManagerPool {
    managers: Vec<Arc<TunnelManager>>,
    next: AtomicUsize,
}

impl TunnelManagerPool {
    pub fn new(params: ConnectionParams, size: usize) -> Self {
        let size = size.max(1);
        let mut managers = Vec::with_capacity(size);
        for _ in 0..size {
            managers.push(Arc::new(TunnelManager::new(params.clone())));
        }

        Self {
            managers,
            next: AtomicUsize::new(0),
        }
    }

    pub fn pick(&self) -> Arc<TunnelManager> {
        let idx = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.managers[idx % self.managers.len()].clone()
    }
}

impl TunnelManager {
    pub fn new(params: ConnectionParams) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_CAPACITY);
        let (udp_tx, udp_rx) = mpsc::channel(UDP_DATA_CHANNEL_CAPACITY);

        tokio::spawn(Self::maintain_tunnel(params, cmd_rx, udp_rx));

        Self { cmd_tx, udp_tx }
    }

    async fn maintain_tunnel(
        params: ConnectionParams,
        mut cmd_rx: mpsc::Receiver<ManagerCommand>,
        mut udp_rx: mpsc::Receiver<UdpSend>,
    ) {
        let mut backoff = ExponentialBackoff::new();

        enum TunnelConn {
            Masque(Box<MasqueTunnel>, NetworkStack),
            Wg(Box<WgTunnel>, NetworkStack),
        }

        loop {
            let mode_name = match params.tunnel_mode {
                TunnelMode::Masque => "MASQUE",
                TunnelMode::Wireguard => "WireGuard",
            };
            log::info!("Establishing {} connection to {}", mode_name, params.endpoint);

            let (conn_tx, mut conn_rx) = oneshot::channel();
            let params_clone = params.clone();
            tokio::spawn(async move {
                let res = match params_clone.tunnel_mode {
                    TunnelMode::Masque => Self::establish_connection(&params_clone)
                        .await
                        .map(|(t, s)| TunnelConn::Masque(Box::new(t), s)),
                    TunnelMode::Wireguard => Self::establish_connection_wg(&params_clone)
                        .await
                        .map(|(t, s)| TunnelConn::Wg(Box::new(t), s)),
                };
                if conn_tx.send(res).is_err() {
                    log::debug!("Connection result dropped: receiver closed");
                }
            });

            loop {
                tokio::select! {
                    res = &mut conn_rx => {
                        match res {
                            Ok(Ok(conn)) => {
                                log::info!("Tunnel connected successfully");
                                backoff.reset();
                                match conn {
                                    TunnelConn::Masque(tunnel, stack) => {
                                        Self::run_loop(
                                            *tunnel,
                                            stack,
                                            &mut cmd_rx,
                                            &mut udp_rx,
                                            &params.dns_servers,
                                            params.keepalive,
                                            params.tcp_buffer_size,
                                        )
                                        .await;
                                    }
                                    TunnelConn::Wg(tunnel, stack) => {
                                        Self::run_loop_wg(
                                            *tunnel,
                                            stack,
                                            &mut cmd_rx,
                                            &mut udp_rx,
                                            &params.dns_servers,
                                            params.tcp_buffer_size,
                                        )
                                        .await;
                                    }
                                }
                                log::warn!("Connection lost, reconnecting...");
                            }
                            Ok(Err(e)) => {
                                log::error!("Failed to connect: {}", e);
                            }
                            Err(_) => {
                                log::error!("Connection task cancelled");
                            }
                        }
                        break;
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(cmd) => Self::handle_command_disconnected(cmd),
                            None => return,
                        }
                    }
                    udp = udp_rx.recv() => {
                        if let Some(cmd) = udp {
                            Self::handle_udp_send_disconnected(cmd);
                        }
                    }
                }
            }

            let delay = backoff.next_delay();
            log::info!("Reconnecting in {:?}", delay);
            let sleep = tokio::time::sleep(delay);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    _ = &mut sleep => break,
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(cmd) => Self::handle_command_disconnected(cmd),
                            None => return,
                        }
                    }
                    udp = udp_rx.recv() => {
                        if let Some(cmd) = udp {
                            Self::handle_udp_send_disconnected(cmd);
                        }
                    }
                }
            }
        }
    }

    async fn establish_connection(
        params: &ConnectionParams,
    ) -> Result<(MasqueTunnel, NetworkStack), Box<dyn std::error::Error + Send + Sync>> {
        let quic_cfg = quic::QuicConfig {
            idle_timeout: params.quic_idle_timeout_ms,
            initial_packet_size: params.initial_packet_size,
            congestion_control: params.congestion_control,
            ..Default::default()
        };

        let quic_conn = quic::connect_with_pinning(
            params.endpoint,
            &params.cert_der,
            &params.key_der,
            &params.sni,
            Duration::from_secs(30),
            params.endpoint_pub_key.as_deref(),
            &quic_cfg,
        )
        .await?;

        let mut masque_tunnel = MasqueTunnel::new(quic_conn);
        masque_tunnel.establish(Duration::from_secs(30)).await?;

        // Dynamically get MTU from QUIC datagram max size
        // Subtract HTTP/3 datagram header (~3 bytes for varint stream ID + context ID)
        let dynamic_mtu = masque_tunnel
            .quic_conn
            .conn
            .dgram_max_writable_len()
            .map(|max| max.saturating_sub(3))
            .unwrap_or(1280);

        let configured_mtu = params.mtu as usize;
        let mtu = if configured_mtu == 0 {
            dynamic_mtu
        } else {
            dynamic_mtu.min(configured_mtu)
        };

        log::info!(
            "Using MTU {} (QUIC limit {}, configured {})",
            mtu,
            dynamic_mtu,
            configured_mtu
        );

        let ipv4 = if params.ipv4.trim().is_empty() {
            None
        } else {
            Some(params.ipv4.as_str())
        };
        let ipv6 = params.ipv6.as_deref().filter(|s| !s.trim().is_empty());
        let stack = NetworkStack::new(ipv4, ipv6, mtu);

        Ok((masque_tunnel, stack))
    }

    async fn establish_connection_wg(
        params: &ConnectionParams,
    ) -> Result<(WgTunnel, NetworkStack), Box<dyn std::error::Error + Send + Sync>> {
        let wg_private_key = params.wg_private_key.ok_or("WG private key not set")?;
        let wg_peer_public_key = params.wg_peer_public_key.ok_or("WG peer public key not set")?;
        let wg_client_id = params.wg_client_id.ok_or("WG client_id not set")?;

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(params.endpoint).await?;
        let socket = Arc::new(socket);

        let keepalive = if params.keepalive > 0 {
            Some(params.keepalive as u16)
        } else {
            None
        };

        let mut wg_tunnel = WgTunnel::new(
            wg_private_key,
            wg_peer_public_key,
            socket,
            wg_client_id,
            keepalive,
        );

        wg_tunnel.establish(Duration::from_secs(30)).await?;

        let mtu = if params.mtu == 0 {
            1280
        } else {
            params.mtu as usize
        };
        log::info!("WireGuard tunnel established, MTU {}", mtu);

        let ipv4 = if params.ipv4.trim().is_empty() {
            None
        } else {
            Some(params.ipv4.as_str())
        };
        let ipv6 = params.ipv6.as_deref().filter(|s| !s.trim().is_empty());
        let stack = NetworkStack::new(ipv4, ipv6, mtu);

        Ok((wg_tunnel, stack))
    }

    pub async fn connect(
        &self,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<SocketChannels, ManagerError> {
        let (response_tx, response_rx) = oneshot::channel();

        self.cmd_tx
            .send(ManagerCommand::Connect {
                remote_ip,
                remote_port,
                local_port,
                response: response_tx,
            })
            .await
            .map_err(|_| ManagerError::ChannelClosed)?;

        response_rx
            .await
            .map_err(|_| ManagerError::ResponseChannelClosed)?
    }

    pub async fn close(&self, handle: SocketHandle) {
        if let Err(e) = self.cmd_tx.send(ManagerCommand::Close { handle }).await {
            log::debug!("Failed to send close command: {}", e);
        }
    }

    pub async fn get_socket_state(&self, handle: SocketHandle) -> TcpSocketState {
        let (response_tx, response_rx) = oneshot::channel();

        if self
            .cmd_tx
            .send(ManagerCommand::GetSocketState {
                handle,
                response: response_tx,
            })
            .await
            .is_err()
        {
            return TcpSocketState::Closed;
        }

        response_rx.await.unwrap_or(TcpSocketState::Closed)
    }

    pub fn cmd_sender(&self) -> mpsc::Sender<ManagerCommand> {
        self.cmd_tx.clone()
    }

    pub async fn send_udp(
        &self,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
        data: Bytes,
    ) -> Result<(), ManagerError> {
        self.udp_tx
            .send(UdpSend {
                remote_ip,
                remote_port,
                local_port,
                data,
            })
            .await
            .map_err(|_| ManagerError::ChannelClosed)
    }

    pub async fn resolve(
        &self,
        domain: &str,
        prefer_ipv6: bool,
    ) -> Result<IpAddress, ManagerError> {
        let (response_tx, response_rx) = oneshot::channel();

        self.cmd_tx
            .send(ManagerCommand::DnsResolve {
                domain: domain.to_string(),
                prefer_ipv6,
                response: response_tx,
            })
            .await
            .map_err(|_| ManagerError::ChannelClosed)?;

        response_rx
            .await
            .map_err(|_| ManagerError::ResponseChannelClosed)?
    }

    pub async fn resolve_all(&self, domain: &str) -> Result<Vec<IpAddress>, ManagerError> {
        let (response_tx, response_rx) = oneshot::channel();

        self.cmd_tx
            .send(ManagerCommand::DnsResolveAll {
                domain: domain.to_string(),
                response: response_tx,
            })
            .await
            .map_err(|_| ManagerError::ChannelClosed)?;

        response_rx
            .await
            .map_err(|_| ManagerError::ResponseChannelClosed)?
    }

    pub async fn wait_socket_ready(&self, handle: SocketHandle) -> TcpSocketState {
        let (response_tx, response_rx) = oneshot::channel();

        if self
            .cmd_tx
            .send(ManagerCommand::WaitSocketReady {
                handle,
                response: response_tx,
            })
            .await
            .is_err()
        {
            return TcpSocketState::Closed;
        }

        response_rx.await.unwrap_or(TcpSocketState::Closed)
    }

    async fn run_loop(
        mut tunnel: MasqueTunnel,
        stack: NetworkStack,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        dns_servers: &[IpAddress],
        keepalive_secs: u64,
        tcp_buffer_size: usize,
    ) {
        let local_addr = tunnel.quic_conn.local_addr;
        let (incoming_tx, mut incoming_rx) = mpsc::channel(INCOMING_DGRAM_CAPACITY);
        let socket = tunnel.quic_conn.socket.clone();
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let mut shutdown_sub = shutdown_tx.subscribe();
        // Guard: when all senders are dropped, the completion channel closes
        let (completion_tx, mut completion_rx) = mpsc::channel::<()>(1);
        let recv_completion_tx = completion_tx.clone();
        let recv_handle = tokio::spawn(async move {
            let _guard = recv_completion_tx;
            let mut buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
            loop {
                tokio::select! {
                    _ = shutdown_sub.recv() => break,
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, from)) => {
                                if len == 0 {
                                    continue;
                                }
                                let data = BytesMut::from(&buf[..len]);
                                if incoming_tx.send(IncomingDatagram { data, from }).await.is_err() {
                                    log::trace!("Incoming datagram channel closed");
                                    break;
                                }
                            }
                            Err(e) => {
                                log::warn!("UDP recv error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        let mut state = RuntimeState::new(stack);

        // Keepalive tracking
        let mut last_keepalive = Instant::now();
        let keepalive_interval = Duration::from_secs(keepalive_secs);
        const MAX_POLL_INTERVAL: Duration = Duration::from_millis(50);
        const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(5);
        let poll_timer = tokio::time::sleep(Duration::from_millis(0));
        tokio::pin!(poll_timer);

        loop {
            // Check connection status at the start of each iteration
            if tunnel.quic_conn.is_closed() {
                log::error!("QUIC connection closed");
                break;
            }

            // Dynamic timeout: min of QUIC timer, smoltcp timer, and upper bound
            let quic_timeout = tunnel
                .quic_conn
                .conn
                .timeout()
                .unwrap_or(Duration::from_millis(100));
            let smoltcp_timeout = state
                .stack
                .poll_delay()
                .unwrap_or(DEFAULT_POLL_INTERVAL);
            let poll_timeout = quic_timeout.min(smoltcp_timeout).min(MAX_POLL_INTERVAL);
            poll_timer
                .as_mut()
                .reset(TokioInstant::now() + poll_timeout);

            tokio::select! {
                biased;
                // Handle control commands from SOCKS5 connections
                Some(cmd) = cmd_rx.recv() => {
                    Self::handle_command(&mut state, dns_servers, tcp_buffer_size, cmd);
                    if !Self::flush_outbound(&mut tunnel, &mut state).await {
                        break;
                    }
                }

                // Handle UDP sends from SOCKS5
                Some(udp_cmd) = udp_rx.recv() => {
                    Self::handle_udp_send(&mut state.stack, &mut state.udp_sessions, udp_cmd);
                    if !Self::flush_outbound(&mut tunnel, &mut state).await {
                        break;
                    }
                }

                // Receive UDP data from QUIC socket - batch read
                Some(incoming) = incoming_rx.recv() => {
                    let mut data = incoming.data;
                    Self::handle_udp_recv(&mut tunnel, &mut state.stack, &mut data[..], incoming.from, local_addr);
                    // Batch read remaining datagrams
                    let mut budget = UDP_BATCH_READ_BUDGET - 1;
                    while budget > 0 {
                        match incoming_rx.try_recv() {
                            Ok(incoming) => {
                                let mut data = incoming.data;
                                Self::handle_udp_recv(&mut tunnel, &mut state.stack, &mut data[..], incoming.from, local_addr);
                                budget -= 1;
                            }
                            Err(_) => break,
                        }
                    }
                    if !Self::flush_outbound(&mut tunnel, &mut state).await {
                        break;
                    }
                }

                // Dynamic timeout - replaces fixed interval polling
                _ = &mut poll_timer => {
                    tunnel.quic_conn.conn.on_timeout();
                    if !Self::poll_all(
                        &mut tunnel,
                        &mut state,
                        &mut last_keepalive,
                        keepalive_interval,
                    ).await {
                        break;
                    }
                }
            }
        }

        // Phase 1: broadcast shutdown to all tasks
        if shutdown_tx.send(()).is_err() {
            log::trace!("Failed to send shutdown signal: no receivers");
        }
        // Phase 2: drop our guard and wait for all tasks to finish
        drop(completion_tx);
        let _ = completion_rx.recv().await; // returns None when all senders dropped
        if let Err(e) = recv_handle.await {
            log::debug!("Recv task join error: {:?}", e);
        }
        log::info!("TunnelManager run_loop ended");
    }

    async fn run_loop_wg(
        mut tunnel: WgTunnel,
        stack: NetworkStack,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        dns_servers: &[IpAddress],
        tcp_buffer_size: usize,
    ) {
        let socket = tunnel.socket();
        let (incoming_tx, mut incoming_rx) = mpsc::channel(INCOMING_DGRAM_CAPACITY);
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let mut shutdown_sub = shutdown_tx.subscribe();
        let (completion_tx, mut completion_rx) = mpsc::channel::<()>(1);
        let recv_completion_tx = completion_tx.clone();

        let peer_addr = socket
            .peer_addr()
            .expect("WG socket should be connected");
        let recv_handle = tokio::spawn(async move {
            let _guard = recv_completion_tx;
            let mut buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
            loop {
                tokio::select! {
                    _ = shutdown_sub.recv() => break,
                    result = socket.recv(&mut buf) => {
                        match result {
                            Ok(len) => {
                                if len == 0 { continue; }
                                let data = BytesMut::from(&buf[..len]);
                                if incoming_tx.send(IncomingDatagram { data, from: peer_addr }).await.is_err() {
                                    log::trace!("Incoming datagram channel closed");
                                    break;
                                }
                            }
                            Err(e) => {
                                log::warn!("UDP recv error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        let mut state = RuntimeState::new(stack);

        const WG_TIMER_INTERVAL: Duration = Duration::from_millis(250);
        const MAX_POLL_INTERVAL: Duration = Duration::from_millis(50);
        const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(5);

        let wg_timer = tokio::time::sleep(WG_TIMER_INTERVAL);
        tokio::pin!(wg_timer);
        let poll_timer = tokio::time::sleep(Duration::from_millis(0));
        tokio::pin!(poll_timer);

        loop {
            if tunnel.is_expired() {
                log::error!("WireGuard tunnel expired");
                break;
            }

            let smoltcp_timeout = state.stack.poll_delay().unwrap_or(DEFAULT_POLL_INTERVAL);
            let poll_timeout = smoltcp_timeout.min(MAX_POLL_INTERVAL);
            poll_timer
                .as_mut()
                .reset(TokioInstant::now() + poll_timeout);

            tokio::select! {
                biased;
                Some(cmd) = cmd_rx.recv() => {
                    Self::handle_command(&mut state, dns_servers, tcp_buffer_size, cmd);
                    if !Self::flush_outbound_wg(&mut tunnel, &mut state).await {
                        break;
                    }
                }

                Some(udp_cmd) = udp_rx.recv() => {
                    Self::handle_udp_send(&mut state.stack, &mut state.udp_sessions, udp_cmd);
                    if !Self::flush_outbound_wg(&mut tunnel, &mut state).await {
                        break;
                    }
                }

                Some(incoming) = incoming_rx.recv() => {
                    tunnel.process_incoming_udp(incoming.data, &mut state.stack).await;
                    let mut budget = UDP_BATCH_READ_BUDGET - 1;
                    while budget > 0 {
                        match incoming_rx.try_recv() {
                            Ok(incoming) => {
                                tunnel.process_incoming_udp(incoming.data, &mut state.stack).await;
                                budget -= 1;
                            }
                            Err(_) => break,
                        }
                    }
                    if !Self::flush_outbound_wg(&mut tunnel, &mut state).await {
                        break;
                    }
                }

                _ = &mut wg_timer => {
                    if let Err(e) = tunnel.tick_timers().await {
                        log::warn!("WG timer error: {}", e);
                    }
                    wg_timer.as_mut().reset(TokioInstant::now() + WG_TIMER_INTERVAL);
                }

                _ = &mut poll_timer => {
                    if !Self::poll_all_wg(&mut tunnel, &mut state).await {
                        break;
                    }
                }
            }
        }

        if shutdown_tx.send(()).is_err() {
            log::trace!("Failed to send shutdown signal: no receivers");
        }
        drop(completion_tx);
        let _ = completion_rx.recv().await;
        if let Err(e) = recv_handle.await {
            log::debug!("Recv task join error: {:?}", e);
        }
        log::info!("TunnelManager WG run_loop ended");
    }

    fn handle_command(
        state: &mut RuntimeState,
        dns_servers: &[IpAddress],
        tcp_buffer_size: usize,
        cmd: ManagerCommand,
    ) {
        match cmd {
            ManagerCommand::Connect {
                remote_ip,
                remote_port,
                local_port,
                response,
            } => {
                let result = Self::create_connection(
                    &mut state.stack,
                    &mut state.sockets,
                    remote_ip,
                    remote_port,
                    local_port,
                    tcp_buffer_size,
                );
                if response.send(result).is_err() {
                    log::trace!("Failed to send connect response: receiver dropped");
                }
            }
            ManagerCommand::Close { handle } => {
                Self::close_connection(&mut state.stack, &mut state.sockets, handle);
            }
            ManagerCommand::DnsResolve {
                domain,
                prefer_ipv6,
                response,
            } => {
                // Check cache first
                if let Some(ip) = dns_cache_get(&state.dns_cache, &domain, prefer_ipv6) {
                    log::debug!("DNS cache hit: {} -> {:?}", domain, ip);
                    if response.send(Ok(ip)).is_err() {
                        log::trace!("Failed to send cached DNS response: receiver dropped");
                    }
                } else {
                    Self::start_dns_query(state, &domain, prefer_ipv6, response, dns_servers);
                }
            }
            ManagerCommand::DnsResolveAll { domain, response } => {
                // Check cache first for all addresses
                if let Some(ips) = dns_cache_get_all(&state.dns_cache, &domain) {
                    log::debug!("DNS cache hit (all): {} -> {} addresses", domain, ips.len());
                    if response.send(Ok(ips)).is_err() {
                        log::trace!("Failed to send cached DNS response: receiver dropped");
                    }
                } else {
                    Self::start_dns_query_all(state, &domain, response, dns_servers);
                }
            }
            ManagerCommand::UdpRegister {
                local_port,
                response,
            } => {
                Self::register_udp_session(
                    &mut state.stack,
                    &mut state.udp_sessions,
                    local_port,
                    response,
                );
            }
            ManagerCommand::UdpUnregister { local_port } => {
                Self::unregister_udp_session(&mut state.stack, &mut state.udp_sessions, local_port);
            }
            ManagerCommand::GetSocketState { handle, response } => {
                let socket_state =
                    Self::get_tcp_socket_state(&mut state.stack, &state.sockets, handle);
                if response.send(socket_state).is_err() {
                    log::trace!("Failed to send socket state response: receiver dropped");
                }
            }
            ManagerCommand::WaitSocketReady { handle, response } => {
                let socket_state =
                    Self::get_tcp_socket_state(&mut state.stack, &state.sockets, handle);
                if socket_state != TcpSocketState::Connecting {
                    // Already ready or closed, respond immediately
                    if response.send(socket_state).is_err() {
                        log::trace!("Failed to send socket ready response: receiver dropped");
                    }
                } else if let Some(socket_state) = state.sockets.get_mut(&handle) {
                    // Still connecting, add to waiters
                    socket_state.ready_waiters.push(response);
                } else {
                    // Socket not found
                    if response.send(TcpSocketState::Closed).is_err() {
                        log::trace!("Failed to send socket closed response: receiver dropped");
                    }
                }
            }
        }
    }

    fn handle_command_disconnected(cmd: ManagerCommand) {
        match cmd {
            ManagerCommand::Connect { response, .. } => {
                if response.send(Err(ManagerError::NotConnected)).is_err() {
                    log::trace!("Failed to send connect error: receiver dropped");
                }
            }
            ManagerCommand::Close { .. } => {}
            ManagerCommand::DnsResolve { response, .. } => {
                if response.send(Err(ManagerError::NotConnected)).is_err() {
                    log::trace!("Failed to send DNS error: receiver dropped");
                }
            }
            ManagerCommand::DnsResolveAll { response, .. } => {
                if response.send(Err(ManagerError::NotConnected)).is_err() {
                    log::trace!("Failed to send DNS error: receiver dropped");
                }
            }
            ManagerCommand::UdpRegister { response, .. } => {
                if response.send(Err(ManagerError::NotConnected)).is_err() {
                    log::trace!("Failed to send UDP register error: receiver dropped");
                }
            }
            ManagerCommand::UdpUnregister { .. } => {}
            ManagerCommand::GetSocketState { response, .. } => {
                if response.send(TcpSocketState::Closed).is_err() {
                    log::trace!("Failed to send socket state: receiver dropped");
                }
            }
            ManagerCommand::WaitSocketReady { response, .. } => {
                if response.send(TcpSocketState::Closed).is_err() {
                    log::trace!("Failed to send socket ready response: receiver dropped");
                }
            }
        }
    }

    fn handle_udp_send(
        stack: &mut NetworkStack,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
        cmd: UdpSend,
    ) {
        Self::send_udp_data(
            stack,
            udp_sessions,
            cmd.remote_ip,
            cmd.remote_port,
            cmd.local_port,
            cmd.data.as_ref(),
        );
    }

    fn handle_udp_send_disconnected(cmd: UdpSend) {
        log::trace!(
            "Dropping UDP send to {:?}:{} from local port {}: tunnel not connected",
            cmd.remote_ip,
            cmd.remote_port,
            cmd.local_port
        );
    }

    fn create_connection(
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
        tcp_buffer_size: usize,
    ) -> Result<SocketChannels, ManagerError> {
        let handle = stack.create_tcp_socket_with_buffer(tcp_buffer_size);

        if let Err(e) = stack.connect_tcp(handle, remote_ip, remote_port, local_port) {
            stack.remove_socket(handle);
            return Err(ManagerError::Stack(e));
        }

        let (to_client_tx, to_client_rx) = mpsc::channel(128);
        let (from_client_tx, from_client_rx) = mpsc::channel(32);

        let state = SocketState {
            to_client: to_client_tx,
            from_client: from_client_rx,
            pending_from_client: VecDeque::new(),
            pending_from_client_bytes: 0,
            pending_to_client: VecDeque::new(),
            pending_to_client_bytes: 0,
            ready_waiters: Vec::new(),
        };

        sockets.insert(handle, state);

        Ok(SocketChannels {
            handle,
            to_stack: from_client_tx,
            from_stack: to_client_rx,
        })
    }

    fn close_connection(
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
        handle: SocketHandle,
    ) {
        // Notify all waiters that the connection is closed
        if let Some(state) = sockets.remove(&handle) {
            for waiter in state.ready_waiters {
                if waiter.send(TcpSocketState::Closed).is_err() {
                    log::trace!("Failed to notify waiter of connection close: receiver dropped");
                }
            }
        }
        stack.tcp_close(handle);
        stack.remove_socket(handle);
    }

    fn get_tcp_socket_state(
        stack: &mut NetworkStack,
        sockets: &HashMap<SocketHandle, SocketState>,
        handle: SocketHandle,
    ) -> TcpSocketState {
        if !sockets.contains_key(&handle) {
            return TcpSocketState::Closed;
        }
        if !stack.tcp_is_active(handle) {
            return TcpSocketState::Closed;
        }
        if stack.tcp_may_send(handle) && stack.tcp_may_recv(handle) {
            TcpSocketState::Established
        } else {
            TcpSocketState::Connecting
        }
    }

    // Notify waiters when socket state changes from Connecting
    // Two-phase approach to avoid borrow conflicts:
    // 1. Collect notifications while holding mutable borrow
    // 2. Send notifications after releasing borrow
    fn notify_ready_waiters(
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
    ) {
        // Phase 1: Collect notifications
        let mut notifications: Vec<(Vec<oneshot::Sender<TcpSocketState>>, TcpSocketState)> =
            Vec::new();

        for (handle, state) in sockets.iter_mut() {
            if state.ready_waiters.is_empty() {
                continue;
            }
            // Check current state
            let tcp_state = if !stack.tcp_is_active(*handle) {
                TcpSocketState::Closed
            } else if stack.tcp_may_send(*handle) && stack.tcp_may_recv(*handle) {
                TcpSocketState::Established
            } else {
                TcpSocketState::Connecting
            };

            if tcp_state != TcpSocketState::Connecting {
                // State changed, drain waiters
                let waiters: Vec<_> = state.ready_waiters.drain(..).collect();
                notifications.push((waiters, tcp_state));
            }
        }

        // Phase 2: Send notifications (no longer borrowing sockets)
        for (waiters, tcp_state) in notifications {
            for waiter in waiters {
                if waiter.send(tcp_state).is_err() {
                    log::trace!("Failed to notify waiter of state change: receiver dropped");
                }
            }
        }
    }

    fn register_udp_session(
        stack: &mut NetworkStack,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
        local_port: u16,
        response: UdpSessionResponse,
    ) {
        let handle = match stack.create_udp_socket_default(local_port) {
            Ok(handle) => handle,
            Err(e) => {
                if response.send(Err(ManagerError::Stack(e))).is_err() {
                    log::trace!("Failed to send UDP register error: receiver dropped");
                }
                return;
            }
        };
        let (tx, rx) = mpsc::channel(1024);

        udp_sessions.insert(
            local_port,
            UdpSessionState {
                handle,
                to_client: tx,
                last_activity: Instant::now(),
            },
        );

        log::debug!("UDP session registered on port {}", local_port);
        if response.send(Ok(rx)).is_err() {
            log::trace!("Failed to send UDP register response: receiver dropped");
        }
    }

    fn send_udp_data(
        stack: &mut NetworkStack,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
        data: &[u8],
    ) {
        if let Some(session) = udp_sessions.get_mut(&local_port) {
            session.last_activity = Instant::now();
            if let Err(e) = stack.udp_send(session.handle, remote_ip, remote_port, data) {
                log::warn!("UDP send failed: {:?}", e);
            }
        } else {
            log::warn!("UDP session not found for port {}", local_port);
        }
    }

    fn unregister_udp_session(
        stack: &mut NetworkStack,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
        local_port: u16,
    ) {
        if let Some(session) = udp_sessions.remove(&local_port) {
            stack.remove_socket(session.handle);
            log::debug!("UDP session unregistered on port {}", local_port);
        }
    }

    fn record_dns_error(
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        group_id: u32,
        query_type: DnsRecordType,
        err: DnsError,
    ) {
        if let Some(group) = dns_groups.get_mut(&group_id) {
            match query_type {
                DnsRecordType::A => {
                    group.ipv4_result = Some(Err(err));
                }
                DnsRecordType::AAAA => {
                    group.ipv6_result = Some(Err(err));
                }
                _ => {}
            }
        }
    }

    fn build_unique_dns_query(
        dns_queries: &HashMap<u16, DnsQueryState>,
        domain: &str,
        record_type: DnsRecordType,
    ) -> Result<(u16, Vec<u8>), DnsError> {
        for _ in 0..=u16::MAX {
            let (tx_id, packet) = build_dns_query(domain, record_type)?;
            if !dns_queries.contains_key(&tx_id) {
                return Ok((tx_id, packet));
            }
        }
        Err(DnsError::SocketError("DNS transaction ID exhausted".into()))
    }

    fn start_dns_query(
        state: &mut RuntimeState,
        domain: &str,
        prefer_ipv6: bool,
        response: oneshot::Sender<Result<IpAddress, ManagerError>>,
        dns_servers: &[IpAddress],
    ) {
        use std::sync::atomic::Ordering;

        let group_id = DNS_GROUP_ID.fetch_add(1, Ordering::Relaxed);

        // Create group to track both queries
        state.dns_groups.insert(
            group_id,
            DnsQueryGroup {
                domain: domain.to_string(),
                response: Some(response),
                response_all: None,
                ipv4_result: None,
                ipv6_result: None,
                created_at: Instant::now(),
                prefer_ipv6,
            },
        );

        // Select DNS server with round-robin and preferred address family
        let dns_server = Self::select_dns_server(dns_servers, prefer_ipv6);

        let dns_handle = match state
            .dns_sockets
            .ensure_socket(&mut state.stack, dns_server)
        {
            Ok(handle) => handle,
            Err(e) => {
                Self::record_dns_error(
                    &mut state.dns_groups,
                    group_id,
                    DnsRecordType::A,
                    e.clone(),
                );
                Self::record_dns_error(&mut state.dns_groups, group_id, DnsRecordType::AAAA, e);
                Self::try_resolve_dns_group(
                    &mut state.dns_queries,
                    &mut state.dns_groups,
                    &mut state.dns_cache,
                    group_id,
                );
                return;
            }
        };

        // Send A query (IPv4)
        match Self::build_unique_dns_query(&state.dns_queries, domain, DnsRecordType::A) {
            Ok((tx_id_a, packet_a)) => {
                if state
                    .stack
                    .udp_send(dns_handle, dns_server, dns_port(), &packet_a)
                    .is_ok()
                {
                    state.dns_queries.insert(
                        tx_id_a,
                        DnsQueryState {
                            group_id,
                            query_type: DnsRecordType::A,
                        },
                    );
                    log::debug!("DNS A query sent: {} (id={})", domain, tx_id_a);
                } else {
                    Self::record_dns_error(
                        &mut state.dns_groups,
                        group_id,
                        DnsRecordType::A,
                        DnsError::SocketError("DNS A send failed".into()),
                    );
                    Self::try_resolve_dns_group(
                        &mut state.dns_queries,
                        &mut state.dns_groups,
                        &mut state.dns_cache,
                        group_id,
                    );
                }
            }
            Err(e) => {
                Self::record_dns_error(&mut state.dns_groups, group_id, DnsRecordType::A, e);
                Self::try_resolve_dns_group(
                    &mut state.dns_queries,
                    &mut state.dns_groups,
                    &mut state.dns_cache,
                    group_id,
                );
            }
        }

        // Send AAAA query (IPv6)
        match Self::build_unique_dns_query(&state.dns_queries, domain, DnsRecordType::AAAA) {
            Ok((tx_id_aaaa, packet_aaaa)) => {
                if state
                    .stack
                    .udp_send(dns_handle, dns_server, dns_port(), &packet_aaaa)
                    .is_ok()
                {
                    state.dns_queries.insert(
                        tx_id_aaaa,
                        DnsQueryState {
                            group_id,
                            query_type: DnsRecordType::AAAA,
                        },
                    );
                    log::debug!("DNS AAAA query sent: {} (id={})", domain, tx_id_aaaa);
                } else {
                    Self::record_dns_error(
                        &mut state.dns_groups,
                        group_id,
                        DnsRecordType::AAAA,
                        DnsError::SocketError("DNS AAAA send failed".into()),
                    );
                    Self::try_resolve_dns_group(
                        &mut state.dns_queries,
                        &mut state.dns_groups,
                        &mut state.dns_cache,
                        group_id,
                    );
                }
            }
            Err(e) => {
                Self::record_dns_error(&mut state.dns_groups, group_id, DnsRecordType::AAAA, e);
                Self::try_resolve_dns_group(
                    &mut state.dns_queries,
                    &mut state.dns_groups,
                    &mut state.dns_cache,
                    group_id,
                );
            }
        }
    }

    fn start_dns_query_all(
        state: &mut RuntimeState,
        domain: &str,
        response: oneshot::Sender<Result<Vec<IpAddress>, ManagerError>>,
        dns_servers: &[IpAddress],
    ) {
        use std::sync::atomic::Ordering;

        let group_id = DNS_GROUP_ID.fetch_add(1, Ordering::Relaxed);

        // Create group to track both queries (resolve_all waits for both results)
        state.dns_groups.insert(
            group_id,
            DnsQueryGroup {
                domain: domain.to_string(),
                response: None,
                response_all: Some(response),
                ipv4_result: None,
                ipv6_result: None,
                created_at: Instant::now(),
                prefer_ipv6: true, // Default to IPv6 preference for sorting
            },
        );

        // Select DNS server (prefer IPv6 for resolve_all)
        let dns_server = Self::select_dns_server(dns_servers, true);

        let dns_handle = match state
            .dns_sockets
            .ensure_socket(&mut state.stack, dns_server)
        {
            Ok(handle) => handle,
            Err(e) => {
                Self::record_dns_error(
                    &mut state.dns_groups,
                    group_id,
                    DnsRecordType::A,
                    e.clone(),
                );
                Self::record_dns_error(&mut state.dns_groups, group_id, DnsRecordType::AAAA, e);
                Self::try_resolve_dns_group(
                    &mut state.dns_queries,
                    &mut state.dns_groups,
                    &mut state.dns_cache,
                    group_id,
                );
                return;
            }
        };

        // Send A query (IPv4)
        match Self::build_unique_dns_query(&state.dns_queries, domain, DnsRecordType::A) {
            Ok((tx_id_a, packet_a)) => {
                if state
                    .stack
                    .udp_send(dns_handle, dns_server, dns_port(), &packet_a)
                    .is_ok()
                {
                    state.dns_queries.insert(
                        tx_id_a,
                        DnsQueryState {
                            group_id,
                            query_type: DnsRecordType::A,
                        },
                    );
                    log::debug!("DNS A query sent (all): {} (id={})", domain, tx_id_a);
                } else {
                    Self::record_dns_error(
                        &mut state.dns_groups,
                        group_id,
                        DnsRecordType::A,
                        DnsError::SocketError("DNS A send failed".into()),
                    );
                    Self::try_resolve_dns_group(
                        &mut state.dns_queries,
                        &mut state.dns_groups,
                        &mut state.dns_cache,
                        group_id,
                    );
                }
            }
            Err(e) => {
                Self::record_dns_error(&mut state.dns_groups, group_id, DnsRecordType::A, e);
                Self::try_resolve_dns_group(
                    &mut state.dns_queries,
                    &mut state.dns_groups,
                    &mut state.dns_cache,
                    group_id,
                );
            }
        }

        // Send AAAA query (IPv6)
        match Self::build_unique_dns_query(&state.dns_queries, domain, DnsRecordType::AAAA) {
            Ok((tx_id_aaaa, packet_aaaa)) => {
                if state
                    .stack
                    .udp_send(dns_handle, dns_server, dns_port(), &packet_aaaa)
                    .is_ok()
                {
                    state.dns_queries.insert(
                        tx_id_aaaa,
                        DnsQueryState {
                            group_id,
                            query_type: DnsRecordType::AAAA,
                        },
                    );
                    log::debug!("DNS AAAA query sent (all): {} (id={})", domain, tx_id_aaaa);
                } else {
                    Self::record_dns_error(
                        &mut state.dns_groups,
                        group_id,
                        DnsRecordType::AAAA,
                        DnsError::SocketError("DNS AAAA send failed".into()),
                    );
                    Self::try_resolve_dns_group(
                        &mut state.dns_queries,
                        &mut state.dns_groups,
                        &mut state.dns_cache,
                        group_id,
                    );
                }
            }
            Err(e) => {
                Self::record_dns_error(&mut state.dns_groups, group_id, DnsRecordType::AAAA, e);
                Self::try_resolve_dns_group(
                    &mut state.dns_queries,
                    &mut state.dns_groups,
                    &mut state.dns_cache,
                    group_id,
                );
            }
        }
    }

    fn process_dns_responses(
        stack: &mut NetworkStack,
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        dns_cache: &mut Cache<String, DnsCacheValue>,
        dns_sockets: &DnsSockets,
    ) {
        for handle in dns_sockets.handles() {
            while stack.udp_can_recv(handle) {
                let mut buf = [0u8; 4096];
                let (len, _endpoint) = match stack.udp_recv(handle, &mut buf) {
                    Ok(result) => result,
                    Err(e) => {
                        log::debug!("DNS recv failed: {}", e);
                        break;
                    }
                };
                if len == 0 {
                    continue;
                }

                let parsed = match parse_dns_response_with_id(&buf[..len]) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        log::debug!("Failed to parse DNS response: {:?}", e);
                        continue;
                    }
                };

                let (transaction_id, response_result) = parsed;
                let Some(state) = dns_queries.remove(&transaction_id) else {
                    log::trace!("DNS response ignored for unknown id={}", transaction_id);
                    continue;
                };

                if let Some(group) = dns_groups.get_mut(&state.group_id) {
                    match state.query_type {
                        DnsRecordType::A => {
                            group.ipv4_result = Some(response_result);
                        }
                        DnsRecordType::AAAA => {
                            group.ipv6_result = Some(response_result);
                        }
                        _ => {}
                    }
                }

                Self::try_resolve_dns_group(dns_queries, dns_groups, dns_cache, state.group_id);
            }
        }
    }

    fn process_udp_responses(
        stack: &mut NetworkStack,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
    ) {
        let ports: Vec<u16> = udp_sessions.keys().copied().collect();

        for local_port in ports {
            let handle = match udp_sessions.get(&local_port) {
                Some(session) => session.handle,
                None => continue,
            };

            if !stack.udp_can_recv(handle) {
                continue;
            }

            let mut buf = [0u8; 65535];
            if let Ok((len, endpoint)) = stack.udp_recv(handle, &mut buf)
                && len > 0
            {
                let remote_ip = endpoint.endpoint.addr;
                let remote_port = endpoint.endpoint.port;

                if let Some(session) = udp_sessions.get_mut(&local_port) {
                    session.last_activity = Instant::now();
                    if session
                        .to_client
                        .try_send((remote_ip, remote_port, Bytes::copy_from_slice(&buf[..len])))
                        .is_err()
                    {
                        log::debug!("UDP session channel full or closed for port {}", local_port);
                    }
                }
            }
        }
    }

    fn try_resolve_dns_group(
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        dns_cache: &mut Cache<String, DnsCacheValue>,
        group_id: u32,
    ) {
        let group = match dns_groups.get_mut(&group_id) {
            Some(g) => g,
            None => return,
        };

        // Happy Eyeballs: send response early if we have a usable result
        if group.response.is_some() {
            let result = match group.prefer_ipv6 {
                true => match (&group.ipv6_result, &group.ipv4_result) {
                    (Some(Ok(v6_records)), _) if !v6_records.is_empty() => {
                        log::debug!("DNS resolved (IPv6): {:?}", v6_records[0].address);
                        Some(Ok(v6_records[0].address))
                    }
                    (_, Some(Ok(v4_records))) if !v4_records.is_empty() => {
                        log::debug!("DNS resolved (IPv4): {:?}", v4_records[0].address);
                        Some(Ok(v4_records[0].address))
                    }
                    (Some(_), Some(_)) => {
                        let err = match (&group.ipv6_result, &group.ipv4_result) {
                            (Some(Err(e6)), _) if !matches!(e6, DnsError::NoRecords) => e6.clone(),
                            (_, Some(Err(e4))) if !matches!(e4, DnsError::NoRecords) => e4.clone(),
                            _ => DnsError::NoRecords,
                        };
                        log::debug!("DNS resolution failed: {:?}", err);
                        Some(Err(err))
                    }
                    _ => None,
                },
                false => match (&group.ipv4_result, &group.ipv6_result) {
                    (Some(Ok(v4_records)), _) if !v4_records.is_empty() => {
                        log::debug!("DNS resolved (IPv4): {:?}", v4_records[0].address);
                        Some(Ok(v4_records[0].address))
                    }
                    (_, Some(Ok(v6_records))) if !v6_records.is_empty() => {
                        log::debug!("DNS resolved (IPv6): {:?}", v6_records[0].address);
                        Some(Ok(v6_records[0].address))
                    }
                    (Some(_), Some(_)) => {
                        let err = match (&group.ipv4_result, &group.ipv6_result) {
                            (Some(Err(e4)), _) if !matches!(e4, DnsError::NoRecords) => e4.clone(),
                            (_, Some(Err(e6))) if !matches!(e6, DnsError::NoRecords) => e6.clone(),
                            _ => DnsError::NoRecords,
                        };
                        log::debug!("DNS resolution failed: {:?}", err);
                        Some(Err(err))
                    }
                    _ => None,
                },
            };

            // Send response early (Happy Eyeballs), but keep group for cache update
            if let Some(res) = result {
                let mapped = res.map_err(ManagerError::Dns);
                if let Some(response) = group.response.take()
                    && response.send(mapped).is_err()
                {
                    log::trace!("Failed to send DNS response: receiver dropped");
                }
            }
        }

        // Check if both queries completed - then update cache and cleanup
        if group.ipv4_result.is_some() && group.ipv6_result.is_some() {
            // Update cache with all records
            let mut all_records: Vec<DnsRecord> = Vec::new();
            if let Some(Ok(v4)) = &group.ipv4_result {
                all_records.extend(v4.iter().cloned());
            }
            if let Some(Ok(v6)) = &group.ipv6_result {
                all_records.extend(v6.iter().cloned());
            }
            if !all_records.is_empty() {
                let domain = group.domain.clone();
                dns_cache_insert(dns_cache, domain.clone(), &all_records);
                log::debug!(
                    "DNS cache updated: {} ({} records)",
                    domain,
                    all_records.len()
                );
            }

            // Handle response_all: return all addresses when both queries complete
            if let Some(response_all) = group.response_all.take() {
                let all_ips: Vec<IpAddress> = all_records.iter().map(|r| r.address).collect();
                if all_ips.is_empty() {
                    let err = match (&group.ipv4_result, &group.ipv6_result) {
                        (Some(Err(e4)), _) if !matches!(e4, DnsError::NoRecords) => e4.clone(),
                        (_, Some(Err(e6))) if !matches!(e6, DnsError::NoRecords) => e6.clone(),
                        _ => DnsError::NoRecords,
                    };
                    log::debug!("DNS resolution (all) failed: {:?}", err);
                    if response_all.send(Err(ManagerError::Dns(err))).is_err() {
                        log::trace!("Failed to send DNS response (all): receiver dropped");
                    }
                } else {
                    log::debug!("DNS resolved (all): {} addresses", all_ips.len());
                    if response_all.send(Ok(all_ips)).is_err() {
                        log::trace!("Failed to send DNS response (all): receiver dropped");
                    }
                }
            }

            // Remove group and cleanup queries
            dns_groups.remove(&group_id);
            dns_queries.retain(|_, s| s.group_id != group_id);
        }
    }

    fn handle_udp_recv(
        tunnel: &mut MasqueTunnel,
        stack: &mut NetworkStack,
        data: &mut [u8],
        from: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) {
        let recv_info = quiche::RecvInfo {
            from,
            to: local_addr,
        };

        if let Err(e) = tunnel.quic_conn.conn.recv(data, recv_info) {
            log::warn!("QUIC recv error: {:?}", e);
            return;
        }

        tunnel.poll_h3();

        let mut dgram_buf = [0u8; 65535];
        loop {
            match tunnel.recv_datagram(&mut dgram_buf) {
                Ok(len) if len > 0 => {
                    stack.inject_packet(&dgram_buf[..len]);
                }
                _ => break,
            }
        }
    }

    /// Common poll logic shared by MASQUE and WG modes:
    /// stack poll, socket notifications, DNS/UDP processing, TCP I/O, cleanup.
    fn poll_stack_common(state: &mut RuntimeState) -> bool {
        if let Err(e) = state.stack.poll() {
            log::error!("smoltcp poll failed, restarting tunnel: {}", e);
            return false;
        }

        Self::notify_ready_waiters(&mut state.stack, &mut state.sockets);

        Self::process_dns_responses(
            &mut state.stack,
            &mut state.dns_queries,
            &mut state.dns_groups,
            &mut state.dns_cache,
            &state.dns_sockets,
        );

        Self::process_udp_responses(&mut state.stack, &mut state.udp_sessions);

        // Cleanup timed out DNS groups (5 second timeout)
        let now = Instant::now();
        let timed_out_groups: Vec<u32> = state
            .dns_groups
            .iter()
            .filter(|(_, group)| now.duration_since(group.created_at) > Duration::from_secs(5))
            .map(|(id, _)| *id)
            .collect();

        for group_id in timed_out_groups {
            let query_ids: Vec<u16> = state
                .dns_queries
                .iter()
                .filter(|(_, s)| s.group_id == group_id)
                .map(|(id, _)| *id)
                .collect();
            for id in query_ids {
                state.dns_queries.remove(&id);
            }
            if let Some(mut group) = state.dns_groups.remove(&group_id) {
                if let Some(response) = group.response.take()
                    && response
                        .send(Err(ManagerError::Dns(DnsError::Timeout)))
                        .is_err()
                {
                    log::trace!("Failed to send DNS timeout response: receiver dropped");
                }
                if let Some(response_all) = group.response_all.take()
                    && response_all
                        .send(Err(ManagerError::Dns(DnsError::Timeout)))
                        .is_err()
                {
                    log::trace!("Failed to send DNS timeout response (all): receiver dropped");
                }
            }
        }

        // Cleanup stale UDP sessions
        let stale_ports: Vec<u16> = state
            .udp_sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.last_activity) > UDP_SESSION_TIMEOUT)
            .map(|(port, _)| *port)
            .collect();
        for port in stale_ports {
            if let Some(session) = state.udp_sessions.remove(&port) {
                state.stack.remove_socket(session.handle);
                log::debug!("Cleaned up stale UDP session on port {}", port);
            }
        }

        let handles: Vec<SocketHandle> = state.sockets.keys().copied().collect();
        let mut closed_handles = Vec::new();

        for handle in handles {
            if !state.stack.tcp_is_active(handle) {
                closed_handles.push(handle);
                continue;
            }

            let mut should_close = false;
            if let Some(socket_state) = state.sockets.get_mut(&handle) {
                if Self::flush_pending_to_client(socket_state) {
                    should_close = true;
                }

                if !should_close
                    && state.stack.tcp_may_recv(handle)
                    && socket_state.pending_to_client_bytes < MAX_PENDING_TO_CLIENT
                {
                    let available =
                        MAX_PENDING_TO_CLIENT.saturating_sub(socket_state.pending_to_client_bytes);
                    let read_len = available.min(MAX_TCP_READ_CHUNK);
                    if read_len > 0 {
                        if state.read_buffer.len() < read_len {
                            state.read_buffer.resize(read_len, 0);
                        }
                        if let Ok(n) = state.stack.tcp_recv(handle, &mut state.read_buffer[..read_len])
                            && n > 0
                        {
                            let data = Bytes::copy_from_slice(&state.read_buffer[..n]);
                            match Self::deliver_to_client(handle, socket_state, data) {
                                Ok(()) | Err(DeliverError::Backpressure) => {}
                                Err(DeliverError::Closed) => {
                                    log::trace!("TCP channel closed for socket {:?}", handle);
                                    should_close = true;
                                }
                            }
                        }
                    }
                }

                if !should_close {
                    Self::flush_pending_to_stack(&mut state.stack, handle, socket_state);

                    if socket_state.pending_from_client_bytes < MAX_PENDING_DATA {
                        while let Ok(data) = socket_state.from_client.try_recv() {
                            socket_state.pending_from_client_bytes += data.len();
                            socket_state.pending_from_client.push_back(data);
                            if socket_state.pending_from_client_bytes >= MAX_PENDING_DATA {
                                log::debug!(
                                    "Pending data exceeded limit for socket {:?} ({} bytes), applying backpressure",
                                    handle,
                                    socket_state.pending_from_client_bytes
                                );
                                break;
                            }
                        }
                    }

                    Self::flush_pending_to_stack(&mut state.stack, handle, socket_state);
                }
            }

            if should_close {
                state.stack.tcp_close(handle);
                closed_handles.push(handle);
            }
        }

        for handle in closed_handles {
            state.sockets.remove(&handle);
            state.stack.remove_socket(handle);
        }

        true
    }

    async fn poll_all(
        tunnel: &mut MasqueTunnel,
        state: &mut RuntimeState,
        last_keepalive: &mut Instant,
        keepalive_interval: Duration,
    ) -> bool {
        // Send keepalive PING if interval elapsed
        if last_keepalive.elapsed() >= keepalive_interval {
            if let Err(e) = tunnel.quic_conn.conn.send_ack_eliciting() {
                log::warn!("Failed to send keepalive PING: {:?}", e);
            } else {
                log::debug!("Sent keepalive PING frame");
            }
            *last_keepalive = Instant::now();
        }

        if !Self::poll_stack_common(state) {
            return false;
        }

        while let Some(packet) = state.stack.take_packet() {
            let send_result = tunnel.send_datagram(packet.as_ref());
            state.stack.recycle_tx_buffer(packet);
            match send_result {
                Ok(Some(icmp)) => {
                    log::debug!("Injecting ICMP Packet Too Big ({} bytes)", icmp.len());
                    state.stack.inject_packet(&icmp);
                }
                Ok(None) => {}
                Err(e) => {
                    log::warn!("Failed to send datagram: {:?}", e);
                }
            }
        }

        if let Err(e) = tunnel.quic_conn.send_async().await {
            log::warn!("Failed to send QUIC data: {:?}", e);
        }
        true
    }

    async fn poll_all_wg(tunnel: &mut WgTunnel, state: &mut RuntimeState) -> bool {
        if !Self::poll_stack_common(state) {
            return false;
        }

        while let Some(packet) = state.stack.take_packet() {
            tunnel.encrypt_ip_packet(packet.as_ref());
            state.stack.recycle_tx_buffer(packet);
        }
        tunnel.flush_send_queue().await;
        true
    }

    /// Common flush logic: poll stack + TCP read handling.
    fn flush_stack_reads(state: &mut RuntimeState) -> bool {
        if let Err(e) = state.stack.poll() {
            log::error!("smoltcp poll failed, restarting tunnel: {}", e);
            return false;
        }

        let handles: Vec<SocketHandle> = state.sockets.keys().copied().collect();
        for handle in handles {
            let Some(socket_state) = state.sockets.get_mut(&handle) else {
                continue;
            };

            if Self::flush_pending_to_client(socket_state) {
                log::trace!("TCP channel closed for socket {:?}", handle);
                state.stack.tcp_close(handle);
                continue;
            }
            if socket_state.pending_to_client_bytes >= MAX_PENDING_TO_CLIENT
                || !state.stack.tcp_may_recv(handle)
            {
                continue;
            }

            let available =
                MAX_PENDING_TO_CLIENT.saturating_sub(socket_state.pending_to_client_bytes);
            let read_len = available.min(MAX_TCP_READ_CHUNK);
            if read_len == 0 {
                continue;
            }

            if state.read_buffer.len() < read_len {
                state.read_buffer.resize(read_len, 0);
            }
            if let Ok(n) = state.stack.tcp_recv(handle, &mut state.read_buffer[..read_len])
                && n > 0
            {
                let data = Bytes::copy_from_slice(&state.read_buffer[..n]);
                match Self::deliver_to_client(handle, socket_state, data) {
                    Ok(()) | Err(DeliverError::Backpressure) => {}
                    Err(DeliverError::Closed) => {
                        log::trace!("TCP channel closed for socket {:?}", handle);
                        state.stack.tcp_close(handle);
                    }
                }
            }
        }

        true
    }

    async fn flush_outbound(
        tunnel: &mut MasqueTunnel,
        state: &mut RuntimeState,
    ) -> bool {
        if !Self::flush_stack_reads(state) {
            return false;
        }

        while let Some(packet) = state.stack.take_packet() {
            let send_result = tunnel.send_datagram(packet.as_ref());
            state.stack.recycle_tx_buffer(packet);
            if let Err(e) = send_result {
                log::debug!("Failed to send datagram: {:?}", e);
            }
        }

        if let Err(e) = tunnel.quic_conn.send_async().await {
            log::debug!("Failed to send QUIC data: {:?}", e);
        }
        true
    }

    async fn flush_outbound_wg(
        tunnel: &mut WgTunnel,
        state: &mut RuntimeState,
    ) -> bool {
        if !Self::flush_stack_reads(state) {
            return false;
        }

        while let Some(packet) = state.stack.take_packet() {
            tunnel.encrypt_ip_packet(packet.as_ref());
            state.stack.recycle_tx_buffer(packet);
        }
        tunnel.flush_send_queue().await;
        true
    }

    fn flush_pending_to_client(state: &mut SocketState) -> bool {
        while let Some(data) = state.pending_to_client.pop_front() {
            let len = data.len();
            match state.to_client.try_send(data) {
                Ok(()) => {
                    state.pending_to_client_bytes =
                        state.pending_to_client_bytes.saturating_sub(len);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                    state.pending_to_client.push_front(data);
                    break;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    state.pending_to_client.clear();
                    state.pending_to_client_bytes = 0;
                    return true;
                }
            }
        }
        false
    }

    fn flush_pending_to_stack(
        stack: &mut NetworkStack,
        handle: SocketHandle,
        state: &mut SocketState,
    ) {
        if !stack.tcp_may_send(handle) {
            return;
        }

        while let Some(data) = state.pending_from_client.pop_front() {
            let len = data.len();
            state.pending_from_client_bytes = state.pending_from_client_bytes.saturating_sub(len);

            match stack.tcp_send(handle, &data) {
                Ok(0) => {
                    state.pending_from_client_bytes += len;
                    state.pending_from_client.push_front(data);
                    break;
                }
                Ok(sent) if sent < len => {
                    let remaining = data.slice(sent..);
                    state.pending_from_client_bytes += remaining.len();
                    state.pending_from_client.push_front(remaining);
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    state.pending_from_client_bytes += len;
                    state.pending_from_client.push_front(data);
                    break;
                }
            }

            if !stack.tcp_may_send(handle) {
                break;
            }
        }
    }

    fn deliver_to_client(
        handle: SocketHandle,
        state: &mut SocketState,
        data: Bytes,
    ) -> Result<(), DeliverError> {
        match state.to_client.try_send(data) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                if state.pending_to_client_bytes + data.len() > MAX_PENDING_TO_CLIENT {
                    log::debug!(
                        "Pending to-client data exceeded limit for socket {:?} ({} bytes), applying backpressure",
                        handle,
                        state.pending_to_client_bytes + data.len()
                    );
                    return Err(DeliverError::Backpressure);
                }
                state.pending_to_client_bytes += data.len();
                state.pending_to_client.push_back(data);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(DeliverError::Closed),
        }
    }

    fn select_dns_server(dns_servers: &[IpAddress], prefer_ipv6: bool) -> IpAddress {
        if dns_servers.is_empty() {
            return IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(1, 1, 1, 1));
        }

        let start = DNS_SERVER_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let len = dns_servers.len();
        for offset in 0..len {
            let idx = (start + offset) % len;
            let server = dns_servers[idx];
            if prefer_ipv6 && matches!(server, IpAddress::Ipv6(_)) {
                return server;
            }
            if !prefer_ipv6 && matches!(server, IpAddress::Ipv4(_)) {
                return server;
            }
        }

        dns_servers[start % len]
    }
}
