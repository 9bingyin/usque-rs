use crate::net::tunnel::dns::{
    DnsError, DnsRecord, DnsRecordType, build_dns_query, dns_port, get_dns_local_port,
    parse_dns_response_with_id,
};
use crate::net::tunnel::masque::MasqueTunnel;
use crate::net::tunnel::quic;
use crate::net::tunnel::stack::{BufferPool, DeviceStats, NetworkStack, StackError, StackTunables};
use crate::net::tunnel::wireguard::WgTunnel;
use bytes::{Bytes, BytesMut};
use quick_cache::unsync::Cache;
use rand::Rng;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpAddress;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant as TokioInstant;

use crate::net::tunnel::quic::{CongestionControl, QuicPerfStats, QuicSendStatus};
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};

#[derive(Clone, Debug)]
pub struct ManagerTunables {
    pub cmd_channel_capacity: usize,
    pub udp_data_channel_capacity: usize,
    pub incoming_dgram_capacity: usize,
    pub udp_recv_buffer_size: usize,
    pub tcp_chunk_size: usize,
    pub udp_session_timeout: Duration,
    pub max_pending_data: usize,
    pub max_pending_to_client: usize,
    pub udp_batch_read_budget: usize,
    pub stack_ingress_budget: usize,
    pub cmd_batch_budget: usize,
    pub udp_batch_budget: usize,
    pub socket_event_batch_budget: usize,
    pub targeted_tcp_sweep_budget: usize,
    pub masque_io_channel_capacity: usize,
    pub masque_send_batch_size: usize,
    pub masque_stack_drain_budget: usize,
    pub wg_stack_drain_budget: usize,
    pub pool_max_size: usize,
    pub max_poll_interval: Duration,
    pub wg_timer_interval: Duration,
    pub wg_udp_recv_buffer_size: usize,
    pub wg_udp_send_buffer_size: usize,
}

impl Default for ManagerTunables {
    fn default() -> Self {
        Self {
            cmd_channel_capacity: 1024,
            udp_data_channel_capacity: 1024,
            incoming_dgram_capacity: 4096,
            udp_recv_buffer_size: 65535,
            tcp_chunk_size: 64 * 1024,
            udp_session_timeout: Duration::from_secs(300),
            max_pending_data: 256 * 1024,
            max_pending_to_client: 256 * 1024,
            udp_batch_read_budget: 128,
            stack_ingress_budget: 64,
            cmd_batch_budget: 128,
            udp_batch_budget: 128,
            socket_event_batch_budget: 128,
            targeted_tcp_sweep_budget: 64,
            masque_io_channel_capacity: 1024,
            masque_send_batch_size: 32,
            masque_stack_drain_budget: 128,
            wg_stack_drain_budget: 256,
            pool_max_size: 256,
            max_poll_interval: Duration::from_millis(50),
            wg_timer_interval: Duration::from_millis(250),
            wg_udp_recv_buffer_size: 4 * 1024 * 1024,
            wg_udp_send_buffer_size: 2 * 1024 * 1024,
        }
    }
}

impl ManagerTunables {
    pub fn from_env() -> Self {
        fn env_usize(name: &str, default: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        fn env_duration_ms(name: &str, default: Duration) -> Duration {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_millis)
                .unwrap_or(default)
        }

        fn env_duration_secs(name: &str, default: Duration) -> Duration {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(default)
        }

        let defaults = Self::default();
        Self {
            cmd_channel_capacity: env_usize(
                "USQUE_CMD_CHANNEL_CAPACITY",
                defaults.cmd_channel_capacity,
            ),
            udp_data_channel_capacity: env_usize(
                "USQUE_UDP_CHANNEL_CAPACITY",
                defaults.udp_data_channel_capacity,
            ),
            incoming_dgram_capacity: env_usize(
                "USQUE_INCOMING_DGRAM_CAPACITY",
                defaults.incoming_dgram_capacity,
            ),
            udp_recv_buffer_size: env_usize(
                "USQUE_INCOMING_UDP_BUFFER_SIZE",
                defaults.udp_recv_buffer_size,
            ),
            tcp_chunk_size: env_usize("USQUE_TCP_CHUNK_SIZE", defaults.tcp_chunk_size),
            udp_session_timeout: env_duration_secs(
                "USQUE_UDP_SESSION_TIMEOUT_SECS",
                defaults.udp_session_timeout,
            ),
            max_pending_data: env_usize("USQUE_MAX_PENDING_DATA", defaults.max_pending_data),
            max_pending_to_client: env_usize(
                "USQUE_MAX_PENDING_TO_CLIENT",
                defaults.max_pending_to_client,
            ),
            udp_batch_read_budget: env_usize(
                "USQUE_UDP_BATCH_READ_BUDGET",
                defaults.udp_batch_read_budget,
            ),
            stack_ingress_budget: env_usize(
                "USQUE_STACK_INGRESS_BUDGET",
                defaults.stack_ingress_budget,
            ),
            cmd_batch_budget: env_usize("USQUE_CMD_BATCH_BUDGET", defaults.cmd_batch_budget),
            udp_batch_budget: env_usize("USQUE_UDP_BATCH_BUDGET", defaults.udp_batch_budget),
            socket_event_batch_budget: env_usize(
                "USQUE_SOCKET_EVENT_BATCH_BUDGET",
                defaults.socket_event_batch_budget,
            ),
            targeted_tcp_sweep_budget: env_usize(
                "USQUE_TARGETED_TCP_SWEEP_BUDGET",
                defaults.targeted_tcp_sweep_budget,
            ),
            masque_io_channel_capacity: env_usize(
                "USQUE_MASQUE_IO_CHANNEL_CAPACITY",
                defaults.masque_io_channel_capacity,
            ),
            masque_send_batch_size: env_usize(
                "USQUE_MASQUE_SEND_BATCH_SIZE",
                defaults.masque_send_batch_size,
            )
            .max(1),
            masque_stack_drain_budget: env_usize(
                "USQUE_MASQUE_STACK_DRAIN_BUDGET",
                defaults.masque_stack_drain_budget,
            ),
            wg_stack_drain_budget: env_usize(
                "USQUE_WG_STACK_DRAIN_BUDGET",
                defaults.wg_stack_drain_budget,
            ),
            pool_max_size: env_usize("USQUE_BUFFER_POOL_MAX_SIZE", defaults.pool_max_size),
            max_poll_interval: env_duration_ms(
                "USQUE_MAX_POLL_INTERVAL_MS",
                defaults.max_poll_interval,
            ),
            wg_timer_interval: env_duration_ms(
                "USQUE_WG_TIMER_INTERVAL_MS",
                defaults.wg_timer_interval,
            ),
            wg_udp_recv_buffer_size: env_usize(
                "USQUE_WG_UDP_RECVBUF",
                defaults.wg_udp_recv_buffer_size,
            ),
            wg_udp_send_buffer_size: env_usize(
                "USQUE_WG_UDP_SNDBUF",
                defaults.wg_udp_send_buffer_size,
            ),
        }
    }
}

/// Format IpAddress for logging (IPv6 uses bracket notation)
fn format_ip(ip: IpAddress) -> String {
    match ip {
        IpAddress::Ipv4(v4) => format!("{}", v4),
        IpAddress::Ipv6(v6) => format!("[{}]", v6),
    }
}

include!("manager/backoff.rs");

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
    pub perf_enabled: bool,
    pub perf_interval_secs: u64,
    pub manager_tunables: ManagerTunables,
    pub stack_tunables: StackTunables,
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
        response: oneshot::Sender<Result<SocketStream, ManagerError>>,
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

include!("manager/buffer.rs");
#[derive(Clone, Copy)]
enum SocketEventKind {
    ReadReady,
    WriteReady,
    Closed,
}

impl SocketEventKind {
    const fn bit(self) -> u8 {
        match self {
            SocketEventKind::ReadReady => 1 << 0,
            SocketEventKind::WriteReady => 1 << 1,
            SocketEventKind::Closed => 1 << 2,
        }
    }
}

const SOCKET_EVENT_READ: u8 = SocketEventKind::ReadReady.bit();
const SOCKET_EVENT_WRITE: u8 = SocketEventKind::WriteReady.bit();
const SOCKET_EVENT_CLOSED: u8 = SocketEventKind::Closed.bit();

struct SocketEvent {
    handle: SocketHandle,
    kind: SocketEventKind,
}
include!("manager/stream.rs");

// Internal state for each socket
struct SocketState {
    stream: Arc<SocketStreamHandle>,
    flow_key: Option<TcpFlowKey>,
    pending_events: u8,
    close_requested: bool,
    write_shutdown: bool,
    fin_sent: bool,
    // Waiters for socket ready notification (event-driven instead of polling)
    ready_waiters: Vec<oneshot::Sender<TcpSocketState>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    local_port: u16,
    remote_ip: IpAddress,
    remote_port: u16,
}

impl SocketState {
    fn buffered_from_client_bytes(&self) -> usize {
        self.stream.send_buffer.len()
    }

    fn buffered_to_client_bytes(&self) -> usize {
        self.stream.recv_buffer.len()
    }
}

include!("manager/dns_cache.rs");

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
}

enum TransportIoEvent {
    Incoming(IncomingDatagram),
    QuicFlush(QuicSendStatus),
    MasqueBlocked,
}

#[derive(Default, Clone, Copy)]
struct IncomingHandling {
    stack_ingress: bool,
    needs_transport_flush: bool,
}

include!("manager/masque_io.rs");

enum TunnelConn {
    Masque(Box<MasqueTunnel>, NetworkStack),
    Wg(Box<WgTunnel>, NetworkStack),
}

enum ActiveTunnel {
    Masque {
        io: MasqueIoHandle,
        blocked_streak: u8,
        blocked_until: Option<TokioInstant>,
    },
    Wg {
        tunnel: Box<WgTunnel>,
        next_timer_at: TokioInstant,
    },
}

struct IncomingTask {
    incoming_rx: mpsc::Receiver<TransportIoEvent>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    completion_tx: Option<mpsc::Sender<()>>,
    completion_rx: Option<mpsc::Receiver<()>>,
    recv_handle: Option<tokio::task::JoinHandle<()>>,
}

struct PerfSnapshot {
    sockets: usize,
    udp_sessions: usize,
    dns_groups: usize,
    pending_from_client_bytes: usize,
    pending_to_client_bytes: usize,
    rx_queue_len: usize,
    tx_queue_len: usize,
    rx_drops: u64,
    tx_drops: u64,
    cmd_queue_len: usize,
    udp_queue_len: usize,
    incoming_queue_len: usize,
    ready_tcp_queue_len: usize,
    transport_pending_send_packets: usize,
    quic_stats: Option<QuicPerfStats>,
}

struct PerfCounters {
    enabled: bool,
    interval: Duration,
    last_report: Instant,
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    poll_count: u64,
    loop_iterations: u64,
    scheduler_yields: u64,
    masque_blocked_events: u64,
    masque_send_batches: u64,
    masque_send_packets: u64,
    quic_socket_blocked: u64,
    quic_send_enobufs: u64,
    quic_pacing_events: u64,
    wg_flushes: u64,
    socket_event_batches: u64,
    socket_events: u64,
    full_tcp_sweeps: u64,
    targeted_tcp_sweeps: u64,
}

impl PerfCounters {
    fn new(enabled: bool, interval_secs: u64) -> Self {
        let interval = Duration::from_secs(interval_secs.max(1));
        Self {
            enabled,
            interval,
            last_report: Instant::now(),
            rx_packets: 0,
            rx_bytes: 0,
            tx_packets: 0,
            tx_bytes: 0,
            poll_count: 0,
            loop_iterations: 0,
            scheduler_yields: 0,
            masque_blocked_events: 0,
            masque_send_batches: 0,
            masque_send_packets: 0,
            quic_socket_blocked: 0,
            quic_send_enobufs: 0,
            quic_pacing_events: 0,
            wg_flushes: 0,
            socket_event_batches: 0,
            socket_events: 0,
            full_tcp_sweeps: 0,
            targeted_tcp_sweeps: 0,
        }
    }

    fn due(&self) -> bool {
        self.enabled && self.last_report.elapsed() >= self.interval
    }

    fn inc_loop(&mut self) {
        if self.enabled {
            self.loop_iterations += 1;
        }
    }

    fn inc_poll(&mut self) {
        if self.enabled {
            self.poll_count += 1;
        }
    }

    fn inc_rx(&mut self, bytes: usize) {
        if self.enabled {
            self.rx_packets += 1;
            self.rx_bytes += bytes as u64;
        }
    }

    fn inc_tx(&mut self, bytes: usize) {
        if self.enabled {
            self.tx_packets += 1;
            self.tx_bytes += bytes as u64;
        }
    }

    fn inc_yield(&mut self) {
        if self.enabled {
            self.scheduler_yields += 1;
        }
    }

    fn inc_masque_blocked(&mut self) {
        if self.enabled {
            self.masque_blocked_events += 1;
        }
    }

    fn record_masque_send_batch(&mut self, status: QuicSendStatus) {
        if !self.enabled {
            return;
        }
        if status.packets_sent > 0 {
            self.masque_send_batches += 1;
            self.masque_send_packets += status.packets_sent as u64;
        }
        if status.blocked {
            self.quic_socket_blocked += 1;
        }
        if status.enobufs {
            self.quic_send_enobufs += 1;
        }
        if status.paced {
            self.quic_pacing_events += 1;
        }
    }

    fn inc_wg_flush(&mut self) {
        if self.enabled {
            self.wg_flushes += 1;
        }
    }

    fn inc_socket_event_batch(&mut self, count: usize) {
        if self.enabled && count > 0 {
            self.socket_event_batches += 1;
            self.socket_events += count as u64;
        }
    }

    fn inc_tcp_sweep(&mut self, full_sweep: bool) {
        if self.enabled {
            if full_sweep {
                self.full_tcp_sweeps += 1;
            } else {
                self.targeted_tcp_sweeps += 1;
            }
        }
    }

    fn report(&mut self, snapshot: PerfSnapshot) {
        if !self.enabled {
            return;
        }
        let elapsed = self.last_report.elapsed();
        if elapsed < self.interval {
            return;
        }
        let secs = elapsed.as_secs_f64();
        log::info!(
            "PERF: rx={:.0}pps ({:.1}Mbps) tx={:.0}pps ({:.1}Mbps) polls={:.0}/s loops={:.0}/s yields={:.0}/s masque_blocked={:.0}/s masque_send_batches={:.0}/s masque_send_pkts={:.0}/s quic_socket_blocked={:.0}/s quic_enobufs={:.0}/s quic_pacing={:.0}/s quic_rtt={}ms quic_cwnd={} quic_lost={} quic_pto={} quic_delivery_est={:.1}Mbps quic_dgram_rx_total={} quic_dgram_tx_total={} wg_flushes={:.0}/s socket_event_batches={:.0}/s socket_events={:.0}/s tcp_sweeps_full={:.0}/s tcp_sweeps_targeted={:.0}/s sockets={} udp_sessions={} dns_groups={} pending_from={}B pending_to={}B rx_q={} tx_q={} drops_rx={} drops_tx={} cmd_q={} udp_q={} in_q={} ready_tcp_q={} transport_pending={}",
            self.rx_packets as f64 / secs,
            self.rx_bytes as f64 * 8.0 / secs / 1_000_000.0,
            self.tx_packets as f64 / secs,
            self.tx_bytes as f64 * 8.0 / secs / 1_000_000.0,
            self.poll_count as f64 / secs,
            self.loop_iterations as f64 / secs,
            self.scheduler_yields as f64 / secs,
            self.masque_blocked_events as f64 / secs,
            self.masque_send_batches as f64 / secs,
            self.masque_send_packets as f64 / secs,
            self.quic_socket_blocked as f64 / secs,
            self.quic_send_enobufs as f64 / secs,
            self.quic_pacing_events as f64 / secs,
            snapshot.quic_stats.map_or(0, |stats| stats.rtt_ms),
            snapshot.quic_stats.map_or(0, |stats| stats.cwnd),
            snapshot.quic_stats.map_or(0, |stats| stats.lost),
            snapshot.quic_stats.map_or(0, |stats| stats.total_pto_count),
            snapshot.quic_stats.map_or(0.0, |stats| {
                stats.delivery_rate_bps as f64 * 8.0 / 1_000_000.0
            }),
            snapshot.quic_stats.map_or(0, |stats| stats.dgram_recv),
            snapshot.quic_stats.map_or(0, |stats| stats.dgram_sent),
            self.wg_flushes as f64 / secs,
            self.socket_event_batches as f64 / secs,
            self.socket_events as f64 / secs,
            self.full_tcp_sweeps as f64 / secs,
            self.targeted_tcp_sweeps as f64 / secs,
            snapshot.sockets,
            snapshot.udp_sessions,
            snapshot.dns_groups,
            snapshot.pending_from_client_bytes,
            snapshot.pending_to_client_bytes,
            snapshot.rx_queue_len,
            snapshot.tx_queue_len,
            snapshot.rx_drops,
            snapshot.tx_drops,
            snapshot.cmd_queue_len,
            snapshot.udp_queue_len,
            snapshot.incoming_queue_len,
            snapshot.ready_tcp_queue_len,
            snapshot.transport_pending_send_packets,
        );
        self.last_report = Instant::now();
        self.rx_packets = 0;
        self.rx_bytes = 0;
        self.tx_packets = 0;
        self.tx_bytes = 0;
        self.poll_count = 0;
        self.loop_iterations = 0;
        self.scheduler_yields = 0;
        self.masque_blocked_events = 0;
        self.masque_send_batches = 0;
        self.masque_send_packets = 0;
        self.quic_socket_blocked = 0;
        self.quic_send_enobufs = 0;
        self.quic_pacing_events = 0;
        self.wg_flushes = 0;
        self.socket_event_batches = 0;
        self.socket_events = 0;
        self.full_tcp_sweeps = 0;
        self.targeted_tcp_sweeps = 0;
    }
}

struct RuntimeState {
    stack: NetworkStack,
    tunables: ManagerTunables,
    sockets: HashMap<SocketHandle, SocketState>,
    tcp_flow_map: HashMap<TcpFlowKey, SocketHandle>,
    // Keep in sync with sockets for fast iteration without per-loop allocations.
    tcp_handles: Vec<SocketHandle>,
    ready_tcp_handles: VecDeque<SocketHandle>,
    ready_tcp_set: HashSet<SocketHandle>,
    socket_event_tx: mpsc::UnboundedSender<SocketEvent>,
    socket_event_rx: mpsc::UnboundedReceiver<SocketEvent>,
    dns_queries: HashMap<u16, DnsQueryState>,
    dns_groups: HashMap<u32, DnsQueryGroup>,
    dns_sockets: DnsSockets,
    dns_cache: Cache<String, DnsCacheValue>,
    udp_sessions: HashMap<u16, UdpSessionState>,
    // Keep in sync with udp_sessions for fast iteration without per-loop allocations.
    udp_ports: Vec<u16>,
    udp_buffer: BytesMut,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    buffer_pool: BufferPool,
    perf: PerfCounters,
}

impl RuntimeState {
    fn new(
        stack: NetworkStack,
        tunables: ManagerTunables,
        perf_enabled: bool,
        perf_interval_secs: u64,
    ) -> Self {
        let buffer_pool = stack.buffer_pool();
        let (socket_event_tx, socket_event_rx) = mpsc::unbounded_channel();
        let tcp_chunk_size = tunables.tcp_chunk_size;
        let udp_recv_buffer_size = tunables.udp_recv_buffer_size;
        Self {
            stack,
            tunables,
            sockets: HashMap::new(),
            tcp_flow_map: HashMap::new(),
            tcp_handles: Vec::new(),
            ready_tcp_handles: VecDeque::new(),
            ready_tcp_set: HashSet::new(),
            socket_event_tx,
            socket_event_rx,
            dns_queries: HashMap::new(),
            dns_groups: HashMap::new(),
            dns_sockets: DnsSockets::new(),
            dns_cache: Cache::new(DNS_CACHE_CAPACITY),
            udp_sessions: HashMap::new(),
            udp_ports: Vec::new(),
            udp_buffer: BytesMut::zeroed(udp_recv_buffer_size),
            read_buffer: BytesMut::zeroed(tcp_chunk_size),
            write_buffer: BytesMut::zeroed(tcp_chunk_size),
            buffer_pool,
            perf: PerfCounters::new(perf_enabled, perf_interval_secs),
        }
    }

    fn has_poll_work(&self) -> bool {
        if !self.udp_ports.is_empty() || !self.dns_queries.is_empty() || !self.dns_groups.is_empty()
        {
            return true;
        }

        if self.sockets.values().any(|socket| {
            socket.buffered_from_client_bytes() > 0
                || socket.buffered_to_client_bytes() > 0
                || socket.close_requested
        }) {
            return true;
        }

        let (rx_queue_len, tx_queue_len) = self.stack.queue_lengths();
        rx_queue_len > 0 || tx_queue_len > 0 || !self.tcp_handles.is_empty()
    }

    fn enqueue_ready_tcp_handle(&mut self, handle: SocketHandle) {
        if self.ready_tcp_set.insert(handle) {
            self.ready_tcp_handles.push_back(handle);
        }
    }

    fn mark_ready_tcp_handle(&mut self, handle: SocketHandle, event_mask: u8) {
        if let Some(socket_state) = self.sockets.get_mut(&handle) {
            socket_state.pending_events |= event_mask;
        }
        self.enqueue_ready_tcp_handle(handle);
    }
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

include!("manager/transport.rs");
include!("manager/commands.rs");
include!("manager/dns_ops.rs");
include!("manager/io.rs");
include!("manager/phases.rs");
include!("manager/runloop.rs");
