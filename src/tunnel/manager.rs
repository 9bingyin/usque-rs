use crate::tunnel::dns::{
    build_dns_query, dns_port, get_dns_local_port, parse_dns_response, DnsError,
    DnsRecordType,
};
use crate::tunnel::masque::MasqueTunnel;
use crate::tunnel::quic;
use crate::tunnel::stack::NetworkStack;
use rand::Rng;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpAddress;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

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
}

// Commands sent from SOCKS5 connections to the manager
pub enum ManagerCommand {
    // Create a new TCP connection
    Connect {
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
        response: oneshot::Sender<Result<SocketChannels, String>>,
    },
    // Close a TCP connection
    Close {
        handle: SocketHandle,
    },
    // DNS resolution through tunnel
    DnsResolve {
        domain: String,
        prefer_ipv6: bool,
        response: oneshot::Sender<Result<IpAddress, DnsError>>,
    },
    // Register UDP session for receiving data from tunnel
    UdpRegister {
        local_port: u16,
        response: oneshot::Sender<Result<mpsc::Receiver<(IpAddress, u16, Vec<u8>)>, String>>,
    },
    // Send UDP data through tunnel
    UdpSend {
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
        data: Vec<u8>,
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
    pub to_stack: mpsc::Sender<Vec<u8>>,
    pub from_stack: mpsc::Receiver<Vec<u8>>,
}

// Internal state for each socket
struct SocketState {
    to_client: mpsc::Sender<Vec<u8>>,
    from_client: mpsc::Receiver<Vec<u8>>,
    pending_data: Vec<u8>,
    pending_to_client: VecDeque<Vec<u8>>,
    pending_to_client_bytes: usize,
}

// DNS query state for a single query (A or AAAA)
struct DnsQueryState {
    handle: SocketHandle,
    group_id: u32,
    query_type: DnsRecordType,
}

// Happy Eyeballs: tracks paired A/AAAA queries
struct DnsQueryGroup {
    response: oneshot::Sender<Result<IpAddress, DnsError>>,
    ipv4_result: Option<Result<Vec<IpAddress>, DnsError>>,
    ipv6_result: Option<Result<Vec<IpAddress>, DnsError>>,
    created_at: Instant,
    prefer_ipv6: bool,
}

// UDP session state for SOCKS5 UDP ASSOCIATE
struct UdpSessionState {
    handle: SocketHandle,
    to_client: mpsc::Sender<(IpAddress, u16, Vec<u8>)>,
    last_activity: Instant,
}

const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
const MAX_PENDING_DATA: usize = 4 * 1024 * 1024; // 4MB per socket
const MAX_PENDING_TO_CLIENT: usize = 4 * 1024 * 1024; // 4MB per socket

static DNS_GROUP_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
static DNS_SERVER_INDEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub struct TunnelManager {
    cmd_tx: mpsc::Sender<ManagerCommand>,
}

impl TunnelManager {
    pub fn new(params: ConnectionParams) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);

        tokio::spawn(Self::maintain_tunnel(params, cmd_rx));

        Self { cmd_tx }
    }

    async fn maintain_tunnel(
        params: ConnectionParams,
        mut cmd_rx: mpsc::Receiver<ManagerCommand>,
    ) {
        let mut backoff = ExponentialBackoff::new();

        loop {
            log::info!("Establishing MASQUE connection to {}", params.endpoint);

            let (conn_tx, mut conn_rx) = oneshot::channel();
            let params_clone = params.clone();
            tokio::spawn(async move {
                let res = Self::establish_connection(&params_clone).await;
                let _ = conn_tx.send(res);
            });

            loop {
                tokio::select! {
                    res = &mut conn_rx => {
                        match res {
                            Ok(Ok((tunnel, stack))) => {
                                log::info!("Tunnel connected successfully");
                                backoff.reset();
                                Self::run_loop(tunnel, stack, &mut cmd_rx, &params.dns_servers, params.keepalive).await;
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
                }
            }
        }
    }

    async fn establish_connection(
        params: &ConnectionParams,
    ) -> Result<(MasqueTunnel, NetworkStack), Box<dyn std::error::Error + Send + Sync>> {
        let quic_cfg = quic::QuicConfig {
            idle_timeout: params.keepalive * 1000,
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
        ).await?;

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

    pub async fn connect(
        &self,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<SocketChannels, String> {
        let (response_tx, response_rx) = oneshot::channel();

        self.cmd_tx
            .send(ManagerCommand::Connect {
                remote_ip,
                remote_port,
                local_port,
                response: response_tx,
            })
            .await
            .map_err(|_| "Manager channel closed".to_string())?;

        response_rx
            .await
            .map_err(|_| "Manager response channel closed".to_string())?
    }

    pub async fn close(&self, handle: SocketHandle) {
        if let Err(e) = self.cmd_tx.send(ManagerCommand::Close { handle }).await {
            log::debug!("Failed to send close command: {}", e);
        }
    }

    pub async fn get_socket_state(&self, handle: SocketHandle) -> TcpSocketState {
        let (response_tx, response_rx) = oneshot::channel();

        if self.cmd_tx
            .send(ManagerCommand::GetSocketState { handle, response: response_tx })
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

    pub async fn resolve(&self, domain: &str, prefer_ipv6: bool) -> Result<IpAddress, DnsError> {
        let (response_tx, response_rx) = oneshot::channel();

        self.cmd_tx
            .send(ManagerCommand::DnsResolve {
                domain: domain.to_string(),
                prefer_ipv6,
                response: response_tx,
            })
            .await
            .map_err(|_| DnsError::ChannelError)?;

        response_rx.await.map_err(|_| DnsError::ChannelError)?
    }

    async fn run_loop(
        mut tunnel: MasqueTunnel,
        mut stack: NetworkStack,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        dns_servers: &[IpAddress],
        keepalive_secs: u64,
    ) {
        let socket = tunnel.quic_conn.socket.clone();
        let local_addr = tunnel.quic_conn.local_addr;

        let mut buf = [0u8; 65535];
        let mut sockets: HashMap<SocketHandle, SocketState> = HashMap::new();
        let mut dns_queries: HashMap<u16, DnsQueryState> = HashMap::new(); // transaction_id -> state
        let mut dns_groups: HashMap<u32, DnsQueryGroup> = HashMap::new(); // group_id -> group
        let mut udp_sessions: HashMap<u16, UdpSessionState> = HashMap::new(); // local_port -> session

        // Keepalive tracking
        let mut last_keepalive = Instant::now();
        let keepalive_interval = Duration::from_secs(keepalive_secs);
        const MAX_POLL_INTERVAL: Duration = Duration::from_millis(50);

        loop {
            // Check connection status at the start of each iteration
            if tunnel.quic_conn.is_closed() {
                log::error!("QUIC connection closed");
                break;
            }

            // Dynamic timeout based on quiche's internal timer
            let quic_timeout = tunnel.quic_conn.conn.timeout()
                .unwrap_or(Duration::from_millis(100));
            let poll_timeout = quic_timeout.min(MAX_POLL_INTERVAL);

            tokio::select! {
                // Handle commands from SOCKS5 connections
                Some(cmd) = cmd_rx.recv() => {
                    Self::handle_command(&mut stack, &mut sockets, &mut dns_queries, &mut dns_groups, &mut udp_sessions, dns_servers, cmd);
                    if !Self::process_after_recv(&mut tunnel, &mut stack, &mut sockets).await {
                        break;
                    }
                }

                // Receive UDP data
                result = socket.recv_from(&mut buf) => {
                    if let Ok((len, from)) = result {
                        Self::handle_udp_recv(&mut tunnel, &mut stack, &mut buf[..len], from, local_addr);
                        if !Self::process_after_recv(&mut tunnel, &mut stack, &mut sockets).await {
                            break;
                        }
                    }
                }

                // Dynamic timeout - replaces fixed interval polling
                _ = tokio::time::sleep(poll_timeout) => {
                    tunnel.quic_conn.conn.on_timeout();
                    if !Self::poll_all(&mut tunnel, &mut stack, &mut sockets, &mut dns_queries, &mut dns_groups, &mut udp_sessions, &mut last_keepalive, keepalive_interval).await {
                        break;
                    }
                }
            }
        }

        log::info!("TunnelManager run_loop ended");
    }

    fn handle_command(
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
        dns_servers: &[IpAddress],
        cmd: ManagerCommand,
    ) {
        match cmd {
            ManagerCommand::Connect {
                remote_ip,
                remote_port,
                local_port,
                response,
            } => {
                let result = Self::create_connection(stack, sockets, remote_ip, remote_port, local_port);
                if response.send(result).is_err() {
                    log::warn!("Failed to send connect response: receiver dropped");
                }
            }
            ManagerCommand::Close { handle } => {
                Self::close_connection(stack, sockets, handle);
            }
            ManagerCommand::DnsResolve {
                domain,
                prefer_ipv6,
                response,
            } => {
                Self::start_dns_query(stack, dns_queries, dns_groups, &domain, prefer_ipv6, response, dns_servers);
            }
            ManagerCommand::UdpRegister { local_port, response } => {
                Self::register_udp_session(stack, udp_sessions, local_port, response);
            }
            ManagerCommand::UdpSend { remote_ip, remote_port, local_port, data } => {
                Self::send_udp_data(stack, udp_sessions, remote_ip, remote_port, local_port, &data);
            }
            ManagerCommand::UdpUnregister { local_port } => {
                Self::unregister_udp_session(stack, udp_sessions, local_port);
            }
            ManagerCommand::GetSocketState { handle, response } => {
                let state = Self::get_tcp_socket_state(stack, sockets, handle);
                if response.send(state).is_err() {
                    log::debug!("Failed to send socket state response: receiver dropped");
                }
            }
        }
    }

    fn handle_command_disconnected(cmd: ManagerCommand) {
        match cmd {
            ManagerCommand::Connect { response, .. } => {
                let _ = response.send(Err("Tunnel not connected".to_string()));
            }
            ManagerCommand::Close { .. } => {}
            ManagerCommand::DnsResolve { response, .. } => {
                let _ = response.send(Err(DnsError::NotConnected));
            }
            ManagerCommand::UdpRegister { response, .. } => {
                let _ = response.send(Err("Tunnel not connected".to_string()));
            }
            ManagerCommand::UdpSend { .. } => {
                log::debug!("Dropping UDP send: tunnel not connected");
            }
            ManagerCommand::UdpUnregister { .. } => {}
            ManagerCommand::GetSocketState { response, .. } => {
                let _ = response.send(TcpSocketState::Closed);
            }
        }
    }

    fn create_connection(
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<SocketChannels, String> {
        let handle = stack.create_tcp_socket();

        if let Err(e) = stack.connect_tcp(handle, remote_ip, remote_port, local_port) {
            stack.remove_socket(handle);
            return Err(format!("Connect failed: {}", e));
        }

        let (to_client_tx, to_client_rx) = mpsc::channel(8192);
        let (from_client_tx, from_client_rx) = mpsc::channel(8192);

        let state = SocketState {
            to_client: to_client_tx,
            from_client: from_client_rx,
            pending_data: Vec::new(),
            pending_to_client: VecDeque::new(),
            pending_to_client_bytes: 0,
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
        stack.tcp_close(handle);
        stack.remove_socket(handle);
        sockets.remove(&handle);
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

    fn register_udp_session(
        stack: &mut NetworkStack,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
        local_port: u16,
        response: oneshot::Sender<Result<mpsc::Receiver<(IpAddress, u16, Vec<u8>)>, String>>,
    ) {
        let handle = match stack.create_udp_socket_default(local_port) {
            Ok(handle) => handle,
            Err(e) => {
                let _ = response.send(Err(format!("Failed to bind UDP socket: {}", e)));
                return;
            }
        };
        let (tx, rx) = mpsc::channel(1024);

        udp_sessions.insert(local_port, UdpSessionState {
            handle,
            to_client: tx,
            last_activity: Instant::now(),
        });

        log::debug!("UDP session registered on port {}", local_port);
        if response.send(Ok(rx)).is_err() {
            log::warn!("Failed to send UDP register response: receiver dropped");
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

    fn start_dns_query(
        stack: &mut NetworkStack,
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        domain: &str,
        prefer_ipv6: bool,
        response: oneshot::Sender<Result<IpAddress, DnsError>>,
        dns_servers: &[IpAddress],
    ) {
        use std::sync::atomic::Ordering;

        let group_id = DNS_GROUP_ID.fetch_add(1, Ordering::Relaxed);

        // Create group to track both queries
        dns_groups.insert(
            group_id,
            DnsQueryGroup {
                response,
                ipv4_result: None,
                ipv6_result: None,
                created_at: Instant::now(),
                prefer_ipv6,
            },
        );

        // Select DNS server with round-robin and preferred address family
        let dns_server = Self::select_dns_server(dns_servers, prefer_ipv6);

        // Send A query (IPv4)
        match build_dns_query(domain, DnsRecordType::A) {
            Ok((tx_id_a, packet_a)) => {
                let local_port = get_dns_local_port();
                match stack.create_udp_socket_for(local_port, dns_server) {
                    Ok(handle) => {
                        if stack.udp_send(handle, dns_server, dns_port(), &packet_a).is_ok() {
                            dns_queries.insert(
                                tx_id_a,
                                DnsQueryState {
                                    handle,
                                    group_id,
                                    query_type: DnsRecordType::A,
                                },
                            );
                            log::debug!("DNS A query sent: {} (id={})", domain, tx_id_a);
                        } else {
                            stack.remove_socket(handle);
                            Self::record_dns_error(
                                dns_groups,
                                group_id,
                                DnsRecordType::A,
                                DnsError::SocketError("DNS A send failed".into()),
                            );
                            Self::try_resolve_dns_group(stack, dns_queries, dns_groups, group_id);
                        }
                    }
                    Err(e) => {
                        Self::record_dns_error(
                            dns_groups,
                            group_id,
                            DnsRecordType::A,
                            DnsError::SocketError(format!("DNS A socket error: {}", e)),
                        );
                        Self::try_resolve_dns_group(stack, dns_queries, dns_groups, group_id);
                    }
                }
            }
            Err(e) => {
                Self::record_dns_error(dns_groups, group_id, DnsRecordType::A, e);
                Self::try_resolve_dns_group(stack, dns_queries, dns_groups, group_id);
            }
        }

        // Send AAAA query (IPv6)
        match build_dns_query(domain, DnsRecordType::AAAA) {
            Ok((tx_id_aaaa, packet_aaaa)) => {
                let local_port = get_dns_local_port();
                match stack.create_udp_socket_for(local_port, dns_server) {
                    Ok(handle) => {
                        if stack.udp_send(handle, dns_server, dns_port(), &packet_aaaa).is_ok() {
                            dns_queries.insert(
                                tx_id_aaaa,
                                DnsQueryState {
                                    handle,
                                    group_id,
                                    query_type: DnsRecordType::AAAA,
                                },
                            );
                            log::debug!("DNS AAAA query sent: {} (id={})", domain, tx_id_aaaa);
                        } else {
                            stack.remove_socket(handle);
                            Self::record_dns_error(
                                dns_groups,
                                group_id,
                                DnsRecordType::AAAA,
                                DnsError::SocketError("DNS AAAA send failed".into()),
                            );
                            Self::try_resolve_dns_group(stack, dns_queries, dns_groups, group_id);
                        }
                    }
                    Err(e) => {
                        Self::record_dns_error(
                            dns_groups,
                            group_id,
                            DnsRecordType::AAAA,
                            DnsError::SocketError(format!("DNS AAAA socket error: {}", e)),
                        );
                        Self::try_resolve_dns_group(stack, dns_queries, dns_groups, group_id);
                    }
                }
            }
            Err(e) => {
                Self::record_dns_error(dns_groups, group_id, DnsRecordType::AAAA, e);
                Self::try_resolve_dns_group(stack, dns_queries, dns_groups, group_id);
            }
        }
    }

    fn process_dns_responses(
        stack: &mut NetworkStack,
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
    ) {
        let query_ids: Vec<u16> = dns_queries.keys().copied().collect();

        for transaction_id in query_ids {
            let (handle, group_id, query_type) = match dns_queries.get(&transaction_id) {
                Some(state) => (state.handle, state.group_id, state.query_type),
                None => continue,
            };

            if !stack.udp_can_recv(handle) {
                continue;
            }

            let mut buf = [0u8; 4096];
            let result = stack.udp_recv(handle, &mut buf);

            if let Ok((len, _endpoint)) = result {
                let response_result = parse_dns_response(&buf[..len], transaction_id);

                // Remove query and socket
                dns_queries.remove(&transaction_id);
                stack.remove_socket(handle);

                // Update group with result
                if let Some(group) = dns_groups.get_mut(&group_id) {
                    match query_type {
                        DnsRecordType::A => {
                            group.ipv4_result = Some(response_result);
                        }
                        DnsRecordType::AAAA => {
                            group.ipv6_result = Some(response_result);
                        }
                        _ => {}
                    }
                }

                // Try to resolve the group
                Self::try_resolve_dns_group(stack, dns_queries, dns_groups, group_id);
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
                    if session.to_client.try_send((
                        remote_ip,
                        remote_port,
                        buf[..len].to_vec(),
                    )).is_err() {
                        log::debug!("UDP session channel full or closed for port {}", local_port);
                    }
                }
            }
        }
    }

    fn try_resolve_dns_group(
        stack: &mut NetworkStack,
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        group_id: u32,
    ) {
        let group = match dns_groups.get(&group_id) {
            Some(g) => g,
            None => return,
        };

        // Happy Eyeballs: select based on preference, then fallback
        let result = match group.prefer_ipv6 {
            true => match (&group.ipv6_result, &group.ipv4_result) {
                (Some(Ok(v6_addrs)), _) if !v6_addrs.is_empty() => {
                    log::debug!("DNS resolved (IPv6): {:?}", v6_addrs[0]);
                    Some(Ok(v6_addrs[0]))
                }
                (_, Some(Ok(v4_addrs))) if !v4_addrs.is_empty() => {
                    log::debug!("DNS resolved (IPv4): {:?}", v4_addrs[0]);
                    Some(Ok(v4_addrs[0]))
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
                (Some(Ok(v4_addrs)), _) if !v4_addrs.is_empty() => {
                    log::debug!("DNS resolved (IPv4): {:?}", v4_addrs[0]);
                    Some(Ok(v4_addrs[0]))
                }
                (_, Some(Ok(v6_addrs))) if !v6_addrs.is_empty() => {
                    log::debug!("DNS resolved (IPv6): {:?}", v6_addrs[0]);
                    Some(Ok(v6_addrs[0]))
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

        if let Some(res) = result {
            // Cleanup remaining queries for this group
            let remaining: Vec<u16> = dns_queries
                .iter()
                .filter(|(_, s)| s.group_id == group_id)
                .map(|(id, _)| *id)
                .collect();
            for id in remaining {
                if let Some(state) = dns_queries.remove(&id) {
                    stack.remove_socket(state.handle);
                }
            }

            // Send response and remove group
            if let Some(group) = dns_groups.remove(&group_id)
                && group.response.send(res).is_err()
            {
                log::debug!("Failed to send DNS response: receiver dropped");
            }
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

    async fn poll_all(
        tunnel: &mut MasqueTunnel,
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
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

        if !stack.poll() {
            log::error!("smoltcp poll panicked, restarting tunnel");
            return false;
        }

        // Process DNS responses
        Self::process_dns_responses(stack, dns_queries, dns_groups);

        // Process UDP session responses
        Self::process_udp_responses(stack, udp_sessions);

        // Cleanup timed out DNS groups (5 second timeout)
        let now = Instant::now();
        let timed_out_groups: Vec<u32> = dns_groups
            .iter()
            .filter(|(_, group)| now.duration_since(group.created_at) > Duration::from_secs(5))
            .map(|(id, _)| *id)
            .collect();

        for group_id in timed_out_groups {
            // Remove all queries for this group
            let query_ids: Vec<u16> = dns_queries
                .iter()
                .filter(|(_, s)| s.group_id == group_id)
                .map(|(id, _)| *id)
                .collect();
            for id in query_ids {
                if let Some(state) = dns_queries.remove(&id) {
                    stack.remove_socket(state.handle);
                }
            }
            // Send timeout error
            if let Some(group) = dns_groups.remove(&group_id)
                && group.response.send(Err(DnsError::Timeout)).is_err()
            {
                log::debug!("Failed to send DNS timeout response: receiver dropped");
            }
        }

        // Cleanup stale UDP sessions
        let stale_ports: Vec<u16> = udp_sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.last_activity) > UDP_SESSION_TIMEOUT)
            .map(|(port, _)| *port)
            .collect();
        for port in stale_ports {
            if let Some(session) = udp_sessions.remove(&port) {
                stack.remove_socket(session.handle);
                log::debug!("Cleaned up stale UDP session on port {}", port);
            }
        }

        let handles: Vec<SocketHandle> = sockets.keys().copied().collect();
        let mut closed_handles = Vec::new();

        for handle in handles {
            if !stack.tcp_is_active(handle) {
                closed_handles.push(handle);
                continue;
            }

            let mut should_close = false;
            let blocked = if let Some(state) = sockets.get_mut(&handle) {
                Self::flush_pending_to_client(state);
                !state.pending_to_client.is_empty()
            } else {
                false
            };

            if !blocked && stack.tcp_may_recv(handle) {
                let mut buf = [0u8; 65535];
                if let Ok(n) = stack.tcp_recv(handle, &mut buf)
                    && n > 0
                    && let Some(state) = sockets.get_mut(&handle)
                    && Self::deliver_to_client(handle, state, buf[..n].to_vec()).is_err()
                {
                    log::debug!("TCP channel closed or backpressure overflow for socket {:?}", handle);
                    should_close = true;
                }
            }

            if let Some(state) = sockets.get_mut(&handle) {
                if !state.pending_data.is_empty() && stack.tcp_may_send(handle)
                    && let Ok(sent) = stack.tcp_send(handle, &state.pending_data)
                    && sent > 0
                {
                    state.pending_data.drain(..sent);
                }

                while let Ok(data) = state.from_client.try_recv() {
                    if stack.tcp_may_send(handle) {
                        match stack.tcp_send(handle, &data) {
                            Ok(sent) if sent < data.len() => {
                                state.pending_data.extend_from_slice(&data[sent..]);
                            }
                            Err(_) => {
                                state.pending_data.extend_from_slice(&data);
                            }
                            _ => {}
                        }
                    } else {
                        state.pending_data.extend_from_slice(&data);
                    }
                    if state.pending_data.len() > MAX_PENDING_DATA {
                        log::warn!(
                            "Pending data exceeded limit for socket {:?} ({} bytes), closing",
                            handle,
                            state.pending_data.len()
                        );
                        should_close = true;
                        break;
                    }
                }
            }

            if should_close {
                stack.tcp_close(handle);
                closed_handles.push(handle);
            }
        }

        for handle in closed_handles {
            sockets.remove(&handle);
            stack.remove_socket(handle);
        }

        while let Some(packet) = stack.take_packet() {
            match tunnel.send_datagram(&packet) {
                Ok(Some(icmp)) => {
                    log::debug!("Injecting ICMP Packet Too Big ({} bytes)", icmp.len());
                    stack.inject_packet(&icmp);
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

    // Lightweight processing after UDP recv: only handle TCP data transfer
    async fn process_after_recv(
        tunnel: &mut MasqueTunnel,
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
    ) -> bool {
        if !stack.poll() {
            log::error!("smoltcp poll panicked, restarting tunnel");
            return false;
        }

        let handles: Vec<SocketHandle> = sockets.keys().copied().collect();
        for handle in handles {
            let blocked = if let Some(state) = sockets.get_mut(&handle) {
                Self::flush_pending_to_client(state);
                !state.pending_to_client.is_empty()
            } else {
                false
            };

            if blocked || !stack.tcp_may_recv(handle) {
                continue;
            }

            let mut buf = [0u8; 65535];
            if let Ok(n) = stack.tcp_recv(handle, &mut buf)
                && n > 0
                && let Some(state) = sockets.get_mut(&handle)
                && Self::deliver_to_client(handle, state, buf[..n].to_vec()).is_err()
            {
                log::debug!("TCP channel closed or backpressure overflow for socket {:?}", handle);
                stack.tcp_close(handle);
            }
        }

        while let Some(packet) = stack.take_packet() {
            if let Err(e) = tunnel.send_datagram(&packet) {
                log::debug!("Failed to send datagram in process_after_recv: {:?}", e);
            }
        }

        if let Err(e) = tunnel.quic_conn.send_async().await {
            log::debug!("Failed to send QUIC data in process_after_recv: {:?}", e);
        }
        true
    }

    fn flush_pending_to_client(state: &mut SocketState) {
        while let Some(data) = state.pending_to_client.pop_front() {
            let len = data.len();
            match state.to_client.try_send(data) {
                Ok(()) => {
                    state.pending_to_client_bytes = state.pending_to_client_bytes.saturating_sub(len);
                }
                Err(err) => {
                    let data = err.into_inner();
                    state.pending_to_client.push_front(data);
                    break;
                }
            }
        }
    }

    fn deliver_to_client(
        handle: SocketHandle,
        state: &mut SocketState,
        data: Vec<u8>,
    ) -> Result<(), ()> {
        match state.to_client.try_send(data) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                if state.pending_to_client_bytes + data.len() > MAX_PENDING_TO_CLIENT {
                    log::warn!(
                        "Pending to-client data exceeded limit for socket {:?} ({} bytes), closing",
                        handle,
                        state.pending_to_client_bytes + data.len()
                    );
                    return Err(());
                }
                state.pending_to_client_bytes += data.len();
                state.pending_to_client.push_back(data);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(()),
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
