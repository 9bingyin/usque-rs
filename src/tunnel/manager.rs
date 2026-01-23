use crate::tunnel::dns::{
    build_dns_query, dns_port, dns_server, get_dns_local_port, parse_dns_response, DnsError,
    DnsRecordType,
};
use crate::tunnel::masque::MasqueTunnel;
use crate::tunnel::quic;
use crate::tunnel::stack::NetworkStack;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpAddress;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

// Connection parameters for establishing and reconnecting tunnel
pub struct ConnectionParams {
    pub endpoint: SocketAddr,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub sni: String,
    pub endpoint_pub_key: Option<Vec<u8>>,
    pub ipv4: String,
    pub ipv6: Option<String>,
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
        response: oneshot::Sender<mpsc::Receiver<(IpAddress, u16, Vec<u8>)>>,
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
}

// Channels for a single TCP socket
pub struct SocketChannels {
    pub handle: SocketHandle,
    pub to_stack: mpsc::Sender<Vec<u8>>,
    pub from_stack: mpsc::Receiver<Vec<u8>>,
}

// Internal state for each socket
struct SocketState {
    handle: SocketHandle,
    to_client: mpsc::Sender<Vec<u8>>,
    from_client: mpsc::Receiver<Vec<u8>>,
    pending_data: Vec<u8>,
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
}

// UDP session state for SOCKS5 UDP ASSOCIATE
struct UdpSessionState {
    handle: SocketHandle,
    to_client: mpsc::Sender<(IpAddress, u16, Vec<u8>)>,
}

static DNS_GROUP_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

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
        let reconnect_delay = Duration::from_secs(1);

        loop {
            log::info!("Establishing MASQUE connection to {}", params.endpoint);

            match Self::establish_connection(&params).await {
                Ok((tunnel, stack)) => {
                    log::info!("Tunnel connected successfully");

                    // Run main loop until connection is closed
                    Self::run_loop(tunnel, stack, &mut cmd_rx).await;

                    log::warn!("Connection lost, reconnecting...");
                }
                Err(e) => {
                    log::error!("Failed to connect: {}", e);
                }
            }

            tokio::time::sleep(reconnect_delay).await;
        }
    }

    async fn establish_connection(
        params: &ConnectionParams,
    ) -> Result<(MasqueTunnel, NetworkStack), Box<dyn std::error::Error + Send + Sync>> {
        let quic_conn = quic::connect_with_pinning(
            params.endpoint,
            &params.cert_der,
            &params.key_der,
            &params.sni,
            Duration::from_secs(30),
            params.endpoint_pub_key.as_deref(),
        ).await?;

        let mut masque_tunnel = MasqueTunnel::new(quic_conn);
        masque_tunnel.establish(Duration::from_secs(30)).await?;

        // Dynamically get MTU from QUIC datagram max size
        // Subtract HTTP/3 datagram header (~3 bytes for varint stream ID + context ID)
        let mtu = masque_tunnel
            .quic_conn
            .conn
            .dgram_max_writable_len()
            .map(|max| max.saturating_sub(3))
            .unwrap_or(1280);

        log::info!("Using MTU {} based on QUIC datagram limit", mtu);

        let stack = NetworkStack::new(
            &params.ipv4,
            params.ipv6.as_deref(),
            mtu,
        );

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
        let _ = self.cmd_tx.send(ManagerCommand::Close { handle }).await;
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
    ) {
        let socket = tunnel.quic_conn.socket.clone();
        let local_addr = tunnel.quic_conn.local_addr;

        let mut buf = [0u8; 65535];
        let mut sockets: HashMap<SocketHandle, SocketState> = HashMap::new();
        let mut dns_queries: HashMap<u16, DnsQueryState> = HashMap::new(); // transaction_id -> state
        let mut dns_groups: HashMap<u32, DnsQueryGroup> = HashMap::new(); // group_id -> group
        let mut udp_sessions: HashMap<u16, UdpSessionState> = HashMap::new(); // local_port -> session
        let mut interval = tokio::time::interval(Duration::from_micros(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // KeepAlive timer - send PING frames every 30 seconds to keep connection alive
        let mut keepalive_interval = tokio::time::interval(Duration::from_secs(30));
        keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            // Check connection status at the start of each iteration
            if tunnel.quic_conn.is_closed() {
                log::error!("QUIC connection closed");
                break;
            }

            tokio::select! {
                biased;

                // Handle commands from SOCKS5 connections
                Some(cmd) = cmd_rx.recv() => {
                    Self::handle_command(&mut stack, &mut sockets, &mut dns_queries, &mut dns_groups, &mut udp_sessions, cmd);
                    Self::process_after_recv(&mut tunnel, &mut stack, &mut sockets).await;
                }

                // Receive UDP data
                result = socket.recv_from(&mut buf) => {
                    if let Ok((len, from)) = result {
                        Self::handle_udp_recv(&mut tunnel, &mut stack, &buf[..len], from, local_addr);
                        Self::process_after_recv(&mut tunnel, &mut stack, &mut sockets).await;
                    }
                }

                // Periodic poll
                _ = interval.tick() => {
                    Self::poll_all(&mut tunnel, &mut stack, &mut sockets, &mut dns_queries, &mut dns_groups, &mut udp_sessions).await;
                }

                // KeepAlive - send PING frame to keep connection alive
                _ = keepalive_interval.tick() => {
                    if let Err(e) = tunnel.quic_conn.conn.send_ack_eliciting() {
                        log::warn!("Failed to send keepalive PING: {:?}", e);
                    } else {
                        log::debug!("Sent keepalive PING frame");
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
                let _ = response.send(result);
            }
            ManagerCommand::Close { handle } => {
                Self::close_connection(stack, sockets, handle);
            }
            ManagerCommand::DnsResolve {
                domain,
                prefer_ipv6,
                response,
            } => {
                Self::start_dns_query(stack, dns_queries, dns_groups, &domain, prefer_ipv6, response);
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
            handle,
            to_client: to_client_tx,
            from_client: from_client_rx,
            pending_data: Vec::new(),
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

    fn register_udp_session(
        stack: &mut NetworkStack,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
        local_port: u16,
        response: oneshot::Sender<mpsc::Receiver<(IpAddress, u16, Vec<u8>)>>,
    ) {
        let handle = stack.create_udp_socket(local_port);
        let (tx, rx) = mpsc::channel(1024);

        udp_sessions.insert(local_port, UdpSessionState {
            handle,
            to_client: tx,
        });

        log::debug!("UDP session registered on port {}", local_port);
        let _ = response.send(rx);
    }

    fn send_udp_data(
        stack: &mut NetworkStack,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
        data: &[u8],
    ) {
        if let Some(session) = udp_sessions.get(&local_port) {
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

    fn start_dns_query(
        stack: &mut NetworkStack,
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        domain: &str,
        _prefer_ipv6: bool,
        response: oneshot::Sender<Result<IpAddress, DnsError>>,
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
            },
        );

        // Send A query (IPv4)
        if let Ok((tx_id_a, packet_a)) = build_dns_query(domain, DnsRecordType::A) {
            let local_port = get_dns_local_port();
            let handle = stack.create_udp_socket(local_port);
            if stack.udp_send(handle, dns_server(), dns_port(), &packet_a).is_ok() {
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
            }
        }

        // Send AAAA query (IPv6)
        if let Ok((tx_id_aaaa, packet_aaaa)) = build_dns_query(domain, DnsRecordType::AAAA) {
            let local_port = get_dns_local_port();
            let handle = stack.create_udp_socket(local_port);
            if stack.udp_send(handle, dns_server(), dns_port(), &packet_aaaa).is_ok() {
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

            let mut buf = [0u8; 512];
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
            if let Ok((len, endpoint)) = stack.udp_recv(handle, &mut buf) {
                if len > 0 {
                    let remote_ip = endpoint.endpoint.addr;
                    let remote_port = endpoint.endpoint.port;

                    if let Some(session) = udp_sessions.get(&local_port) {
                        let _ = session.to_client.try_send((
                            remote_ip,
                            remote_port,
                            buf[..len].to_vec(),
                        ));
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

        // Happy Eyeballs: prefer IPv6 if available, fallback to IPv4
        let result = match (&group.ipv6_result, &group.ipv4_result) {
            // IPv6 succeeded with addresses
            (Some(Ok(v6_addrs)), _) if !v6_addrs.is_empty() => {
                log::debug!("DNS resolved (IPv6): {:?}", v6_addrs[0]);
                Some(Ok(v6_addrs[0]))
            }
            // IPv4 succeeded with addresses
            (_, Some(Ok(v4_addrs))) if !v4_addrs.is_empty() => {
                log::debug!("DNS resolved (IPv4): {:?}", v4_addrs[0]);
                Some(Ok(v4_addrs[0]))
            }
            // Both failed or returned no records
            (Some(_), Some(_)) => {
                log::debug!("DNS resolution failed: no records from both A and AAAA");
                Some(Err(DnsError::NoRecords))
            }
            // Still waiting for one response
            _ => None,
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
            if let Some(group) = dns_groups.remove(&group_id) {
                let _ = group.response.send(res);
            }
        }
    }

    fn handle_udp_recv(
        tunnel: &mut MasqueTunnel,
        stack: &mut NetworkStack,
        data: &[u8],
        from: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) {
        let recv_info = quiche::RecvInfo {
            from,
            to: local_addr,
        };

        if let Err(e) = tunnel.quic_conn.conn.recv(&mut data.to_vec(), recv_info) {
            log::warn!("QUIC recv error: {:?}", e);
            return;
        }

        tunnel.poll_h3();

        let mut dgram_buf = [0u8; 65535];
        loop {
            match tunnel.recv_datagram(&mut dgram_buf) {
                Ok(len) if len > 0 => {
                    stack.inject_packet(dgram_buf[..len].to_vec());
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
    ) {
        tunnel.quic_conn.conn.on_timeout();

        stack.poll();

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
            if let Some(group) = dns_groups.remove(&group_id) {
                let _ = group.response.send(Err(DnsError::Timeout));
            }
        }

        let handles: Vec<SocketHandle> = sockets.keys().copied().collect();
        let mut closed_handles = Vec::new();

        for handle in handles {
            if !stack.tcp_is_active(handle) {
                closed_handles.push(handle);
                continue;
            }

            if stack.tcp_may_recv(handle) {
                let mut buf = [0u8; 65535];
                if let Ok(n) = stack.tcp_recv(handle, &mut buf) {
                    if n > 0 {
                        if let Some(state) = sockets.get(&handle) {
                            let _ = state.to_client.try_send(buf[..n].to_vec());
                        }
                    }
                }
            }

            if let Some(state) = sockets.get_mut(&handle) {
                if !state.pending_data.is_empty() && stack.tcp_may_send(handle) {
                    if let Ok(sent) = stack.tcp_send(handle, &state.pending_data) {
                        if sent > 0 {
                            state.pending_data.drain(..sent);
                        }
                    }
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
                }
            }
        }

        for handle in closed_handles {
            sockets.remove(&handle);
            stack.remove_socket(handle);
        }

        while let Some(packet) = stack.take_packet() {
            match tunnel.send_datagram(&packet) {
                Ok(Some(icmp)) => {
                    // Inject ICMP Packet Too Big message back to stack
                    log::debug!("Injecting ICMP Packet Too Big ({} bytes)", icmp.len());
                    stack.inject_packet(icmp);
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
    }

    // Lightweight processing after UDP recv: only handle TCP data transfer
    async fn process_after_recv(
        tunnel: &mut MasqueTunnel,
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
    ) {
        stack.poll();

        let handles: Vec<SocketHandle> = sockets.keys().copied().collect();
        for handle in handles {
            if stack.tcp_may_recv(handle) {
                let mut buf = [0u8; 65535];
                if let Ok(n) = stack.tcp_recv(handle, &mut buf) {
                    if n > 0 {
                        if let Some(state) = sockets.get(&handle) {
                            let _ = state.to_client.try_send(buf[..n].to_vec());
                        }
                    }
                }
            }
        }

        while let Some(packet) = stack.take_packet() {
            let _ = tunnel.send_datagram(&packet);
        }

        let _ = tunnel.quic_conn.send_async().await;
    }
}
