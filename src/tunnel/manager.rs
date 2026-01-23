use crate::tunnel::masque::MasqueTunnel;
use crate::tunnel::quic;
use crate::tunnel::stack::NetworkStack;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpAddress;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
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

    async fn run_loop(
        mut tunnel: MasqueTunnel,
        mut stack: NetworkStack,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
    ) {
        let socket = tunnel.quic_conn.socket.clone();
        let local_addr = tunnel.quic_conn.local_addr;

        let mut buf = [0u8; 65535];
        let mut sockets: HashMap<SocketHandle, SocketState> = HashMap::new();
        let mut interval = tokio::time::interval(Duration::from_micros(50));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
                    Self::handle_command(&mut stack, &mut sockets, cmd);
                }

                // Receive UDP data
                result = socket.recv_from(&mut buf) => {
                    if let Ok((len, from)) = result {
                        Self::handle_udp_recv(&mut tunnel, &mut stack, &buf[..len], from, local_addr);
                    }
                }

                // Periodic poll
                _ = interval.tick() => {
                    Self::poll_all(&mut tunnel, &mut stack, &mut sockets).await;
                }
            }
        }

        log::info!("TunnelManager run_loop ended");
    }

    fn handle_command(
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
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

        let (to_client_tx, to_client_rx) = mpsc::channel(1024);
        let (from_client_tx, from_client_rx) = mpsc::channel(1024);

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
    ) {
        tunnel.quic_conn.conn.on_timeout();

        stack.poll();

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
}
