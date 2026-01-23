use crate::tunnel::masque::MasqueTunnel;
use crate::tunnel::stack::NetworkStack;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpAddress;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

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
    pub fn new(tunnel: MasqueTunnel, ipv4: &str, ipv6: Option<&str>) -> Self {
        let stack = NetworkStack::new(ipv4, ipv6, 1280);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);

        let manager_task = ManagerTask {
            stack,
            tunnel,
            sockets: HashMap::new(),
            cmd_rx,
        };

        tokio::spawn(manager_task.run());

        Self { cmd_tx }
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
}

struct ManagerTask {
    stack: NetworkStack,
    tunnel: MasqueTunnel,
    sockets: HashMap<SocketHandle, SocketState>,
    cmd_rx: mpsc::Receiver<ManagerCommand>,
}

impl ManagerTask {
    async fn run(mut self) {
        let socket = self.tunnel.quic_conn.socket.clone();
        let local_addr = self.tunnel.quic_conn.local_addr;

        let mut buf = [0u8; 65535];
        let mut interval = tokio::time::interval(Duration::from_micros(50));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                // Handle commands from SOCKS5 connections
                Some(cmd) = self.cmd_rx.recv() => {
                    self.handle_command(cmd);
                }

                // Receive UDP data
                result = socket.recv_from(&mut buf) => {
                    if let Ok((len, from)) = result {
                        self.handle_udp_recv(&buf[..len], from, local_addr);
                    }
                }

                // Periodic poll
                _ = interval.tick() => {
                    self.poll_all().await;
                }
            }
        }
    }

    fn handle_command(&mut self, cmd: ManagerCommand) {
        match cmd {
            ManagerCommand::Connect {
                remote_ip,
                remote_port,
                local_port,
                response,
            } => {
                let result = self.create_connection(remote_ip, remote_port, local_port);
                let _ = response.send(result);
            }
            ManagerCommand::Close { handle } => {
                self.close_connection(handle);
            }
        }
    }

    fn create_connection(
        &mut self,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<SocketChannels, String> {
        let handle = self.stack.create_tcp_socket();

        if let Err(e) = self.stack.connect_tcp(handle, remote_ip, remote_port, local_port) {
            self.stack.remove_socket(handle);
            return Err(format!("Connect failed: {}", e));
        }

        // Create channels for this socket
        let (to_client_tx, to_client_rx) = mpsc::channel(1024);
        let (from_client_tx, from_client_rx) = mpsc::channel(1024);

        let state = SocketState {
            handle,
            to_client: to_client_tx,
            from_client: from_client_rx,
            pending_data: Vec::new(),
        };

        self.sockets.insert(handle, state);

        Ok(SocketChannels {
            handle,
            to_stack: from_client_tx,
            from_stack: to_client_rx,
        })
    }

    fn close_connection(&mut self, handle: SocketHandle) {
        self.stack.tcp_close(handle);
        self.stack.remove_socket(handle);
        self.sockets.remove(&handle);
    }

    fn handle_udp_recv(
        &mut self,
        data: &[u8],
        from: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) {
        let recv_info = quiche::RecvInfo {
            from,
            to: local_addr,
        };

        if let Err(e) = self.tunnel.quic_conn.conn.recv(&mut data.to_vec(), recv_info) {
            log::warn!("QUIC recv error: {:?}", e);
            return;
        }

        // Poll H3 to process any events
        self.tunnel.poll_h3();

        // Read datagrams and inject into stack
        let mut dgram_buf = [0u8; 65535];
        loop {
            match self.tunnel.recv_datagram(&mut dgram_buf) {
                Ok(len) if len > 0 => {
                    self.stack.inject_packet(dgram_buf[..len].to_vec());
                }
                _ => break,
            }
        }
    }

    async fn poll_all(&mut self) {
        // Handle QUIC timeout to send PING frames and keep connection alive
        self.tunnel.quic_conn.conn.on_timeout();

        // Check if QUIC connection is closed
        if self.tunnel.quic_conn.is_closed() {
            log::error!("QUIC connection closed");
            return;
        }

        // Poll the TCP/IP stack
        self.stack.poll();

        // Process each socket
        let handles: Vec<SocketHandle> = self.sockets.keys().copied().collect();
        let mut closed_handles = Vec::new();

        for handle in handles {
            if !self.stack.tcp_is_active(handle) {
                closed_handles.push(handle);
                continue;
            }

            // Read data from stack and send to client
            if self.stack.tcp_may_recv(handle) {
                let mut buf = [0u8; 65535];
                if let Ok(n) = self.stack.tcp_recv(handle, &mut buf) {
                    if n > 0 {
                        if let Some(state) = self.sockets.get(&handle) {
                            let _ = state.to_client.try_send(buf[..n].to_vec());
                        }
                    }
                }
            }

            // Read data from client and send to stack
            if let Some(state) = self.sockets.get_mut(&handle) {
                // First, try to send any pending data
                if !state.pending_data.is_empty() && self.stack.tcp_may_send(handle) {
                    if let Ok(sent) = self.stack.tcp_send(handle, &state.pending_data) {
                        if sent > 0 {
                            state.pending_data.drain(..sent);
                        }
                    }
                }

                // Then receive new data from client
                while let Ok(data) = state.from_client.try_recv() {
                    if self.stack.tcp_may_send(handle) {
                        match self.stack.tcp_send(handle, &data) {
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

        // Clean up closed sockets
        for handle in closed_handles {
            self.sockets.remove(&handle);
            self.stack.remove_socket(handle);
        }

        // Take packets from stack and send to tunnel
        while let Some(packet) = self.stack.take_packet() {
            if let Err(e) = self.tunnel.send_datagram(&packet) {
                log::warn!("Failed to send datagram: {:?}", e);
            }
        }

        // Send QUIC data
        if let Err(e) = self.tunnel.quic_conn.send_async().await {
            log::warn!("Failed to send QUIC data: {:?}", e);
        }
    }
}
