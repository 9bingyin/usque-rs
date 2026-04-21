impl TunnelManager {
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
                    &mut state.tcp_handles,
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
                Self::close_connection(
                    &mut state.stack,
                    &mut state.sockets,
                    &mut state.tcp_handles,
                    handle,
                );
            }
            ManagerCommand::DnsResolve {
                domain,
                prefer_ipv6,
                response,
            } => {
                if let Some(ip) = dns_cache_get(&state.dns_cache, &domain, prefer_ipv6) {
                    log::debug!("DNS cached: {} -> {}", domain, format_ip(ip));
                    if response.send(Ok(ip)).is_err() {
                        log::trace!("DNS response dropped: receiver closed");
                    }
                } else {
                    Self::start_dns_query(state, &domain, prefer_ipv6, response, dns_servers);
                }
            }
            ManagerCommand::DnsResolveAll { domain, response } => {
                if let Some(ips) = dns_cache_get_all(&state.dns_cache, &domain) {
                    log::debug!("DNS cached: {} -> {} addresses", domain, ips.len());
                    if response.send(Ok(ips)).is_err() {
                        log::trace!("DNS response dropped: receiver closed");
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
                    &mut state.udp_ports,
                    local_port,
                    response,
                );
            }
            ManagerCommand::UdpUnregister { local_port } => {
                Self::unregister_udp_session(
                    &mut state.stack,
                    &mut state.udp_sessions,
                    &mut state.udp_ports,
                    local_port,
                );
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
                    if response.send(socket_state).is_err() {
                        log::trace!("Failed to send socket ready response: receiver dropped");
                    }
                } else if let Some(socket_state) = state.sockets.get_mut(&handle) {
                    socket_state.ready_waiters.push(response);
                } else if response.send(TcpSocketState::Closed).is_err() {
                    log::trace!("Failed to send socket closed response: receiver dropped");
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
        tcp_handles: &mut Vec<SocketHandle>,
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
            close_requested: false,
            write_shutdown: false,
            fin_sent: false,
            ready_waiters: Vec::new(),
        };

        sockets.insert(handle, state);
        tcp_handles.push(handle);

        Ok(SocketChannels {
            handle,
            to_stack: from_client_tx,
            from_stack: to_client_rx,
        })
    }

    fn close_connection(
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
        tcp_handles: &mut Vec<SocketHandle>,
        handle: SocketHandle,
    ) {
        if let Some(state) = sockets.get_mut(&handle) {
            state.close_requested = true;
            state.write_shutdown = true;
            for waiter in state.ready_waiters.drain(..) {
                if waiter.send(TcpSocketState::Closed).is_err() {
                    log::trace!("Failed to notify waiter of connection close: receiver dropped");
                }
            }
            return;
        }

        stack.tcp_close(handle);
        stack.remove_socket(handle);
        tcp_handles.retain(|h| *h != handle);
    }

    fn get_tcp_socket_state(
        stack: &mut NetworkStack,
        sockets: &HashMap<SocketHandle, SocketState>,
        handle: SocketHandle,
    ) -> TcpSocketState {
        let Some(socket_state) = sockets.get(&handle) else {
            return TcpSocketState::Closed;
        };
        if socket_state.close_requested {
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
        udp_ports: &mut Vec<u16>,
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
        udp_ports.push(local_port);

        log::debug!("UDP session registered on port {}", local_port);
        if response.send(Ok(rx)).is_err() {
            log::trace!("UDP register response dropped: receiver closed");
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
        udp_ports: &mut Vec<u16>,
        local_port: u16,
    ) {
        if let Some(session) = udp_sessions.remove(&local_port) {
            stack.remove_socket(session.handle);
            log::debug!("UDP session closed on port {}", local_port);
        }
        udp_ports.retain(|p| *p != local_port);
    }
}
