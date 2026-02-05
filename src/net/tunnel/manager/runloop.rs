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
            log::info!("connecting {} to {}", mode_name, params.endpoint);

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
                    log::trace!("connection result dropped");
                }
            });

            loop {
                tokio::select! {
                    res = &mut conn_rx => {
                        match res {
                            Ok(Ok(conn)) => {
                                log::info!("tunnel established");
                                backoff.reset();
                                match conn {
                                    TunnelConn::Masque(tunnel, stack) => {
                                        Self::run_loop(
                                            *tunnel,
                                            stack,
                                            &mut cmd_rx,
                                            &mut udp_rx,
                                            &params,
                                        )
                                        .await;
                                    }
                                    TunnelConn::Wg(tunnel, stack) => {
                                        Self::run_loop_wg(
                                            *tunnel,
                                            stack,
                                            &mut cmd_rx,
                                            &mut udp_rx,
                                            &params,
                                        )
                                        .await;
                                    }
                                }
                                log::warn!("tunnel disconnected, reconnecting");
                            }
                            Ok(Err(e)) => {
                                log::error!("connection failed: {}", e);
                            }
                            Err(_) => {
                                log::error!("connection task cancelled");
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
            log::info!("reconnecting in {:?}", delay);
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

        log::info!("MTU {} (QUIC {}, configured {})", mtu, dynamic_mtu, configured_mtu);

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
        let std_socket = socket.into_std()?;
        Self::configure_udp_socket_buffers(&std_socket, 4 * 1024 * 1024, 2 * 1024 * 1024);
        let socket = tokio::net::UdpSocket::from_std(std_socket)?;
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
        log::info!("client IPv4: {}, IPv6: {:?}", params.ipv4, params.ipv6);

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
            log::trace!("failed to send close command: {}", e);
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
        params: &ConnectionParams,
    ) {
        let local_addr = tunnel.quic_conn.local_addr;
        let (incoming_tx, mut incoming_rx) = mpsc::channel(INCOMING_DGRAM_CAPACITY);
        let socket = tunnel.quic_conn.socket.clone();
        let buffer_pool = stack.buffer_pool();
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let mut shutdown_sub = shutdown_tx.subscribe();
        // Guard: when all senders are dropped, the completion channel closes
        let (completion_tx, mut completion_rx) = mpsc::channel::<()>(1);
        let recv_completion_tx = completion_tx.clone();
        let recv_handle = tokio::spawn({
            let buffer_pool = buffer_pool.clone();
            async move {
            let _guard = recv_completion_tx;
            loop {
                tokio::select! {
                    _ = shutdown_sub.recv() => break,
                    result = async {
                        let mut buf = Self::take_pooled_buffer(&buffer_pool, UDP_RECV_BUFFER_SIZE);
                        buf.resize(UDP_RECV_BUFFER_SIZE, 0);
                        match socket.recv_from(&mut buf[..]).await {
                            Ok((len, from)) => Ok((buf, len, from)),
                            Err(e) => Err((buf, e)),
                        }
                    } => {
                        match result {
                            Ok((mut buf, len, from)) => {
                                if len == 0 {
                                    Self::return_pooled_buffer(&buffer_pool, buf);
                                    continue;
                                }
                                buf.truncate(len);
                                if incoming_tx.send(IncomingDatagram { data: buf, from }).await.is_err() {
                                    log::trace!("incoming datagram channel closed");
                                    break;
                                }
                            }
                            Err((buf, e)) => {
                                Self::return_pooled_buffer(&buffer_pool, buf);
                                log::warn!("UDP recv error: {}", e);
                            }
                        }
                    }
                }
            }
        }
        });

        let mut state = RuntimeState::new(stack, params.perf_enabled, params.perf_interval_secs);

        // Keepalive tracking
        let mut last_keepalive = Instant::now();
        let keepalive_interval = Duration::from_secs(params.keepalive);
        const MAX_POLL_INTERVAL: Duration = Duration::from_millis(50);
        const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(5);
        let poll_timer = tokio::time::sleep(Duration::from_millis(0));
        tokio::pin!(poll_timer);

        loop {
            // Check connection status at the start of each iteration
            if tunnel.quic_conn.is_closed() {
                log::error!("QUIC connection closed unexpectedly");
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

            state.perf.inc_loop();
            let mut dirty = false;

            tokio::select! {
                biased;
                // Handle control commands from SOCKS5 connections
                Some(cmd) = cmd_rx.recv() => {
                    Self::handle_command(&mut state, &params.dns_servers, params.tcp_buffer_size, cmd);
                    dirty = true;
                }

                // Handle UDP sends from SOCKS5
                Some(udp_cmd) = udp_rx.recv() => {
                    Self::handle_udp_send(&mut state.stack, &mut state.udp_sessions, udp_cmd);
                    dirty = true;
                }

                // Receive UDP data from QUIC socket - batch read
                Some(incoming) = incoming_rx.recv() => {
                    let mut data = incoming.data;
                    Self::handle_udp_recv(
                        &mut tunnel,
                        &mut state.stack,
                        &state.buffer_pool,
                        &mut state.perf,
                        &mut data[..],
                        incoming.from,
                        local_addr,
                    );
                    Self::return_pooled_buffer(&state.buffer_pool, data);
                    dirty = true;
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

            if dirty {
                let mut budget = CMD_BATCH_BUDGET;
                while budget > 0 {
                    match cmd_rx.try_recv() {
                        Ok(cmd) => {
                            Self::handle_command(&mut state, &params.dns_servers, params.tcp_buffer_size, cmd);
                            budget -= 1;
                        }
                        Err(_) => break,
                    }
                }

                let mut budget = UDP_BATCH_BUDGET;
                while budget > 0 {
                    match udp_rx.try_recv() {
                        Ok(udp_cmd) => {
                            Self::handle_udp_send(&mut state.stack, &mut state.udp_sessions, udp_cmd);
                            budget -= 1;
                        }
                        Err(_) => break,
                    }
                }

                let mut budget = UDP_BATCH_READ_BUDGET;
                while budget > 0 {
                    match incoming_rx.try_recv() {
                        Ok(incoming) => {
                            let mut data = incoming.data;
                            Self::handle_udp_recv(
                                &mut tunnel,
                                &mut state.stack,
                                &state.buffer_pool,
                                &mut state.perf,
                                &mut data[..],
                                incoming.from,
                                local_addr,
                            );
                            Self::return_pooled_buffer(&state.buffer_pool, data);
                            budget -= 1;
                        }
                        Err(_) => break,
                    }
                }

                if !Self::flush_outbound(&mut tunnel, &mut state).await {
                    break;
                }
            }

            if state.perf.due() {
                let snapshot = Self::build_perf_snapshot(
                    &mut state,
                    cmd_rx.len(),
                    udp_rx.len(),
                    incoming_rx.len(),
                );
                state.perf.report(snapshot);
            }
        }

        // Phase 1: broadcast shutdown to all tasks
        if shutdown_tx.send(()).is_err() {
            log::trace!("shutdown signal dropped");
        }
        // Phase 2: drop our guard and wait for all tasks to finish
        drop(completion_tx);
        let _ = completion_rx.recv().await; // returns None when all senders dropped
        if let Err(e) = recv_handle.await {
            log::trace!("recv task join error: {:?}", e);
        }
        log::debug!("MASQUE run_loop ended");
    }

    async fn run_loop_wg(
        mut tunnel: WgTunnel,
        stack: NetworkStack,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        params: &ConnectionParams,
    ) {
        let socket = tunnel.socket();
        let (incoming_tx, mut incoming_rx) = mpsc::channel(INCOMING_DGRAM_CAPACITY);
        let buffer_pool = stack.buffer_pool();
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let mut shutdown_sub = shutdown_tx.subscribe();
        let (completion_tx, mut completion_rx) = mpsc::channel::<()>(1);
        let recv_completion_tx = completion_tx.clone();

        let peer_addr = socket
            .peer_addr()
            .expect("WG socket should be connected");
        let recv_handle = tokio::spawn({
            let buffer_pool = buffer_pool.clone();
            async move {
            let _guard = recv_completion_tx;
            loop {
                tokio::select! {
                    _ = shutdown_sub.recv() => break,
                    result = async {
                        let mut buf = Self::take_pooled_buffer(&buffer_pool, UDP_RECV_BUFFER_SIZE);
                        buf.resize(UDP_RECV_BUFFER_SIZE, 0);
                        match socket.recv(&mut buf[..]).await {
                            Ok(len) => Ok((buf, len)),
                            Err(e) => Err((buf, e)),
                        }
                    } => {
                        match result {
                            Ok((mut buf, len)) => {
                                if len == 0 {
                                    Self::return_pooled_buffer(&buffer_pool, buf);
                                    continue;
                                }
                                buf.truncate(len);
                                if incoming_tx.send(IncomingDatagram { data: buf, from: peer_addr }).await.is_err() {
                                    log::trace!("incoming datagram channel closed");
                                    break;
                                }
                            }
                            Err((buf, e)) => {
                                Self::return_pooled_buffer(&buffer_pool, buf);
                                log::warn!("UDP recv error: {}", e);
                            }
                        }
                    }
                }
            }
        }
        });

        let mut state = RuntimeState::new(stack, params.perf_enabled, params.perf_interval_secs);

        const WG_TIMER_INTERVAL: Duration = Duration::from_millis(250);
        const MAX_POLL_INTERVAL: Duration = Duration::from_millis(50);
        const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(5);

        let wg_timer = tokio::time::sleep(WG_TIMER_INTERVAL);
        tokio::pin!(wg_timer);
        let poll_timer = tokio::time::sleep(Duration::from_millis(0));
        tokio::pin!(poll_timer);

        loop {
            if tunnel.is_expired() {
                log::error!("WireGuard tunnel session expired");
                break;
            }

            state.perf.inc_loop();

            let smoltcp_timeout = state.stack.poll_delay().unwrap_or(DEFAULT_POLL_INTERVAL);
            let poll_timeout = smoltcp_timeout.min(MAX_POLL_INTERVAL);
            poll_timer
                .as_mut()
                .reset(TokioInstant::now() + poll_timeout);

            let mut dirty = false;
            let mut handled_incoming = false;

            tokio::select! {
                biased;
                Some(cmd) = cmd_rx.recv() => {
                    Self::handle_command(&mut state, &params.dns_servers, params.tcp_buffer_size, cmd);
                    dirty = true;
                }

                Some(udp_cmd) = udp_rx.recv() => {
                    Self::handle_udp_send(&mut state.stack, &mut state.udp_sessions, udp_cmd);
                    dirty = true;
                }

                Some(incoming) = incoming_rx.recv() => {
                    let mut data = incoming.data;
                    state.perf.inc_rx(data.len());
                    tunnel.decrypt_incoming(&mut data, &mut state.stack);
                    Self::return_pooled_buffer(&state.buffer_pool, data);
                    dirty = true;
                    handled_incoming = true;
                }

                _ = &mut wg_timer => {
                    if let Err(e) = tunnel.tick_timers().await {
                        log::warn!("WireGuard timer error: {}", e);
                    }
                    wg_timer.as_mut().reset(TokioInstant::now() + WG_TIMER_INTERVAL);
                }

                _ = &mut poll_timer => {
                    if !Self::poll_all_wg(&mut tunnel, &mut state).await {
                        break;
                    }
                }
            }

            if dirty {
                let mut budget = CMD_BATCH_BUDGET;
                while budget > 0 {
                    match cmd_rx.try_recv() {
                        Ok(cmd) => {
                            Self::handle_command(&mut state, &params.dns_servers, params.tcp_buffer_size, cmd);
                            budget -= 1;
                        }
                        Err(_) => break,
                    }
                }

                let mut budget = UDP_BATCH_BUDGET;
                while budget > 0 {
                    match udp_rx.try_recv() {
                        Ok(udp_cmd) => {
                            Self::handle_udp_send(&mut state.stack, &mut state.udp_sessions, udp_cmd);
                            budget -= 1;
                        }
                        Err(_) => break,
                    }
                }

                let mut budget = UDP_BATCH_READ_BUDGET;
                while budget > 0 {
                    match incoming_rx.try_recv() {
                        Ok(incoming) => {
                            let mut data = incoming.data;
                            state.perf.inc_rx(data.len());
                            tunnel.decrypt_incoming(&mut data, &mut state.stack);
                            Self::return_pooled_buffer(&state.buffer_pool, data);
                            budget -= 1;
                            handled_incoming = true;
                        }
                        Err(_) => break,
                    }
                }

                if handled_incoming {
                    tunnel.drain_queued_to_send_queue();
                    tunnel.flush_send_queue().await;
                }

                if !Self::flush_outbound_wg(&mut tunnel, &mut state).await {
                    break;
                }
            }

            if state.perf.due() {
                let snapshot = Self::build_perf_snapshot(
                    &mut state,
                    cmd_rx.len(),
                    udp_rx.len(),
                    incoming_rx.len(),
                );
                state.perf.report(snapshot);
            }
        }

        if shutdown_tx.send(()).is_err() {
            log::trace!("shutdown signal dropped");
        }
        drop(completion_tx);
        let _ = completion_rx.recv().await;
        if let Err(e) = recv_handle.await {
            log::trace!("recv task join error: {:?}", e);
        }
        log::debug!("WireGuard run_loop ended");
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
                Self::close_connection(&mut state.stack, &mut state.sockets, &mut state.tcp_handles, handle);
            }
            ManagerCommand::DnsResolve {
                domain,
                prefer_ipv6,
                response,
            } => {
                // Check cache first
                if let Some(ip) = dns_cache_get(&state.dns_cache, &domain, prefer_ipv6) {
                    log::debug!("DNS cached: {} -> {:?}", domain, ip);
                    if response.send(Ok(ip)).is_err() {
                        log::trace!("DNS response dropped: receiver closed");
                    }
                } else {
                    Self::start_dns_query(state, &domain, prefer_ipv6, response, dns_servers);
                }
            }
            ManagerCommand::DnsResolveAll { domain, response } => {
                // Check cache first for all addresses
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
        tcp_handles.retain(|h| *h != handle);
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

        log::info!("UDP session registered on port {}", local_port);
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
            log::info!("UDP session closed on port {}", local_port);
        }
        udp_ports.retain(|p| *p != local_port);
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
                    log::debug!("DNS query: {} A", domain);
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
                    log::debug!("DNS query: {} AAAA", domain);
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
                    log::debug!("DNS query: {} A (all)", domain);
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
                    log::debug!("DNS query: {} AAAA (all)", domain);
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
        udp_ports: &[u16],
    ) {
        for &local_port in udp_ports {
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
                        log::info!("DNS resolved: {} -> {:?}", group.domain, v6_records[0].address);
                        Some(Ok(v6_records[0].address))
                    }
                    (_, Some(Ok(v4_records))) if !v4_records.is_empty() => {
                        log::info!("DNS resolved: {} -> {:?}", group.domain, v4_records[0].address);
                        Some(Ok(v4_records[0].address))
                    }
                    (Some(_), Some(_)) => {
                        let err = match (&group.ipv6_result, &group.ipv4_result) {
                            (Some(Err(e6)), _) if !matches!(e6, DnsError::NoRecords) => e6.clone(),
                            (_, Some(Err(e4))) if !matches!(e4, DnsError::NoRecords) => e4.clone(),
                            _ => DnsError::NoRecords,
                        };
                        log::warn!("DNS resolution failed: {} -> {:?}", group.domain, err);
                        Some(Err(err))
                    }
                    _ => None,
                },
                false => match (&group.ipv4_result, &group.ipv6_result) {
                    (Some(Ok(v4_records)), _) if !v4_records.is_empty() => {
                        log::info!("DNS resolved: {} -> {:?}", group.domain, v4_records[0].address);
                        Some(Ok(v4_records[0].address))
                    }
                    (_, Some(Ok(v6_records))) if !v6_records.is_empty() => {
                        log::info!("DNS resolved: {} -> {:?}", group.domain, v6_records[0].address);
                        Some(Ok(v6_records[0].address))
                    }
                    (Some(_), Some(_)) => {
                        let err = match (&group.ipv4_result, &group.ipv6_result) {
                            (Some(Err(e4)), _) if !matches!(e4, DnsError::NoRecords) => e4.clone(),
                            (_, Some(Err(e6))) if !matches!(e6, DnsError::NoRecords) => e6.clone(),
                            _ => DnsError::NoRecords,
                        };
                        log::warn!("DNS resolution failed: {} -> {:?}", group.domain, err);
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
                log::debug!("DNS cache updated: {} ({} records)", domain, all_records.len());
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
                    log::warn!("DNS resolution failed: {} -> {:?}", group.domain, err);
                    if response_all.send(Err(ManagerError::Dns(err))).is_err() {
                        log::trace!("DNS response dropped: receiver closed");
                    }
                } else {
                    log::info!(
                        "DNS resolved: {} -> [{}]",
                        group.domain,
                        all_ips.iter().map(|ip| format!("{:?}", ip)).collect::<Vec<_>>().join(", ")
                    );
                    if response_all.send(Ok(all_ips)).is_err() {
                        log::trace!("DNS response dropped: receiver closed");
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
        buffer_pool: &BufferPool,
        perf: &mut PerfCounters,
        data: &mut [u8],
        from: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) {
        let recv_info = quiche::RecvInfo {
            from,
            to: local_addr,
        };

        if let Err(e) = tunnel.quic_conn.conn.recv(data, recv_info) {
            log::warn!("QUIC recv failed: {:?}", e);
            return;
        }

        tunnel.poll_h3();

        let mut dgram_buf = [0u8; 65535];
        loop {
            match tunnel.recv_datagram(&mut dgram_buf) {
                Ok(len) if len > 0 => {
                    let mut packet = Self::take_pooled_buffer(buffer_pool, len);
                    packet.extend_from_slice(&dgram_buf[..len]);
                    perf.inc_rx(len);
                    stack.inject_packet_owned(packet);
                }
                _ => break,
            }
        }
    }

    /// Common poll logic shared by MASQUE and WG modes:
    /// stack poll, socket notifications, DNS/UDP processing, TCP I/O, cleanup.
    fn poll_stack_common(state: &mut RuntimeState) -> bool {
        if let Err(e) = state.stack.poll() {
            log::error!("network stack poll failed: {}", e);
            return false;
        }
        state.perf.inc_poll();

        Self::notify_ready_waiters(&mut state.stack, &mut state.sockets);

        Self::process_dns_responses(
            &mut state.stack,
            &mut state.dns_queries,
            &mut state.dns_groups,
            &mut state.dns_cache,
            &state.dns_sockets,
        );

        Self::process_udp_responses(&mut state.stack, &mut state.udp_sessions, &state.udp_ports);

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
        for port in &stale_ports {
            if let Some(session) = state.udp_sessions.remove(port) {
                state.stack.remove_socket(session.handle);
                log::info!("UDP session expired on port {}", port);
            }
        }
        if !stale_ports.is_empty() {
            state.udp_ports.retain(|p| !stale_ports.contains(p));
        }

        let mut closed_handles = Vec::new();

        for handle in state.tcp_handles.iter().copied() {
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

        for handle in &closed_handles {
            state.sockets.remove(handle);
            state.stack.remove_socket(*handle);
        }
        if !closed_handles.is_empty() {
            state.tcp_handles
                .retain(|h| !closed_handles.contains(h));
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
                log::warn!("keepalive PING failed: {:?}", e);
            } else {
                log::trace!("sent keepalive PING");
            }
            *last_keepalive = Instant::now();
        }

        if !Self::poll_stack_common(state) {
            return false;
        }

        while let Some(mut packet) = state.stack.take_packet() {
            state.perf.inc_tx(packet.len());
            let send_result = tunnel.send_datagram(&mut packet);
            state.stack.recycle_tx_buffer(packet);
            match send_result {
                Ok(Some(icmp)) => {
                    log::debug!("injecting ICMP Packet Too Big ({} bytes)", icmp.len());
                    state.stack
                        .inject_packet_owned(BytesMut::from(Bytes::from(icmp)));
                }
                Ok(None) => {}
                Err(e) => {
                    log::debug!("datagram send failed: {:?}", e);
                }
            }
        }

        if let Err(e) = tunnel.quic_conn.send_async().await {
            log::debug!("QUIC send failed: {:?}", e);
        }
        true
    }

    async fn poll_all_wg(tunnel: &mut WgTunnel, state: &mut RuntimeState) -> bool {
        if !Self::poll_stack_common(state) {
            return false;
        }

        while let Some(packet) = state.stack.take_packet() {
            state.perf.inc_tx(packet.len());
            tunnel.encrypt_ip_packet(packet.as_ref());
            state.stack.recycle_tx_buffer(packet);
        }
        tunnel.flush_send_queue().await;
        true
    }

    /// Common flush logic: poll stack + TCP read handling.
    fn flush_stack_reads(state: &mut RuntimeState) -> bool {
        if let Err(e) = state.stack.poll() {
            log::error!("network stack poll failed: {}", e);
            return false;
        }
        state.perf.inc_poll();

        for handle in state.tcp_handles.iter().copied() {
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

        while let Some(mut packet) = state.stack.take_packet() {
            state.perf.inc_tx(packet.len());
            let send_result = tunnel.send_datagram(&mut packet);
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
            state.perf.inc_tx(packet.len());
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

    fn configure_udp_socket_buffers(
        socket: &std::net::UdpSocket,
        recv_size: usize,
        send_size: usize,
    ) {
        let sock = socket2::SockRef::from(socket);

        if let Err(e) = sock.set_recv_buffer_size(recv_size) {
            log::warn!("Failed to set SO_RCVBUF to {}KB: {}", recv_size / 1024, e);
        }
        if let Err(e) = sock.set_send_buffer_size(send_size) {
            log::warn!("Failed to set SO_SNDBUF to {}KB: {}", send_size / 1024, e);
        }

        let actual_recv = sock.recv_buffer_size().unwrap_or(0);
        let actual_send = sock.send_buffer_size().unwrap_or(0);
        log::info!(
            "WG UDP socket buffers: recv={}KB (req {}KB), send={}KB (req {}KB)",
            actual_recv / 1024,
            recv_size / 1024,
            actual_send / 1024,
            send_size / 1024,
        );
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

    fn take_pooled_buffer(pool: &BufferPool, capacity: usize) -> BytesMut {
        let mut guard = match pool.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(mut buf) = guard.pop() {
            buf.clear();
            if buf.capacity() < capacity {
                buf.reserve(capacity - buf.capacity());
            }
            buf
        } else {
            BytesMut::with_capacity(capacity)
        }
    }

    fn return_pooled_buffer(pool: &BufferPool, mut buf: BytesMut) {
        buf.clear();
        let mut guard = match pool.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.len() < POOL_MAX_SIZE {
            guard.push(buf);
        }
    }

    fn build_perf_snapshot(
        state: &mut RuntimeState,
        cmd_queue_len: usize,
        udp_queue_len: usize,
        incoming_queue_len: usize,
    ) -> PerfSnapshot {
        let DeviceStats {
            rx_queue_len,
            tx_queue_len,
            rx_drops,
            tx_drops,
        } = state.stack.take_device_stats();

        let mut pending_from_client_bytes = 0usize;
        let mut pending_to_client_bytes = 0usize;
        for socket_state in state.sockets.values() {
            pending_from_client_bytes += socket_state.pending_from_client_bytes;
            pending_to_client_bytes += socket_state.pending_to_client_bytes;
        }

        PerfSnapshot {
            sockets: state.sockets.len(),
            udp_sessions: state.udp_sessions.len(),
            dns_groups: state.dns_groups.len(),
            pending_from_client_bytes,
            pending_to_client_bytes,
            rx_queue_len,
            tx_queue_len,
            rx_drops,
            tx_drops,
            cmd_queue_len,
            udp_queue_len,
            incoming_queue_len,
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
