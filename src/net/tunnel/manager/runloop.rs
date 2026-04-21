impl TunnelManager {
    pub fn new(params: ConnectionParams) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(params.manager_tunables.cmd_channel_capacity);
        let (udp_tx, udp_rx) = mpsc::channel(params.manager_tunables.udp_data_channel_capacity);

        tokio::spawn(Self::maintain_tunnel(params, cmd_rx, udp_rx));

        Self { cmd_tx, udp_tx }
    }

    async fn maintain_tunnel(
        params: ConnectionParams,
        mut cmd_rx: mpsc::Receiver<ManagerCommand>,
        mut udp_rx: mpsc::Receiver<UdpSend>,
    ) {
        let mut backoff = ExponentialBackoff::new();

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
                                let (active_tunnel, stack, incoming_task) =
                                    ActiveTunnel::from_conn(conn, params.keepalive, &params.manager_tunables);
                                Self::run_active_tunnel(
                                    active_tunnel,
                                    stack,
                                    incoming_task,
                                    &mut cmd_rx,
                                    &mut udp_rx,
                                    &params,
                                )
                                .await;
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
        fn env_u64(name: &str, default: u64) -> u64 {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        fn env_usize(name: &str, default: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        fn env_f64(name: &str, default: f64) -> f64 {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        let quic_cfg = quic::QuicConfig {
            idle_timeout: params.quic_idle_timeout_ms,
            initial_packet_size: params.initial_packet_size,
            max_recv_udp_payload_size: env_usize(
                "USQUE_QUIC_MAX_RECV_UDP_PAYLOAD_SIZE",
                usize::from(params.initial_packet_size.max(1350)),
            ),
            max_connection_window: env_u64("USQUE_QUIC_MAX_CONNECTION_WINDOW", 20_000_000),
            max_stream_window: env_u64("USQUE_QUIC_MAX_STREAM_WINDOW", 8_000_000),
            send_capacity_factor: env_f64("USQUE_QUIC_SEND_CAPACITY_FACTOR", 2.0),
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
        let stack = NetworkStack::new(ipv4, ipv6, mtu, params.stack_tunables.clone());

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
        Self::configure_udp_socket_buffers(
            &std_socket,
            params.manager_tunables.wg_udp_recv_buffer_size,
            params.manager_tunables.wg_udp_send_buffer_size,
        );
        let socket = tokio::net::UdpSocket::from_std(std_socket)?;
        let socket = Arc::new(socket);

        let keepalive = if params.keepalive > 0 {
            Some(params.keepalive as u16)
        } else {
            None
        };
        let mtu = if params.mtu == 0 {
            1280
        } else {
            params.mtu as usize
        };

        let mut wg_tunnel = WgTunnel::new(
            wg_private_key,
            wg_peer_public_key,
            socket,
            wg_client_id,
            keepalive,
            mtu,
        );

        wg_tunnel.establish(Duration::from_secs(30)).await?;

        log::info!("WireGuard tunnel established, MTU {}", mtu);
        if let Some(ref v6) = params.ipv6 {
            log::info!("client IP: {}, {}", params.ipv4, v6);
        } else {
            log::info!("client IP: {}", params.ipv4);
        }

        let ipv4 = if params.ipv4.trim().is_empty() {
            None
        } else {
            Some(params.ipv4.as_str())
        };
        let ipv6 = params.ipv6.as_deref().filter(|s| !s.trim().is_empty());
        let stack = NetworkStack::new(ipv4, ipv6, mtu, params.stack_tunables.clone());

        Ok((wg_tunnel, stack))
    }

    pub async fn connect(
        &self,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<SocketStream, ManagerError> {
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

    async fn run_active_tunnel(
        mut tunnel: ActiveTunnel,
        stack: NetworkStack,
        incoming_task: Option<IncomingTask>,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        params: &ConnectionParams,
    ) {
        let mut incoming_task = incoming_task.unwrap_or_else(|| {
            Self::spawn_incoming_task(
                tunnel.socket(),
                stack.buffer_pool(),
                tunnel.peer_addr(),
                &params.manager_tunables,
            )
        });
        let mut state = RuntimeState::new(
            stack,
            params.manager_tunables.clone(),
            params.perf_enabled,
            params.perf_interval_secs,
        );
        let poll_timer = tokio::time::sleep(Duration::from_millis(0));
        tokio::pin!(poll_timer);

        loop {
            if !tunnel.check_alive() {
                break;
            }

            state.perf.inc_loop();
            let stack_poll_deadline = tunnel.stack_poll_deadline(&mut state);
            let transport_timeout_deadline =
                tunnel.transport_timeout_deadline(state.tunables.max_poll_interval);
            let transport_send_deadline =
                tunnel.transport_send_deadline(state.tunables.max_poll_interval);
            let poll_deadline = [stack_poll_deadline, transport_timeout_deadline, transport_send_deadline]
                .into_iter()
                .flatten()
                .min();
            let has_poll_timer = poll_deadline.is_some();
            let socket = tunnel.socket();
            let needs_socket_writable = tunnel.needs_socket_writable();
            poll_timer.as_mut().reset(
                poll_deadline
                    .unwrap_or_else(|| {
                        TokioInstant::now() + Duration::from_secs(365 * 24 * 60 * 60)
                    }),
            );

            let has_maintenance = tunnel.maintenance_deadline().is_some();
            let maintenance_deadline = tunnel
                .maintenance_deadline()
                .unwrap_or_else(|| TokioInstant::now() + Duration::from_secs(365 * 24 * 60 * 60));
            let maintenance_timer = tokio::time::sleep_until(maintenance_deadline);
            tokio::pin!(maintenance_timer);

            let mut dirty = false;
            let mut needs_transport_flush = false;

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

                Some(event) = incoming_task.incoming_rx.recv() => {
                    let handled = Self::handle_transport_io_event(&mut tunnel, &mut state, event);
                    needs_transport_flush |= handled.needs_transport_flush;
                    dirty = true;
                }

                Some(event) = state.socket_event_rx.recv() => {
                    Self::handle_socket_event(&mut state, event);
                    dirty = true;
                }

                writable = socket.writable(), if needs_socket_writable => {
                    match writable {
                        Ok(()) => {
                            needs_transport_flush = true;
                        }
                        Err(e) => {
                            log::debug!("UDP writable wait failed: {}", e);
                        }
                    }
                }

                _ = &mut maintenance_timer, if has_maintenance => {
                    Self::run_maintenance_tick(&mut tunnel, &state.tunables).await;
                    needs_transport_flush = true;
                }

                _ = &mut poll_timer, if has_poll_timer => {
                    let now = TokioInstant::now();
                    let stack_due = stack_poll_deadline.is_some_and(|deadline| deadline <= now);
                    let transport_timeout_due =
                        transport_timeout_deadline.is_some_and(|deadline| deadline <= now);
                    let transport_send_due =
                        transport_send_deadline.is_some_and(|deadline| deadline <= now);
                    if !Self::poll_active_tunnel(
                        &mut tunnel,
                        &mut state,
                        stack_due,
                        transport_timeout_due,
                        transport_send_due,
                    )
                    .await
                    {
                        break;
                    }
                }
            }

            if !dirty && needs_transport_flush {
                Self::flush_transport_side_effects(&mut tunnel, &mut state.perf).await;
            }

            if dirty {
                if !Self::process_dirty_cycle(
                    &mut tunnel,
                    &mut state,
                    cmd_rx,
                    udp_rx,
                    &mut incoming_task,
                    params,
                )
                .await
                {
                    break;
                }
            }

            if state.perf.due() {
                let snapshot = Self::build_perf_snapshot(
                    &mut state,
                    &tunnel,
                    cmd_rx.len(),
                    udp_rx.len(),
                    incoming_task.incoming_rx.len(),
                );
                state.perf.report(snapshot);
            }

            let should_yield = poll_deadline.is_some_and(|deadline| deadline <= TokioInstant::now() + Duration::from_millis(1))
                || (dirty
                    && (cmd_rx.len() > 0
                        || udp_rx.len() > 0
                        || incoming_task.incoming_rx.len() > 0));
            if should_yield {
                state.perf.inc_yield();
                tokio::task::yield_now().await;
            }
        }

        let mode_name = tunnel.mode_name();
        Self::shutdown_incoming_task(incoming_task).await;
        log::debug!("{} run_loop ended", mode_name);
    }
}
