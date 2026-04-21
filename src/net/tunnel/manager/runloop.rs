struct LoopSchedule {
    stack_poll_deadline: Option<TokioInstant>,
    blocked_send_deadline: Option<TokioInstant>,
    poll_deadline: Option<TokioInstant>,
    maintenance_deadline: Option<TokioInstant>,
    needs_socket_writable: bool,
}

#[derive(Default)]
struct LoopSelectOutcome {
    dirty: bool,
    needs_transport_flush: bool,
    should_break: bool,
}

impl TunnelManager {
    pub fn new(params: ConnectionParams) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(params.manager_tunables.cmd_channel_capacity);
        let (udp_tx, udp_rx) = mpsc::channel(params.manager_tunables.udp_data_channel_capacity);
        let stats = Arc::new(ManagerRuntimeStats::new(
            params.manager_tunables.manager_max_tcp_sockets_per_worker,
        ));

        tokio::spawn(Self::maintain_tunnel(
            params,
            stats.clone(),
            cmd_rx,
            udp_rx,
        ));

        Self { cmd_tx, udp_tx, stats }
    }

    async fn maintain_tunnel(
        params: ConnectionParams,
        stats: Arc<ManagerRuntimeStats>,
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
                                    stats.clone(),
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
                            Some(cmd) => Self::handle_command_disconnected(&stats, cmd),
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
                            Some(cmd) => Self::handle_command_disconnected(&stats, cmd),
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

        let masque_tunnel = MasqueTunnel::connect(
            params.endpoint,
            &params.cert_der,
            &params.key_der,
            &params.sni,
            Duration::from_secs(30),
            params.endpoint_pub_key.as_deref(),
            &quic_cfg,
        )
        .await?;

        // Dynamically get MTU from QUIC datagram max size
        // tokio-quiche H3 driver already accounts for quarter stream id;
        // we still reserve one byte for MASQUE Context ID.
        let dynamic_mtu = masque_tunnel.max_ip_packet_len();

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
        if !self.stats.try_reserve_tcp_slot() {
            return Err(ManagerError::Overloaded);
        }
        self.connect_inner(remote_ip, remote_port, local_port).await
    }

    pub async fn connect_reserved(
        &self,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<SocketStream, ManagerError> {
        self.connect_inner(remote_ip, remote_port, local_port).await
    }

    async fn connect_inner(
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
                reserved_slot: true,
                response: response_tx,
            })
            .await
            .map_err(|_| {
                self.stats.finish_reserved_tcp_connect();
                ManagerError::ChannelClosed
            })?;

        response_rx
            .await
            .map_err(|_| {
                self.stats.finish_reserved_tcp_connect();
                ManagerError::ResponseChannelClosed
            })?
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
        runtime_stats: Arc<ManagerRuntimeStats>,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        params: &ConnectionParams,
    ) {
        let datagram_pool: BufferPool = Arc::new(std::sync::Mutex::new(Vec::with_capacity(
            params.manager_tunables.pool_max_size,
        )));
        let mut incoming_task = incoming_task.unwrap_or_else(|| {
            Self::spawn_incoming_task(
                tunnel.socket(),
                datagram_pool.clone(),
                tunnel.peer_addr(),
                &params.manager_tunables,
            )
        });
        let mut state = RuntimeState::new(
            stack,
            datagram_pool,
            params.manager_tunables.clone(),
            runtime_stats.clone(),
            params.perf_enabled,
            params.perf_interval_secs,
        );
        let mut poll_timer = Box::pin(tokio::time::sleep(Duration::from_millis(0)));
        let mut maintenance_timer = Box::pin(tokio::time::sleep(Duration::from_millis(0)));

        loop {
            if !tunnel.check_alive() {
                break;
            }

            state.perf.inc_loop();
            let schedule = Self::compute_loop_schedule(
                &tunnel,
                &mut state,
                &mut poll_timer,
                &mut maintenance_timer,
            );
            let outcome = Self::run_loop_select_once(
                &mut tunnel,
                &mut state,
                &schedule,
                cmd_rx,
                udp_rx,
                &mut incoming_task,
                params,
                &mut poll_timer,
                &mut maintenance_timer,
            )
            .await;
            if !Self::finish_loop_iteration(
                &mut tunnel,
                &mut state,
                &schedule,
                outcome,
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

        let mode_name = tunnel.mode_name();
        state.runtime_stats.reset();
        Self::shutdown_incoming_task(incoming_task).await;
        log::debug!("{} run_loop ended", mode_name);
    }

    fn compute_loop_schedule(
        tunnel: &ActiveTunnel,
        state: &mut RuntimeState,
        poll_timer: &mut std::pin::Pin<Box<tokio::time::Sleep>>,
        maintenance_timer: &mut std::pin::Pin<Box<tokio::time::Sleep>>,
    ) -> LoopSchedule {
        let stack_poll_deadline = tunnel.stack_poll_deadline(state);
        let blocked_send_deadline = tunnel.blocked_send_deadline(state.tunables.max_poll_interval);
        let poll_deadline = [stack_poll_deadline, blocked_send_deadline]
            .into_iter()
            .flatten()
            .min();
        let maintenance_deadline = tunnel.maintenance_deadline();

        Self::reset_sleep_timer(poll_timer, poll_deadline);
        Self::reset_sleep_timer(maintenance_timer, maintenance_deadline);

        LoopSchedule {
            stack_poll_deadline,
            blocked_send_deadline,
            poll_deadline,
            maintenance_deadline,
            needs_socket_writable: tunnel.needs_socket_writable(),
        }
    }

    fn reset_sleep_timer(
        timer: &mut std::pin::Pin<Box<tokio::time::Sleep>>,
        deadline: Option<TokioInstant>,
    ) {
        timer
            .as_mut()
            .reset(deadline.unwrap_or_else(Self::disabled_timer_deadline));
    }

    fn disabled_timer_deadline() -> TokioInstant {
        TokioInstant::now() + Duration::from_secs(365 * 24 * 60 * 60)
    }

    async fn run_loop_select_once(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        schedule: &LoopSchedule,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        incoming_task: &mut IncomingTask,
        params: &ConnectionParams,
        poll_timer: &mut std::pin::Pin<Box<tokio::time::Sleep>>,
        maintenance_timer: &mut std::pin::Pin<Box<tokio::time::Sleep>>,
    ) -> LoopSelectOutcome {
        let socket = tunnel.socket();
        let mut outcome = LoopSelectOutcome::default();

        tokio::select! {
            biased;
            Some(cmd) = cmd_rx.recv() => {
                Self::handle_command(state, &params.dns_servers, params.tcp_buffer_size, cmd);
                outcome.dirty = true;
            }

            Some(udp_cmd) = udp_rx.recv() => {
                Self::handle_udp_send(&mut state.stack, &mut state.udp_sessions, udp_cmd);
                outcome.dirty = true;
            }

            Some(event) = incoming_task.incoming_rx.recv() => {
                let handled = Self::handle_transport_io_event(tunnel, state, event);
                outcome.needs_transport_flush |= handled.needs_transport_flush;
                outcome.dirty = true;
            }

            Some(event) = state.socket_event_rx.recv() => {
                Self::handle_socket_event(state, event);
                outcome.dirty = true;
            }

            writable = socket.writable(), if schedule.needs_socket_writable => {
                match writable {
                    Ok(()) => {
                        outcome.needs_transport_flush = true;
                    }
                    Err(e) => {
                        log::debug!("UDP writable wait failed: {}", e);
                    }
                }
            }

            _ = maintenance_timer.as_mut(), if schedule.maintenance_deadline.is_some() => {
                Self::run_maintenance_tick(tunnel, &state.tunables).await;
                outcome.needs_transport_flush = true;
            }

            _ = poll_timer.as_mut(), if schedule.poll_deadline.is_some() => {
                let now = TokioInstant::now();
                let stack_due = schedule
                    .stack_poll_deadline
                    .is_some_and(|deadline| deadline <= now);
                let transport_send_due = schedule
                    .blocked_send_deadline
                    .is_some_and(|deadline| deadline <= now);
                if !Self::poll_active_tunnel(
                    tunnel,
                    state,
                    stack_due,
                    transport_send_due,
                )
                .await
                {
                    outcome.should_break = true;
                }
            }
        }

        outcome
    }

    async fn finish_loop_iteration(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        schedule: &LoopSchedule,
        outcome: LoopSelectOutcome,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        incoming_task: &mut IncomingTask,
        params: &ConnectionParams,
    ) -> bool {
        if outcome.should_break {
            return false;
        }

        if !outcome.dirty && outcome.needs_transport_flush {
            Self::flush_transport_side_effects(tunnel, &mut state.perf).await;
        }

        if outcome.dirty
            && !Self::process_dirty_cycle(
                tunnel,
                state,
                cmd_rx,
                udp_rx,
                incoming_task,
                params,
            )
            .await
        {
            return false;
        }

        if state.perf.due() {
            let snapshot = Self::build_perf_snapshot(
                state,
                tunnel,
                cmd_rx.len(),
                udp_rx.len(),
                incoming_task.incoming_rx.len(),
            );
            state.perf.report(snapshot);
        }

        if Self::should_yield(
            schedule,
            outcome.dirty,
            cmd_rx.len(),
            udp_rx.len(),
            incoming_task.incoming_rx.len(),
        ) {
            state.perf.inc_yield();
            tokio::task::yield_now().await;
        }

        true
    }

    fn should_yield(
        schedule: &LoopSchedule,
        dirty: bool,
        cmd_queue_len: usize,
        udp_queue_len: usize,
        incoming_queue_len: usize,
    ) -> bool {
        let now = TokioInstant::now();
        schedule.poll_deadline.is_some_and(|deadline| deadline <= now)
            || schedule
                .maintenance_deadline
                .is_some_and(|deadline| deadline <= now)
            || (dirty && (cmd_queue_len > 0 || udp_queue_len > 0 || incoming_queue_len > 0))
    }

    fn reported_load(&self) -> ManagerLoadSnapshot {
        self.stats.snapshot()
    }

    fn try_reserve_tcp_slot(&self) -> bool {
        self.stats.try_reserve_tcp_slot()
    }
}

#[cfg(test)]
mod runloop_tests {
    use super::*;

    #[test]
    fn should_yield_when_deadline_is_overdue() {
        let schedule = LoopSchedule {
            stack_poll_deadline: None,
            blocked_send_deadline: None,
            poll_deadline: Some(TokioInstant::now()),
            maintenance_deadline: None,
            needs_socket_writable: false,
        };

        assert!(TunnelManager::should_yield(&schedule, false, 0, 0, 0));
    }

    #[test]
    fn should_not_yield_without_overdue_deadline_or_backlog() {
        let schedule = LoopSchedule {
            stack_poll_deadline: None,
            blocked_send_deadline: None,
            poll_deadline: Some(TokioInstant::now() + Duration::from_millis(20)),
            maintenance_deadline: Some(TokioInstant::now() + Duration::from_millis(20)),
            needs_socket_writable: false,
        };

        assert!(!TunnelManager::should_yield(&schedule, false, 0, 0, 0));
    }
}
