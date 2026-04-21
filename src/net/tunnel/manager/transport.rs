impl ActiveTunnel {
    fn stack_poll_deadline(&self, state: &mut RuntimeState) -> Option<TokioInstant> {
        if !state.has_poll_work() {
            return None;
        }

        if state.stack.has_rx_packets() {
            return Some(TokioInstant::now());
        }

        let timeout = state
            .stack
            .poll_delay()
            .unwrap_or(Duration::ZERO)
            .min(state.tunables.max_poll_interval);
        Some(TokioInstant::now() + timeout)
    }

    fn transport_timeout_deadline(&self, max_poll_interval: Duration) -> Option<TokioInstant> {
        match self {
            ActiveTunnel::Masque { tunnel, .. } => tunnel
                .quic_conn
                .conn
                .timeout()
                .map(|timeout| TokioInstant::now() + timeout.min(max_poll_interval)),
            ActiveTunnel::Wg { .. } => None,
        }
    }

    fn transport_send_deadline(&self, max_poll_interval: Duration) -> Option<TokioInstant> {
        match self {
            ActiveTunnel::Masque {
                tunnel,
                blocked_until,
                ..
            } => {
                let mut deadline = tunnel
                    .quic_conn
                    .next_send_at()
                    .map(TokioInstant::from_std);
                if let Some(until) = blocked_until
                    && *until > TokioInstant::now()
                {
                    deadline = Some(deadline.map_or(*until, |current| current.min(*until)));
                }
                deadline.map(|when| when.min(TokioInstant::now() + max_poll_interval))
            }
            ActiveTunnel::Wg { .. } => None,
        }
    }

    fn from_conn(
        conn: TunnelConn,
        keepalive_secs: u64,
        tunables: &ManagerTunables,
    ) -> (Self, NetworkStack) {
        match conn {
            TunnelConn::Masque(tunnel, stack) => (
                Self::Masque {
                    local_addr: tunnel.quic_conn.local_addr,
                    tunnel,
                    keepalive_interval: Duration::from_secs(keepalive_secs),
                    last_keepalive: Instant::now(),
                    blocked_streak: 0,
                    blocked_until: None,
                },
                stack,
            ),
            TunnelConn::Wg(tunnel, stack) => (
                Self::Wg {
                    tunnel,
                    next_timer_at: TokioInstant::now() + tunables.wg_timer_interval,
                },
                stack,
            ),
        }
    }

    fn socket(&self) -> Arc<tokio::net::UdpSocket> {
        match self {
            ActiveTunnel::Masque { tunnel, .. } => tunnel.quic_conn.socket.clone(),
            ActiveTunnel::Wg { tunnel, .. } => tunnel.socket(),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        match self {
            ActiveTunnel::Masque { tunnel, .. } => tunnel.quic_conn.peer_addr,
            ActiveTunnel::Wg { tunnel, .. } => tunnel
                .socket()
                .peer_addr()
                .expect("WG socket should be connected"),
        }
    }

    fn mode_name(&self) -> &'static str {
        match self {
            ActiveTunnel::Masque { .. } => "MASQUE",
            ActiveTunnel::Wg { .. } => "WireGuard",
        }
    }

    fn check_alive(&self) -> bool {
        match self {
            ActiveTunnel::Masque { tunnel, .. } => {
                if tunnel.quic_conn.is_closed() {
                    log::error!("QUIC connection closed unexpectedly");
                    false
                } else {
                    true
                }
            }
            ActiveTunnel::Wg { tunnel, .. } => {
                if tunnel.is_expired() {
                    log::error!("WireGuard tunnel session expired");
                    false
                } else {
                    true
                }
            }
        }
    }

    fn maintenance_deadline(&self) -> Option<TokioInstant> {
        match self {
            ActiveTunnel::Wg { next_timer_at, .. } => Some(*next_timer_at),
            ActiveTunnel::Masque {
                keepalive_interval,
                last_keepalive,
                ..
            } => {
                if keepalive_interval.is_zero() {
                    None
                } else {
                    Some(TokioInstant::from_std(*last_keepalive + *keepalive_interval))
                }
            }
        }
    }

    fn stack_drain_budget(&self, tunables: &ManagerTunables) -> usize {
        match self {
            ActiveTunnel::Masque { .. } => tunables.masque_stack_drain_budget,
            ActiveTunnel::Wg { .. } => tunables.wg_stack_drain_budget,
        }
    }

    fn transport_pending_send_packets(&self) -> usize {
        match self {
            ActiveTunnel::Masque { tunnel, .. } => tunnel.quic_conn.pending_send_packets(),
            ActiveTunnel::Wg { tunnel, .. } => tunnel.pending_send_packets(),
        }
    }

    fn has_transport_flush_pending(&self) -> bool {
        match self {
            ActiveTunnel::Masque { tunnel, .. } => tunnel.quic_conn.has_pending_send_work(),
            ActiveTunnel::Wg { .. } => false,
        }
    }

    fn mark_transport_flush_pending(&mut self) {
        if let ActiveTunnel::Masque { tunnel, .. } = self {
            tunnel.quic_conn.mark_pending_send();
        }
    }

    fn quic_perf_stats(&self) -> Option<quic::QuicPerfStats> {
        match self {
            ActiveTunnel::Masque { tunnel, .. } => tunnel.quic_conn.perf_stats(),
            ActiveTunnel::Wg { .. } => None,
        }
    }

    fn masque_drain_blocked(&self) -> bool {
        matches!(
            self,
            ActiveTunnel::Masque {
                blocked_until: Some(until),
                ..
            } if *until > TokioInstant::now()
        )
    }

    fn needs_socket_writable(&self) -> bool {
        match self {
            ActiveTunnel::Masque { tunnel, .. } => tunnel.quic_conn.needs_socket_writable(),
            ActiveTunnel::Wg { .. } => false,
        }
    }

}

impl TunnelManager {
    fn spawn_incoming_task(
        socket: Arc<tokio::net::UdpSocket>,
        buffer_pool: BufferPool,
        peer_addr: SocketAddr,
        tunables: &ManagerTunables,
    ) -> IncomingTask {
        let (incoming_tx, incoming_rx) = mpsc::channel(tunables.incoming_dgram_capacity);
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let mut shutdown_sub = shutdown_tx.subscribe();
        let (completion_tx, completion_rx) = mpsc::channel::<()>(1);
        let recv_completion_tx = completion_tx.clone();
        let udp_recv_buffer_size = tunables.udp_recv_buffer_size;
        let pool_max_size = tunables.pool_max_size;

        let recv_handle = tokio::spawn(async move {
            let _guard = recv_completion_tx;
            loop {
                tokio::select! {
                    _ = shutdown_sub.recv() => break,
                    result = async {
                        let mut buf = Self::take_pooled_buffer(&buffer_pool, udp_recv_buffer_size);
                        buf.resize(udp_recv_buffer_size, 0);
                        match socket.recv(&mut buf[..]).await {
                            Ok(len) => Ok((buf, len)),
                            Err(e) => Err((buf, e)),
                        }
                    } => {
                        match result {
                            Ok((mut buf, len)) => {
                                if len == 0 {
                                    Self::return_pooled_buffer(&buffer_pool, buf, pool_max_size);
                                    continue;
                                }
                                buf.truncate(len);
                                if incoming_tx.send(IncomingDatagram { data: buf, from: peer_addr }).await.is_err() {
                                    log::trace!("incoming datagram channel closed");
                                    break;
                                }
                            }
                            Err((buf, e)) => {
                                Self::return_pooled_buffer(&buffer_pool, buf, pool_max_size);
                                log::warn!("UDP recv error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        IncomingTask {
            incoming_rx,
            shutdown_tx,
            completion_tx,
            completion_rx,
            recv_handle,
        }
    }

    async fn shutdown_incoming_task(mut task: IncomingTask) {
        if task.shutdown_tx.send(()).is_err() {
            log::trace!("shutdown signal dropped");
        }
        drop(task.completion_tx);
        let _ = task.completion_rx.recv().await;
        if let Err(e) = task.recv_handle.await {
            log::trace!("recv task join error: {:?}", e);
        }
    }

    async fn run_maintenance_tick(tunnel: &mut ActiveTunnel, tunables: &ManagerTunables) {
        match tunnel {
            ActiveTunnel::Wg {
                tunnel,
                next_timer_at,
            } => {
                if let Err(e) = tunnel.tick_timers().await {
                    log::warn!("WireGuard timer error: {}", e);
                }
                *next_timer_at = TokioInstant::now() + tunables.wg_timer_interval;
            }
            ActiveTunnel::Masque {
                tunnel,
                last_keepalive,
                keepalive_interval,
                ..
            } => {
                if !keepalive_interval.is_zero() {
                    if let Err(e) = tunnel.quic_conn.conn.send_ack_eliciting() {
                        log::warn!("keepalive PING failed: {:?}", e);
                    } else {
                        log::trace!("sent keepalive PING");
                        tunnel.quic_conn.mark_pending_send();
                    }
                    *last_keepalive = Instant::now();
                }
            }
        }
    }

    fn handle_incoming_datagram(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        incoming: IncomingDatagram,
    ) -> IncomingHandling {
        let mut data = incoming.data;

        let handling = match tunnel {
            ActiveTunnel::Masque {
                tunnel,
                local_addr,
                ..
            } => {
                tunnel.quic_conn.mark_pending_send();
                IncomingHandling {
                    stack_ingress: Self::handle_udp_recv(
                    tunnel,
                    state,
                    &mut data[..],
                    incoming.from,
                    *local_addr,
                    ),
                    needs_transport_flush: true,
                }
            }
            ActiveTunnel::Wg { tunnel, .. } => {
                state.perf.inc_rx(data.len());
                let packet = tunnel.decrypt_incoming(&mut data);
                if let Some(packet) = packet {
                    Self::note_incoming_tcp_handle(state, &packet[..]);
                    state.stack.inject_packet_owned(packet);
                    IncomingHandling {
                        stack_ingress: true,
                        needs_transport_flush: true,
                    }
                } else {
                    IncomingHandling {
                        stack_ingress: false,
                        needs_transport_flush: true,
                    }
                }
            }
        };

        Self::return_pooled_buffer(&state.buffer_pool, data, state.tunables.pool_max_size);
        handling
    }

    async fn flush_transport_side_effects(
        tunnel: &mut ActiveTunnel,
        perf: &mut PerfCounters,
    ) {
        match tunnel {
            ActiveTunnel::Masque {
                tunnel: masque_tunnel,
                ..
            } => {
                let should_flush = masque_tunnel.quic_conn.pending_send_packets() > 0
                    || masque_tunnel.quic_conn.take_pending_send();
                if !should_flush {
                    return;
                }
                match masque_tunnel.quic_conn.send_async().await {
                    Ok(status) => perf.record_quic_flush(status),
                    Err(e) => log::debug!("QUIC send failed: {:?}", e),
                }
            }
            ActiveTunnel::Wg { tunnel, .. } => {
                let _ = tunnel.drain_queued_to_send_queue();
                if tunnel.pending_send_packets() > 0 {
                    let flushed = tunnel.flush_send_queue().await;
                    if flushed > 0 {
                        perf.inc_wg_flush();
                    }
                }
            }
        }
    }

    async fn poll_active_tunnel(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        stack_due: bool,
        transport_timeout_due: bool,
        transport_send_due: bool,
    ) -> bool {
        if transport_timeout_due
            && let ActiveTunnel::Masque { tunnel, .. } = tunnel
        {
            tunnel.quic_conn.conn.on_timeout();
            tunnel.quic_conn.mark_pending_send();
        }

        if stack_due && !Self::poll_stack_common(state, true) {
            return false;
        }

        if stack_due || transport_send_due {
            Self::drain_stack_packets(tunnel, state).await;
        }
        if stack_due || transport_send_due {
            tunnel.mark_transport_flush_pending();
        }
        if tunnel.has_transport_flush_pending() || tunnel.transport_pending_send_packets() > 0 {
            Self::flush_transport_side_effects(tunnel, &mut state.perf).await;
        }
        true
    }

    async fn drain_stack_packets(tunnel: &mut ActiveTunnel, state: &mut RuntimeState) {
        let budget = tunnel.stack_drain_budget(&state.tunables);
        if tunnel.masque_drain_blocked() {
            return;
        }

        match tunnel {
            ActiveTunnel::Masque {
                tunnel: masque_tunnel,
                blocked_streak,
                blocked_until,
                ..
            } => {
                let mut attempted = 0usize;
                let mut queued_to_quiche = false;
                while attempted < budget {
                    let Some(packet) = state.stack.take_packet() else {
                        break;
                    };
                    state.perf.inc_tx(packet.len());
                    attempted += 1;
                    match masque_tunnel.send_datagram(&packet) {
                        Ok(crate::net::tunnel::masque::DatagramSendState::Sent) => {
                            *blocked_streak = 0;
                            *blocked_until = None;
                            queued_to_quiche = true;
                            state.stack.recycle_tx_buffer(packet);
                        }
                        Ok(crate::net::tunnel::masque::DatagramSendState::Dropped) => {
                            *blocked_streak = 0;
                            *blocked_until = None;
                            queued_to_quiche = true;
                            state.stack.recycle_tx_buffer(packet);
                        }
                        Ok(crate::net::tunnel::masque::DatagramSendState::PacketTooBig(icmp)) => {
                            *blocked_streak = 0;
                            *blocked_until = None;
                            queued_to_quiche = true;
                            state.stack.recycle_tx_buffer(packet);
                            log::debug!("injecting ICMP Packet Too Big ({} bytes)", icmp.len());
                            state
                                .stack
                                .inject_packet_owned(BytesMut::from(Bytes::from(icmp)));
                        }
                        Ok(crate::net::tunnel::masque::DatagramSendState::Blocked) => {
                            state.perf.inc_masque_blocked();
                            *blocked_streak = blocked_streak.saturating_add(1).min(6);
                            let backoff_ms = 1u64 << (*blocked_streak as u32 - 1);
                            *blocked_until = Some(
                                TokioInstant::now()
                                    + Duration::from_millis(backoff_ms.min(32)),
                            );
                            state.stack.requeue_packet_front(packet);
                            break;
                        }
                        Err(e) => {
                            state.stack.recycle_tx_buffer(packet);
                            log::debug!("datagram send failed: {:?}", e);
                        }
                    }
                }
                if queued_to_quiche {
                    masque_tunnel.quic_conn.mark_pending_send();
                }
            }
            ActiveTunnel::Wg { tunnel, .. } => {
                let mut drained = 0usize;
                while drained < budget {
                    let Some(packet) = state.stack.take_packet() else {
                        break;
                    };
                    state.perf.inc_tx(packet.len());
                    tunnel.encrypt_ip_packet(packet.as_ref());
                    state.stack.recycle_tx_buffer(packet);
                    drained += 1;
                }
                if drained > 0 || tunnel.pending_send_packets() > 0 {
                    let flushed = tunnel.flush_send_queue().await;
                    if flushed > 0 {
                        state.perf.inc_wg_flush();
                    }
                }
            }
        }
    }
}
