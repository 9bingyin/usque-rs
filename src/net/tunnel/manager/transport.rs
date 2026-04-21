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

    fn blocked_send_deadline(&self, max_poll_interval: Duration) -> Option<TokioInstant> {
        match self {
            ActiveTunnel::Masque { blocked_until, .. } => blocked_until
                .as_ref()
                .copied()
                .filter(|until| *until > TokioInstant::now())
                .map(|until| until.min(TokioInstant::now() + max_poll_interval)),
            ActiveTunnel::Wg { .. } => None,
        }
    }

    fn from_conn(
        conn: TunnelConn,
        keepalive_secs: u64,
        tunables: &ManagerTunables,
    ) -> (Self, NetworkStack, Option<IncomingTask>) {
        match conn {
            TunnelConn::Masque(tunnel, stack) => {
                let (io, incoming_task) =
                    MasqueIoHandle::spawn(tunnel, stack.buffer_pool(), keepalive_secs, tunables);
                (
                    Self::Masque {
                        io,
                        blocked_streak: 0,
                        blocked_until: None,
                    },
                    stack,
                    Some(incoming_task),
                )
            }
            TunnelConn::Wg(tunnel, stack) => (
                Self::Wg {
                    tunnel,
                    next_timer_at: TokioInstant::now() + tunables.wg_timer_interval,
                },
                stack,
                None,
            ),
        }
    }

    fn socket(&self) -> Arc<tokio::net::UdpSocket> {
        match self {
            ActiveTunnel::Masque { io, .. } => io.socket.clone(),
            ActiveTunnel::Wg { tunnel, .. } => tunnel.socket(),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        match self {
            ActiveTunnel::Masque { io, .. } => io.peer_addr,
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
            ActiveTunnel::Masque { io, .. } => {
                if !io.is_alive() {
                    log::error!("QUIC IO worker closed unexpectedly");
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
            ActiveTunnel::Masque { .. } => None,
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
            ActiveTunnel::Masque { io, .. } => io.pending_send_packets(),
            ActiveTunnel::Wg { tunnel, .. } => tunnel.pending_send_packets(),
        }
    }

    fn has_transport_flush_pending(&self) -> bool {
        match self {
            ActiveTunnel::Masque { .. } => false,
            ActiveTunnel::Wg { .. } => false,
        }
    }

    fn mark_transport_flush_pending(&mut self) {
        let _ = self;
    }

    fn quic_perf_stats(&self) -> Option<quic::QuicPerfStats> {
        match self {
            ActiveTunnel::Masque { io, .. } => io.quic_perf_stats(),
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
            ActiveTunnel::Masque { .. } => false,
            ActiveTunnel::Wg { .. } => false,
        }
    }

    fn manager_drives_transport_flush(&self) -> bool {
        matches!(self, ActiveTunnel::Wg { .. })
    }

}

impl TunnelManager {
    fn spawn_incoming_task(
        socket: Arc<tokio::net::UdpSocket>,
        buffer_pool: BufferPool,
        _peer_addr: SocketAddr,
        tunables: &ManagerTunables,
    ) -> IncomingTask {
        let (incoming_tx, incoming_rx) = mpsc::channel(tunables.incoming_dgram_capacity);
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let mut shutdown_sub = shutdown_tx.subscribe();
        let (completion_tx, completion_rx) = mpsc::channel::<()>(1);
        let recv_completion_tx = completion_tx.clone();
        let udp_recv_buffer_size = tunables.udp_recv_buffer_size;
        let pool_max_size = tunables.pool_max_size;
        let buffer_reuse_max_capacity = tunables.buffer_reuse_max_capacity;
        let udp_read_drain_budget = tunables.udp_batch_read_budget.saturating_mul(4).max(1);

        let recv_handle = tokio::spawn(async move {
            let _guard = recv_completion_tx;
            loop {
                tokio::select! {
                    _ = shutdown_sub.recv() => break,
                    readable = socket.readable() => {
                        match readable {
                            Ok(()) => {
                                if Self::drain_ready_udp_socket(
                                    socket.as_ref(),
                                    &incoming_tx,
                                    &buffer_pool,
                                    udp_recv_buffer_size,
                                    pool_max_size,
                                    buffer_reuse_max_capacity,
                                    udp_read_drain_budget,
                                )
                                .await
                                .is_err()
                                {
                                    break;
                                }
                            }
                            Err(e) => {
                                log::warn!("UDP readable wait failed: {}", e);
                            }
                        }
                    }
                }
            }
        });

        IncomingTask {
            incoming_rx,
            shutdown_tx: Some(shutdown_tx),
            completion_tx: Some(completion_tx),
            completion_rx: Some(completion_rx),
            recv_handle: Some(recv_handle),
        }
    }

    async fn drain_ready_udp_socket(
        socket: &tokio::net::UdpSocket,
        incoming_tx: &mpsc::Sender<TransportIoEvent>,
        buffer_pool: &BufferPool,
        udp_recv_buffer_size: usize,
        pool_max_size: usize,
        buffer_reuse_max_capacity: usize,
        budget: usize,
    ) -> Result<usize, ()> {
        let mut drained = 0usize;
        while drained < budget {
            let mut buf = Self::take_pooled_buffer(buffer_pool, udp_recv_buffer_size);
            buf.resize(udp_recv_buffer_size, 0);
            match socket.try_recv(&mut buf[..]) {
                Ok(0) => {
                    Self::return_pooled_buffer(
                        buffer_pool,
                        buf,
                        pool_max_size,
                        buffer_reuse_max_capacity,
                    );
                    break;
                }
                Ok(len) => {
                    drained += 1;
                    buf.truncate(len);
                    if incoming_tx
                        .send(TransportIoEvent::Incoming(IncomingDatagram { data: buf }))
                        .await
                        .is_err()
                    {
                        log::trace!("incoming datagram channel closed");
                        return Err(());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    Self::return_pooled_buffer(
                        buffer_pool,
                        buf,
                        pool_max_size,
                        buffer_reuse_max_capacity,
                    );
                    break;
                }
                Err(e) => {
                    Self::return_pooled_buffer(
                        buffer_pool,
                        buf,
                        pool_max_size,
                        buffer_reuse_max_capacity,
                    );
                    log::warn!("UDP recv error: {}", e);
                    break;
                }
            }
        }
        Ok(drained)
    }

    async fn shutdown_incoming_task(mut task: IncomingTask) {
        if let Some(shutdown_tx) = task.shutdown_tx.take()
            && shutdown_tx.send(()).is_err()
        {
            log::trace!("shutdown signal dropped");
        }
        drop(task.completion_tx.take());
        if let Some(completion_rx) = task.completion_rx.as_mut() {
            let _ = completion_rx.recv().await;
        }
        if let Some(recv_handle) = task.recv_handle.take()
            && let Err(e) = recv_handle.await
        {
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
            ActiveTunnel::Masque { .. } => {}
        }
    }

    fn handle_incoming_datagram(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        incoming: IncomingDatagram,
    ) -> IncomingHandling {
        match tunnel {
            ActiveTunnel::Masque { .. } => {
                let data = incoming.data;
                state.perf.inc_rx(data.len());
                Self::note_incoming_tcp_handle(state, &data[..]);
                state.stack.inject_packet_owned(data);
                IncomingHandling {
                    stack_ingress: true,
                    needs_transport_flush: false,
                }
            }
            ActiveTunnel::Wg { tunnel, .. } => {
                let mut data = incoming.data;
                state.perf.inc_rx(data.len());
                let handling = if let Some(packet) = tunnel.decrypt_incoming(&mut data) {
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
                };
                Self::return_pooled_buffer(
                    &state.datagram_pool,
                    data,
                    state.tunables.pool_max_size,
                    state.tunables.buffer_reuse_max_capacity,
                );
                handling
            }
        }
    }

    fn handle_transport_io_event(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        event: TransportIoEvent,
    ) -> IncomingHandling {
        match event {
            TransportIoEvent::Incoming(incoming) => {
                Self::handle_incoming_datagram(tunnel, state, incoming)
            }
            TransportIoEvent::QuicFlush(status) => {
                state.perf.record_masque_send_batch(status);
                IncomingHandling::default()
            }
            TransportIoEvent::MasqueBlocked => {
                state.perf.inc_masque_blocked();
                IncomingHandling::default()
            }
        }
    }

    async fn flush_transport_side_effects(
        tunnel: &mut ActiveTunnel,
        perf: &mut PerfCounters,
    ) {
        match tunnel {
            ActiveTunnel::Masque {
                ..
            } => {}
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
        transport_send_due: bool,
    ) -> bool {
        if stack_due && !Self::poll_stack_common(state, true) {
            return false;
        }

        if stack_due || transport_send_due {
            Self::drain_stack_packets(tunnel, state).await;
        }
        if tunnel.manager_drives_transport_flush() && (stack_due || transport_send_due) {
            tunnel.mark_transport_flush_pending();
        }
        if tunnel.manager_drives_transport_flush()
            && (tunnel.has_transport_flush_pending() || tunnel.transport_pending_send_packets() > 0)
        {
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
                io,
                blocked_streak,
                blocked_until,
                ..
            } => {
                let batch_size = io.send_batch_size().min(budget.max(1));
                let mut attempted = 0usize;
                while attempted < budget {
                    let Some(first_packet) = state.stack.take_packet() else {
                        break;
                    };
                    let mut packets = Vec::with_capacity(batch_size);
                    state.perf.inc_tx(first_packet.len());
                    packets.push(first_packet);
                    attempted += 1;

                    while attempted < budget && packets.len() < batch_size {
                        let Some(packet) = state.stack.take_packet() else {
                            break;
                        };
                        state.perf.inc_tx(packet.len());
                        packets.push(packet);
                        attempted += 1;
                    }

                    match io.try_send_batch(packets) {
                        Ok(()) => {
                            *blocked_streak = 0;
                            *blocked_until = None;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(packets)) => {
                            state.perf.inc_masque_blocked();
                            *blocked_streak = blocked_streak.saturating_add(1).min(6);
                            let backoff_ms = 1u64 << (*blocked_streak as u32 - 1);
                            *blocked_until = Some(
                                TokioInstant::now()
                                    + Duration::from_millis(backoff_ms.min(32)),
                            );
                            for packet in packets.into_iter().rev() {
                                state.stack.requeue_packet_front(packet);
                            }
                            break;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(packets)) => {
                            log::debug!("MASQUE IO channel closed");
                            for packet in packets.into_iter().rev() {
                                state.stack.requeue_packet_front(packet);
                            }
                            break;
                        }
                    }
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

#[cfg(test)]
mod transport_tests {
    use super::*;
    use std::sync::Mutex;

    fn test_buffer_pool() -> BufferPool {
        Arc::new(Mutex::new(Vec::new()))
    }

    #[tokio::test]
    async fn drain_ready_udp_socket_drains_multiple_datagrams() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.connect(receiver.local_addr().unwrap()).await.unwrap();

        sender.send(b"one").await.unwrap();
        sender.send(b"two").await.unwrap();

        receiver.readable().await.unwrap();

        let (event_tx, mut event_rx) = mpsc::channel(4);
        let drained = TunnelManager::drain_ready_udp_socket(
            &receiver,
            &event_tx,
            &test_buffer_pool(),
            2048,
            8,
            2048,
            8,
        )
        .await
        .unwrap();

        assert_eq!(drained, 2);
        assert!(matches!(
            event_rx.try_recv(),
            Ok(TransportIoEvent::Incoming(IncomingDatagram { data })) if &data[..] == b"one"
        ));
        assert!(matches!(
            event_rx.try_recv(),
            Ok(TransportIoEvent::Incoming(IncomingDatagram { data })) if &data[..] == b"two"
        ));
    }

    #[tokio::test]
    async fn drain_ready_udp_socket_respects_budget() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.connect(receiver.local_addr().unwrap()).await.unwrap();

        sender.send(b"one").await.unwrap();
        sender.send(b"two").await.unwrap();
        sender.send(b"three").await.unwrap();

        receiver.readable().await.unwrap();

        let (event_tx, mut event_rx) = mpsc::channel(4);
        let drained = TunnelManager::drain_ready_udp_socket(
            &receiver,
            &event_tx,
            &test_buffer_pool(),
            2048,
            8,
            2048,
            2,
        )
        .await
        .unwrap();

        assert_eq!(drained, 2);
        assert!(matches!(
            event_rx.try_recv(),
            Ok(TransportIoEvent::Incoming(IncomingDatagram { data })) if &data[..] == b"one"
        ));
        assert!(matches!(
            event_rx.try_recv(),
            Ok(TransportIoEvent::Incoming(IncomingDatagram { data })) if &data[..] == b"two"
        ));
        assert!(matches!(
            event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        let drained = TunnelManager::drain_ready_udp_socket(
            &receiver,
            &event_tx,
            &test_buffer_pool(),
            2048,
            8,
            2048,
            2,
        )
        .await
        .unwrap();

        assert_eq!(drained, 1);
        assert!(matches!(
            event_rx.try_recv(),
            Ok(TransportIoEvent::Incoming(IncomingDatagram { data })) if &data[..] == b"three"
        ));
    }
}
