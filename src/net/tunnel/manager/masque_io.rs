use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

struct MasqueIoHandle {
    socket: Arc<tokio::net::UdpSocket>,
    peer_addr: SocketAddr,
    send_tx: mpsc::Sender<BytesMut>,
    queued_packets: Arc<AtomicUsize>,
    alive: Arc<AtomicBool>,
    quic_stats: Arc<Mutex<Option<QuicPerfStats>>>,
}

impl MasqueIoHandle {
    fn spawn(
        tunnel: Box<MasqueTunnel>,
        buffer_pool: BufferPool,
        keepalive_secs: u64,
        tunables: &ManagerTunables,
    ) -> (Self, IncomingTask) {
        let socket = tunnel.quic_conn.socket.clone();
        let peer_addr = tunnel.quic_conn.peer_addr;
        let (send_tx, mut send_rx) = mpsc::channel::<BytesMut>(tunables.masque_io_channel_capacity);
        let (event_tx, event_rx) =
            mpsc::channel::<TransportIoEvent>(tunables.incoming_dgram_capacity);
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let mut shutdown_sub = shutdown_tx.subscribe();
        let (completion_tx, completion_rx) = mpsc::channel::<()>(1);
        let worker_completion_tx = completion_tx.clone();
        let queued_packets = Arc::new(AtomicUsize::new(0));
        let queued_packets_worker = queued_packets.clone();
        let alive = Arc::new(AtomicBool::new(true));
        let alive_worker = alive.clone();
        let quic_stats = Arc::new(Mutex::new(None));
        let quic_stats_worker = quic_stats.clone();
        let pool_max_size = tunables.pool_max_size;
        let udp_recv_buffer_size = tunables.udp_recv_buffer_size;
        let max_poll_interval = tunables.max_poll_interval;
        let keepalive_interval = Duration::from_secs(keepalive_secs);
        let send_budget_limit = tunables.masque_stack_drain_budget;

        let recv_handle = tokio::spawn(async move {
            let _guard = worker_completion_tx;
            let mut tunnel = tunnel;
            let mut recv_buf =
                TunnelManager::take_pooled_buffer(&buffer_pool, udp_recv_buffer_size);
            recv_buf.resize(udp_recv_buffer_size, 0);
            let mut pending_packet: Option<BytesMut> = None;
            let mut last_keepalive = Instant::now();

            loop {
                if tunnel.quic_conn.is_closed() {
                    log::warn!("MASQUE IO worker detected closed QUIC connection");
                    break;
                }

                if let Ok(mut guard) = quic_stats_worker.lock() {
                    *guard = tunnel.quic_conn.perf_stats();
                }

                if !keepalive_interval.is_zero() && last_keepalive.elapsed() >= keepalive_interval {
                    if let Err(e) = tunnel.quic_conn.conn.send_ack_eliciting() {
                        log::warn!("keepalive PING failed: {:?}", e);
                    } else {
                        tunnel.quic_conn.mark_pending_send();
                        last_keepalive = Instant::now();
                    }
                }

                if let Some(timeout) = tunnel.quic_conn.conn.timeout()
                    && timeout.is_zero()
                {
                    tunnel.quic_conn.conn.on_timeout();
                    tunnel.quic_conn.mark_pending_send();
                }

                let mut queued_to_quiche = false;
                let mut send_budget = 0usize;
                loop {
                    if send_budget >= send_budget_limit {
                        break;
                    }

                    let packet = if let Some(packet) = pending_packet.take() {
                        packet
                    } else {
                        match send_rx.try_recv() {
                            Ok(packet) => packet,
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                log::trace!("MASQUE IO send channel disconnected");
                                break;
                            }
                        }
                    };

                    send_budget += 1;
                    match tunnel.send_datagram(&packet) {
                        Ok(crate::net::tunnel::masque::DatagramSendState::Sent)
                        | Ok(crate::net::tunnel::masque::DatagramSendState::Dropped) => {
                            queued_to_quiche = true;
                            queued_packets_worker.fetch_sub(1, Ordering::AcqRel);
                            TunnelManager::return_pooled_buffer(
                                &buffer_pool,
                                packet,
                                pool_max_size,
                            );
                        }
                        Ok(crate::net::tunnel::masque::DatagramSendState::PacketTooBig(icmp)) => {
                            queued_to_quiche = true;
                            queued_packets_worker.fetch_sub(1, Ordering::AcqRel);
                            TunnelManager::return_pooled_buffer(
                                &buffer_pool,
                                packet,
                                pool_max_size,
                            );
                            let mut icmp_packet =
                                TunnelManager::take_pooled_buffer(&buffer_pool, icmp.len());
                            icmp_packet.extend_from_slice(&icmp);
                            if event_tx
                                .send(TransportIoEvent::Incoming(IncomingDatagram {
                                    data: icmp_packet,
                                }))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(crate::net::tunnel::masque::DatagramSendState::Blocked) => {
                            pending_packet = Some(packet);
                            let _ = event_tx.try_send(TransportIoEvent::MasqueBlocked);
                            break;
                        }
                        Err(e) => {
                            log::debug!("MASQUE IO dgram_send failed: {:?}", e);
                            queued_packets_worker.fetch_sub(1, Ordering::AcqRel);
                            TunnelManager::return_pooled_buffer(
                                &buffer_pool,
                                packet,
                                pool_max_size,
                            );
                        }
                    }
                }

                if queued_to_quiche {
                    tunnel.quic_conn.mark_pending_send();
                }

                let should_flush = tunnel.quic_conn.pending_send_packets() > 0
                    || tunnel.quic_conn.take_pending_send();
                if should_flush {
                    match tunnel.quic_conn.send_async().await {
                        Ok(status) => {
                            if status.packets_sent > 0
                                || status.blocked
                                || status.enobufs
                                || status.paced
                            {
                                let _ = event_tx.try_send(TransportIoEvent::QuicFlush(status));
                            }
                        }
                        Err(e) => {
                            log::debug!("MASQUE IO QUIC send failed: {:?}", e);
                        }
                    }
                }

                let recv_deadline = tunnel
                    .quic_conn
                    .conn
                    .timeout()
                    .map(|timeout| TokioInstant::now() + timeout.min(max_poll_interval));
                let send_deadline = tunnel
                    .quic_conn
                    .next_send_at()
                    .map(TokioInstant::from_std)
                    .map(|deadline| deadline.min(TokioInstant::now() + max_poll_interval));
                let keepalive_deadline = if keepalive_interval.is_zero() {
                    None
                } else {
                    Some(TokioInstant::from_std(last_keepalive + keepalive_interval))
                };
                let poll_deadline = [recv_deadline, send_deadline, keepalive_deadline]
                    .into_iter()
                    .flatten()
                    .min();
                let has_poll_timer = poll_deadline.is_some();
                let needs_socket_writable = tunnel.quic_conn.needs_socket_writable();
                let poll_timer = tokio::time::sleep_until(
                    poll_deadline.unwrap_or_else(|| {
                        TokioInstant::now() + Duration::from_secs(365 * 24 * 60 * 60)
                    }),
                );
                tokio::pin!(poll_timer);

                tokio::select! {
                    biased;
                    _ = shutdown_sub.recv() => break,

                    Some(packet) = send_rx.recv(), if pending_packet.is_none() => {
                        pending_packet = Some(packet);
                    }

                    recv_result = tunnel.quic_conn.socket.recv_from(&mut recv_buf[..]) => {
                        match recv_result {
                            Ok((len, from)) => {
                                let recv_info = quiche::RecvInfo {
                                    from,
                                    to: tunnel.quic_conn.local_addr,
                                };
                                match tunnel.quic_conn.conn.recv(&mut recv_buf[..len], recv_info) {
                                    Ok(_) => {
                                        tunnel.poll_h3();
                                        tunnel.quic_conn.mark_pending_send();
                                        loop {
                                            match tunnel.recv_datagram(recv_buf.as_mut()) {
                                                Ok(len) if len > 0 => {
                                                    let mut packet = TunnelManager::take_pooled_buffer(
                                                        &buffer_pool,
                                                        len,
                                                    );
                                                    packet.extend_from_slice(&recv_buf[..len]);
                                                    if event_tx
                                                        .send(TransportIoEvent::Incoming(IncomingDatagram {
                                                            data: packet,
                                                        }))
                                                        .await
                                                        .is_err()
                                                    {
                                                        break;
                                                    }
                                                }
                                                _ => break,
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("MASQUE IO QUIC recv failed: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("MASQUE IO UDP recv failed: {}", e);
                            }
                        }
                    }

                    writable = tunnel.quic_conn.socket.writable(), if needs_socket_writable => {
                        if let Err(e) = writable {
                            log::debug!("MASQUE IO writable wait failed: {}", e);
                        }
                    }

                    _ = &mut poll_timer, if has_poll_timer => {}
                }
            }

            while let Ok(packet) = send_rx.try_recv() {
                queued_packets_worker.fetch_sub(1, Ordering::AcqRel);
                TunnelManager::return_pooled_buffer(&buffer_pool, packet, pool_max_size);
            }
            if let Some(packet) = pending_packet.take() {
                queued_packets_worker.fetch_sub(1, Ordering::AcqRel);
                TunnelManager::return_pooled_buffer(&buffer_pool, packet, pool_max_size);
            }
            if let Ok(mut guard) = quic_stats_worker.lock() {
                *guard = tunnel.quic_conn.perf_stats();
            }
            alive_worker.store(false, Ordering::Release);
        });

        (
            Self {
                socket,
                peer_addr,
                send_tx,
                queued_packets,
                alive,
                quic_stats,
            },
            IncomingTask {
                incoming_rx: event_rx,
                shutdown_tx: Some(shutdown_tx),
                completion_tx: Some(completion_tx),
                completion_rx: Some(completion_rx),
                recv_handle: Some(recv_handle),
            },
        )
    }

    fn try_send_packet(&self, packet: BytesMut) -> Result<(), tokio::sync::mpsc::error::TrySendError<BytesMut>> {
        match self.send_tx.try_send(packet) {
            Ok(()) => {
                self.queued_packets.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(packet)) => {
                Err(tokio::sync::mpsc::error::TrySendError::Full(packet))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(packet)) => {
                Err(tokio::sync::mpsc::error::TrySendError::Closed(packet))
            }
        }
    }

    fn pending_send_packets(&self) -> usize {
        self.queued_packets.load(Ordering::Acquire)
    }

    fn quic_perf_stats(&self) -> Option<QuicPerfStats> {
        self.quic_stats.lock().ok().and_then(|guard| *guard)
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}
