use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::time::MissedTickBehavior;
use tokio_quiche::http3::driver::{ClientH3Event, H3Event, InboundFrame};

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
        _keepalive_secs: u64,
        tunables: &ManagerTunables,
    ) -> (Self, IncomingTask) {
        let socket = tunnel.socket.clone();
        let peer_addr = tunnel.peer_addr;
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
        let send_budget_limit = tunables.masque_stack_drain_budget;
        let stats_interval = tunables.max_poll_interval.max(Duration::from_millis(250));

        let recv_handle = tokio::spawn(async move {
            let _guard = worker_completion_tx;
            let mut tunnel = tunnel;
            let mut h3_events = tunnel.controller.take_event_receiver();
            let mut recv_buf =
                TunnelManager::take_pooled_buffer(&buffer_pool, udp_recv_buffer_size);
            recv_buf.resize(udp_recv_buffer_size, 0);
            let mut stats_tick = tokio::time::interval(stats_interval);
            stats_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

            if let Some(stats) = tunnel.sample_quic_stats().await
                && let Ok(mut guard) = quic_stats_worker.lock()
            {
                *guard = Some(stats);
            }

            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_sub.recv() => break,

                    _ = stats_tick.tick() => {
                        if let Some(stats) = tunnel.sample_quic_stats().await
                            && let Ok(mut guard) = quic_stats_worker.lock()
                        {
                            *guard = Some(stats);
                        }
                    }

                    maybe_event = h3_events.recv() => {
                        match maybe_event {
                            Some(ClientH3Event::Core(H3Event::ConnectionError(error))) => {
                                log::warn!("MASQUE H3 connection error: {:?}", error);
                                break;
                            }
                            Some(ClientH3Event::Core(H3Event::ConnectionShutdown(reason))) => {
                                log::warn!("MASQUE H3 connection shutdown: {:?}", reason);
                                break;
                            }
                            Some(ClientH3Event::Core(H3Event::ResetStream { stream_id }))
                                if stream_id == tunnel.connect_stream_id =>
                            {
                                log::warn!("MASQUE CONNECT-IP stream reset");
                                break;
                            }
                            Some(ClientH3Event::Core(H3Event::StreamClosed { stream_id }))
                                if stream_id == tunnel.connect_stream_id =>
                            {
                                log::warn!("MASQUE CONNECT-IP stream closed");
                                break;
                            }
                            Some(_) => {}
                            None => {
                                log::warn!("MASQUE H3 controller event stream closed");
                                break;
                            }
                        }
                    }

                    maybe_frame = tunnel.flow_recv.recv() => {
                        match maybe_frame {
                            Some(InboundFrame::Datagram(dgram)) => {
                                match tunnel.decode_datagram(dgram, recv_buf.as_mut()) {
                                    Ok(len) if len > 0 => {
                                        let mut packet = TunnelManager::take_pooled_buffer(
                                            &buffer_pool,
                                            len,
                                        );
                                        packet.extend_from_slice(&recv_buf[..len]);
                                        if event_tx
                                            .send(TransportIoEvent::Incoming(IncomingDatagram { data: packet }))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(error) => {
                                        log::debug!("MASQUE datagram decode failed: {:?}", error);
                                    }
                                }
                            }
                            Some(InboundFrame::Body(_, _)) => {}
                            None => {
                                log::warn!("MASQUE datagram flow closed");
                                break;
                            }
                        }
                    }

                    maybe_control = tunnel.connect_recv.recv() => {
                        match maybe_control {
                            Some(InboundFrame::Body(body, fin)) => {
                                if let Err(error) = tunnel.process_control_chunk(body.freeze(), fin) {
                                    log::warn!("MASQUE control stream parse failed: {:?}", error);
                                    break;
                                }
                            }
                            Some(InboundFrame::Datagram(_)) => {
                                log::debug!("ignored unexpected MASQUE datagram on control stream");
                            }
                            None => {
                                log::trace!("MASQUE control stream body closed");
                            }
                        }
                    }

                    maybe_packet = send_rx.recv() => {
                        let Some(first_packet) = maybe_packet else {
                            log::trace!("MASQUE IO send channel disconnected");
                            break;
                        };

                        let mut batch = Vec::with_capacity(send_budget_limit.min(16));
                        batch.push(first_packet);
                        while batch.len() < send_budget_limit {
                            match send_rx.try_recv() {
                                Ok(packet) => batch.push(packet),
                                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                            }
                        }

                        let mut sent_packets = 0usize;
                        let mut sent_bytes = 0usize;
                        let mut blocked = false;

                        for packet in batch {
                            match tunnel.send_datagram(&packet).await {
                                Ok(crate::net::tunnel::masque::DatagramSendState::Sent)
                                | Ok(crate::net::tunnel::masque::DatagramSendState::Dropped) => {
                                    sent_packets += 1;
                                    sent_bytes += packet.len();
                                    queued_packets_worker.fetch_sub(1, Ordering::AcqRel);
                                    TunnelManager::return_pooled_buffer(&buffer_pool, packet, pool_max_size);
                                }
                                Ok(crate::net::tunnel::masque::DatagramSendState::PacketTooBig(icmp)) => {
                                    sent_packets += 1;
                                    sent_bytes += packet.len();
                                    queued_packets_worker.fetch_sub(1, Ordering::AcqRel);
                                    TunnelManager::return_pooled_buffer(&buffer_pool, packet, pool_max_size);
                                    let mut icmp_packet =
                                        TunnelManager::take_pooled_buffer(&buffer_pool, icmp.len());
                                    icmp_packet.extend_from_slice(&icmp);
                                    if event_tx
                                        .send(TransportIoEvent::Incoming(IncomingDatagram { data: icmp_packet }))
                                        .await
                                        .is_err()
                                    {
                                        blocked = true;
                                        break;
                                    }
                                }
                                Ok(crate::net::tunnel::masque::DatagramSendState::Blocked) => {
                                    blocked = true;
                                    let _ = event_tx.try_send(TransportIoEvent::MasqueBlocked);
                                    break;
                                }
                                Err(error) => {
                                    log::debug!("MASQUE datagram send failed: {:?}", error);
                                    queued_packets_worker.fetch_sub(1, Ordering::AcqRel);
                                    TunnelManager::return_pooled_buffer(&buffer_pool, packet, pool_max_size);
                                }
                            }
                        }

                        if sent_packets > 0 || blocked {
                            let _ = event_tx.try_send(TransportIoEvent::QuicFlush(QuicSendStatus {
                                bytes_sent: sent_bytes,
                                packets_sent: sent_packets,
                                blocked,
                                enobufs: false,
                                paced: false,
                            }));
                        }
                    }
                }
            }

            tunnel.close();

            while let Ok(packet) = send_rx.try_recv() {
                queued_packets_worker.fetch_sub(1, Ordering::AcqRel);
                TunnelManager::return_pooled_buffer(&buffer_pool, packet, pool_max_size);
            }
            let final_stats = tunnel.sample_quic_stats().await;
            if let Ok(mut guard) = quic_stats_worker.lock() {
                *guard = final_stats;
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

    fn try_send_packet(
        &self,
        packet: BytesMut,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<BytesMut>> {
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
