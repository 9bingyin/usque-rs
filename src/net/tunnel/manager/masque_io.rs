use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::time::MissedTickBehavior;
use tokio_quiche::http3::driver::{ClientH3Event, H3Event, InboundFrame};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MasqueSendRound {
    sent_packets: usize,
    sent_bytes: usize,
    blocked: bool,
}

struct MasqueIoHandle {
    socket: Arc<tokio::net::UdpSocket>,
    peer_addr: SocketAddr,
    send_tx: mpsc::Sender<Vec<BytesMut>>,
    queued_packets: Arc<AtomicUsize>,
    alive: Arc<AtomicBool>,
    quic_stats: Arc<Mutex<Option<QuicPerfStats>>>,
    send_batch_size: usize,
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
        let (send_tx, mut send_rx) =
            mpsc::channel::<Vec<BytesMut>>(tunables.masque_io_channel_capacity);
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
        let buffer_reuse_max_capacity = tunables.buffer_reuse_max_capacity;
        let udp_recv_buffer_size = tunables.udp_recv_buffer_size;
        let send_budget_limit = tunables.masque_stack_drain_budget;
        let send_batch_size = tunables.masque_send_batch_size.max(1);
        let stats_interval = tunables.max_poll_interval.max(Duration::from_millis(250));

        let recv_handle = tokio::spawn(async move {
            let _guard = worker_completion_tx;
            let mut tunnel = tunnel;
            let mut h3_events = tunnel.controller.take_event_receiver();
            let mut recv_buf =
                TunnelManager::take_pooled_buffer(&buffer_pool, udp_recv_buffer_size);
            recv_buf.resize(udp_recv_buffer_size, 0);
            let mut stats_tick = tokio::time::interval(stats_interval);
            let mut send_backlog = VecDeque::new();
            stats_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

            if let Some(stats) = tunnel.sample_quic_stats().await
                && let Ok(mut guard) = quic_stats_worker.lock()
            {
                *guard = Some(stats);
            }

            loop {
                if !send_backlog.is_empty() {
                    match Self::flush_send_backlog(
                        &mut tunnel,
                        &mut send_backlog,
                        &event_tx,
                        &buffer_pool,
                        pool_max_size,
                        buffer_reuse_max_capacity,
                    )
                    .await
                    {
                        Ok(round) => {
                            Self::emit_send_round_events(&event_tx, round);
                            continue;
                        }
                        Err(()) => break,
                    }
                }

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
                                        let mut packet =
                                            TunnelManager::take_pooled_buffer(&buffer_pool, len);
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

                    maybe_packet_batch = send_rx.recv() => {
                        let Some(batch) = maybe_packet_batch else {
                            log::trace!("MASQUE IO send channel disconnected");
                            break;
                        };
                        Self::absorb_send_batch(&mut send_backlog, batch, &queued_packets_worker);
                        Self::drain_send_channel_round(
                            &mut send_backlog,
                            &mut send_rx,
                            &queued_packets_worker,
                            send_budget_limit,
                        );
                    }
                }
            }

            tunnel.close();

            while let Some(packet) = send_backlog.pop_front() {
                TunnelManager::return_pooled_buffer(
                    &buffer_pool,
                    packet,
                    pool_max_size,
                    buffer_reuse_max_capacity,
                );
            }
            while let Ok(packets) = send_rx.try_recv() {
                queued_packets_worker.fetch_sub(packets.len(), Ordering::AcqRel);
                for packet in packets {
                    TunnelManager::return_pooled_buffer(
                        &buffer_pool,
                        packet,
                        pool_max_size,
                        buffer_reuse_max_capacity,
                    );
                }
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
                send_batch_size,
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

    fn try_send_batch(
        &self,
        packets: Vec<BytesMut>,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<BytesMut>>> {
        let packet_count = packets.len();
        match self.send_tx.try_send(packets) {
            Ok(()) => {
                self.queued_packets.fetch_add(packet_count, Ordering::AcqRel);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(packets)) => {
                Err(tokio::sync::mpsc::error::TrySendError::Full(packets))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(packets)) => {
                Err(tokio::sync::mpsc::error::TrySendError::Closed(packets))
            }
        }
    }

    fn send_batch_size(&self) -> usize {
        self.send_batch_size
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

    fn absorb_send_batch(
        send_backlog: &mut VecDeque<BytesMut>,
        packets: Vec<BytesMut>,
        queued_packets: &AtomicUsize,
    ) {
        queued_packets.fetch_sub(packets.len(), Ordering::AcqRel);
        send_backlog.extend(packets);
    }

    fn drain_send_channel_round(
        send_backlog: &mut VecDeque<BytesMut>,
        send_rx: &mut mpsc::Receiver<Vec<BytesMut>>,
        queued_packets: &AtomicUsize,
        send_budget_limit: usize,
    ) {
        while send_backlog.len() < send_budget_limit {
            match send_rx.try_recv() {
                Ok(packets) => {
                    Self::absorb_send_batch(send_backlog, packets, queued_packets);
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
    }

    async fn flush_send_backlog(
        tunnel: &mut MasqueTunnel,
        send_backlog: &mut VecDeque<BytesMut>,
        event_tx: &mpsc::Sender<TransportIoEvent>,
        buffer_pool: &BufferPool,
        pool_max_size: usize,
        buffer_reuse_max_capacity: usize,
    ) -> Result<MasqueSendRound, ()> {
        let mut round = MasqueSendRound::default();
        let mut waited_on_full = false;

        while let Some(packet) = send_backlog.pop_front() {
            match tunnel.send_datagram(&packet, !waited_on_full).await {
                Ok(crate::net::tunnel::masque::DatagramSendState::Sent { waited }) => {
                    waited_on_full |= waited;
                    round.sent_packets += 1;
                    round.sent_bytes += packet.len();
                    TunnelManager::return_pooled_buffer(
                        buffer_pool,
                        packet,
                        pool_max_size,
                        buffer_reuse_max_capacity,
                    );
                }
                Ok(crate::net::tunnel::masque::DatagramSendState::Dropped) => {
                    round.sent_packets += 1;
                    round.sent_bytes += packet.len();
                    TunnelManager::return_pooled_buffer(
                        buffer_pool,
                        packet,
                        pool_max_size,
                        buffer_reuse_max_capacity,
                    );
                }
                Ok(crate::net::tunnel::masque::DatagramSendState::PacketTooBig(icmp)) => {
                    round.sent_packets += 1;
                    round.sent_bytes += packet.len();
                    TunnelManager::return_pooled_buffer(
                        buffer_pool,
                        packet,
                        pool_max_size,
                        buffer_reuse_max_capacity,
                    );
                    let mut icmp_packet = TunnelManager::take_pooled_buffer(buffer_pool, icmp.len());
                    icmp_packet.extend_from_slice(&icmp);
                    if event_tx
                        .send(TransportIoEvent::Incoming(IncomingDatagram { data: icmp_packet }))
                        .await
                        .is_err()
                    {
                        return Err(());
                    }
                }
                Ok(crate::net::tunnel::masque::DatagramSendState::Blocked) => {
                    round.blocked = true;
                    send_backlog.push_front(packet);
                    break;
                }
                Err(error) => {
                    log::debug!("MASQUE datagram send failed: {:?}", error);
                    TunnelManager::return_pooled_buffer(
                        buffer_pool,
                        packet,
                        pool_max_size,
                        buffer_reuse_max_capacity,
                    );
                }
            }
        }

        Ok(round)
    }

    fn emit_send_round_events(event_tx: &mpsc::Sender<TransportIoEvent>, round: MasqueSendRound) {
        if round.blocked {
            let _ = event_tx.try_send(TransportIoEvent::MasqueBlocked);
        }
        if round.sent_packets > 0 || round.blocked {
            let _ = event_tx.try_send(TransportIoEvent::QuicFlush(QuicSendStatus {
                bytes_sent: round.sent_bytes,
                packets_sent: round.sent_packets,
                blocked: round.blocked,
                enobufs: false,
                paced: false,
            }));
        }
    }
}

#[cfg(test)]
mod masque_io_tests {
    use super::*;

    #[test]
    fn drain_send_channel_round_merges_multiple_batches() {
        let (tx, mut rx) = mpsc::channel(4);
        let queued_packets = AtomicUsize::new(5);
        let mut backlog = VecDeque::new();

        tx.try_send(vec![BytesMut::from(&b"c"[..]), BytesMut::from(&b"d"[..])])
            .unwrap();
        tx.try_send(vec![BytesMut::from(&b"e"[..])]).unwrap();

        MasqueIoHandle::absorb_send_batch(
            &mut backlog,
            vec![BytesMut::from(&b"a"[..]), BytesMut::from(&b"b"[..])],
            &queued_packets,
        );
        MasqueIoHandle::drain_send_channel_round(&mut backlog, &mut rx, &queued_packets, 8);

        assert_eq!(queued_packets.load(Ordering::Acquire), 0);
        assert_eq!(
            backlog
                .into_iter()
                .map(|buf| buf.freeze())
                .collect::<Vec<_>>(),
            vec![
                Bytes::from_static(b"a"),
                Bytes::from_static(b"b"),
                Bytes::from_static(b"c"),
                Bytes::from_static(b"d"),
                Bytes::from_static(b"e"),
            ]
        );
    }

    #[test]
    fn emit_send_round_events_reports_once_per_round() {
        let (event_tx, mut event_rx) = mpsc::channel(4);
        MasqueIoHandle::emit_send_round_events(
            &event_tx,
            MasqueSendRound {
                sent_packets: 3,
                sent_bytes: 1200,
                blocked: true,
            },
        );

        assert!(matches!(
            event_rx.try_recv(),
            Ok(TransportIoEvent::MasqueBlocked)
        ));
        assert!(matches!(
            event_rx.try_recv(),
            Ok(TransportIoEvent::QuicFlush(QuicSendStatus {
                packets_sent: 3,
                bytes_sent: 1200,
                blocked: true,
                ..
            }))
        ));
        assert!(matches!(
            event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }
}
