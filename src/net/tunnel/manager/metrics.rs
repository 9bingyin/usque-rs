#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ManagerLoadSnapshot {
    active_tcp_sockets: usize,
    pending_connects: usize,
    pending_to_client_bytes: usize,
    transport_pending_send_packets: usize,
}

struct ManagerRuntimeStats {
    max_tcp_sockets_per_worker: usize,
    active_tcp_sockets: std::sync::atomic::AtomicUsize,
    pending_connects: std::sync::atomic::AtomicUsize,
    pending_to_client_bytes: std::sync::atomic::AtomicUsize,
    transport_pending_send_packets: std::sync::atomic::AtomicUsize,
}

impl ManagerRuntimeStats {
    fn new(max_tcp_sockets_per_worker: usize) -> Self {
        Self {
            max_tcp_sockets_per_worker,
            active_tcp_sockets: std::sync::atomic::AtomicUsize::new(0),
            pending_connects: std::sync::atomic::AtomicUsize::new(0),
            pending_to_client_bytes: std::sync::atomic::AtomicUsize::new(0),
            transport_pending_send_packets: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn snapshot(&self) -> ManagerLoadSnapshot {
        ManagerLoadSnapshot {
            active_tcp_sockets: self
                .active_tcp_sockets
                .load(std::sync::atomic::Ordering::Acquire),
            pending_connects: self
                .pending_connects
                .load(std::sync::atomic::Ordering::Acquire),
            pending_to_client_bytes: self
                .pending_to_client_bytes
                .load(std::sync::atomic::Ordering::Acquire),
            transport_pending_send_packets: self
                .transport_pending_send_packets
                .load(std::sync::atomic::Ordering::Acquire),
        }
    }

    fn try_reserve_tcp_slot(&self) -> bool {
        loop {
            let active = self
                .active_tcp_sockets
                .load(std::sync::atomic::Ordering::Acquire);
            let pending = self
                .pending_connects
                .load(std::sync::atomic::Ordering::Acquire);
            if active.saturating_add(pending) >= self.max_tcp_sockets_per_worker {
                return false;
            }
            if self
                .pending_connects
                .compare_exchange(
                    pending,
                    pending + 1,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    fn finish_reserved_tcp_connect(&self) {
        loop {
            let pending = self
                .pending_connects
                .load(std::sync::atomic::Ordering::Acquire);
            if pending == 0 {
                return;
            }
            if self
                .pending_connects
                .compare_exchange(
                    pending,
                    pending - 1,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_ok()
            {
                return;
            }
        }
    }

    fn update(&self, active_tcp_sockets: usize, pending_to_client_bytes: usize, transport_pending_send_packets: usize) {
        self.active_tcp_sockets
            .store(active_tcp_sockets, std::sync::atomic::Ordering::Release);
        self.pending_to_client_bytes
            .store(pending_to_client_bytes, std::sync::atomic::Ordering::Release);
        self.transport_pending_send_packets
            .store(
                transport_pending_send_packets,
                std::sync::atomic::Ordering::Release,
            );
    }

    fn reset(&self) {
        self.update(0, 0, 0);
        self.pending_connects
            .store(0, std::sync::atomic::Ordering::Release);
    }
}

struct PerfSnapshot {
    sockets: usize,
    udp_sessions: usize,
    dns_groups: usize,
    pending_from_client_bytes: usize,
    pending_to_client_bytes: usize,
    rx_queue_len: usize,
    tx_queue_len: usize,
    rx_drops: u64,
    tx_drops: u64,
    cmd_queue_len: usize,
    udp_queue_len: usize,
    incoming_queue_len: usize,
    ready_tcp_queue_len: usize,
    transport_pending_send_packets: usize,
    quic_stats: Option<QuicPerfStats>,
}

struct PerfCounters {
    enabled: bool,
    interval: Duration,
    last_report: Instant,
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    poll_count: u64,
    loop_iterations: u64,
    scheduler_yields: u64,
    masque_blocked_events: u64,
    masque_send_batches: u64,
    masque_send_packets: u64,
    quic_socket_blocked: u64,
    quic_send_enobufs: u64,
    quic_pacing_events: u64,
    wg_flushes: u64,
    socket_event_batches: u64,
    socket_events: u64,
    full_tcp_sweeps: u64,
    targeted_tcp_sweeps: u64,
}

impl PerfCounters {
    fn new(enabled: bool, interval_secs: u64) -> Self {
        let interval = Duration::from_secs(interval_secs.max(1));
        Self {
            enabled,
            interval,
            last_report: Instant::now(),
            rx_packets: 0,
            rx_bytes: 0,
            tx_packets: 0,
            tx_bytes: 0,
            poll_count: 0,
            loop_iterations: 0,
            scheduler_yields: 0,
            masque_blocked_events: 0,
            masque_send_batches: 0,
            masque_send_packets: 0,
            quic_socket_blocked: 0,
            quic_send_enobufs: 0,
            quic_pacing_events: 0,
            wg_flushes: 0,
            socket_event_batches: 0,
            socket_events: 0,
            full_tcp_sweeps: 0,
            targeted_tcp_sweeps: 0,
        }
    }

    fn due(&self) -> bool {
        self.enabled && self.last_report.elapsed() >= self.interval
    }

    fn inc_loop(&mut self) {
        if self.enabled {
            self.loop_iterations += 1;
        }
    }

    fn inc_poll(&mut self) {
        if self.enabled {
            self.poll_count += 1;
        }
    }

    fn inc_rx(&mut self, bytes: usize) {
        if self.enabled {
            self.rx_packets += 1;
            self.rx_bytes += bytes as u64;
        }
    }

    fn inc_tx(&mut self, bytes: usize) {
        if self.enabled {
            self.tx_packets += 1;
            self.tx_bytes += bytes as u64;
        }
    }

    fn inc_yield(&mut self) {
        if self.enabled {
            self.scheduler_yields += 1;
        }
    }

    fn inc_masque_blocked(&mut self) {
        if self.enabled {
            self.masque_blocked_events += 1;
        }
    }

    fn record_masque_send_batch(&mut self, status: QuicSendStatus) {
        if !self.enabled {
            return;
        }
        if status.packets_sent > 0 {
            self.masque_send_batches += 1;
            self.masque_send_packets += status.packets_sent as u64;
        }
        if status.blocked {
            self.quic_socket_blocked += 1;
        }
        if status.enobufs {
            self.quic_send_enobufs += 1;
        }
        if status.paced {
            self.quic_pacing_events += 1;
        }
    }

    fn inc_wg_flush(&mut self) {
        if self.enabled {
            self.wg_flushes += 1;
        }
    }

    fn inc_socket_event_batch(&mut self, count: usize) {
        if self.enabled && count > 0 {
            self.socket_event_batches += 1;
            self.socket_events += count as u64;
        }
    }

    fn inc_tcp_sweep(&mut self, full_sweep: bool) {
        if self.enabled {
            if full_sweep {
                self.full_tcp_sweeps += 1;
            } else {
                self.targeted_tcp_sweeps += 1;
            }
        }
    }

    fn report(&mut self, snapshot: PerfSnapshot) {
        if !self.enabled {
            return;
        }
        let elapsed = self.last_report.elapsed();
        if elapsed < self.interval {
            return;
        }
        let secs = elapsed.as_secs_f64();
        log::info!(
            "PERF: rx={:.0}pps ({:.1}Mbps) tx={:.0}pps ({:.1}Mbps) polls={:.0}/s loops={:.0}/s yields={:.0}/s masque_blocked={:.0}/s masque_send_batches={:.0}/s masque_send_pkts={:.0}/s quic_socket_blocked={:.0}/s quic_enobufs={:.0}/s quic_pacing={:.0}/s quic_rtt={}ms quic_cwnd={} quic_lost={} quic_pto={} quic_delivery_est={:.1}Mbps quic_dgram_rx_total={} quic_dgram_tx_total={} wg_flushes={:.0}/s socket_event_batches={:.0}/s socket_events={:.0}/s tcp_sweeps_full={:.0}/s tcp_sweeps_targeted={:.0}/s sockets={} udp_sessions={} dns_groups={} pending_from={}B pending_to={}B rx_q={} tx_q={} drops_rx={} drops_tx={} cmd_q={} udp_q={} in_q={} ready_tcp_q={} transport_pending={}",
            self.rx_packets as f64 / secs,
            self.rx_bytes as f64 * 8.0 / secs / 1_000_000.0,
            self.tx_packets as f64 / secs,
            self.tx_bytes as f64 * 8.0 / secs / 1_000_000.0,
            self.poll_count as f64 / secs,
            self.loop_iterations as f64 / secs,
            self.scheduler_yields as f64 / secs,
            self.masque_blocked_events as f64 / secs,
            self.masque_send_batches as f64 / secs,
            self.masque_send_packets as f64 / secs,
            self.quic_socket_blocked as f64 / secs,
            self.quic_send_enobufs as f64 / secs,
            self.quic_pacing_events as f64 / secs,
            snapshot.quic_stats.map_or(0, |stats| stats.rtt_ms),
            snapshot.quic_stats.map_or(0, |stats| stats.cwnd),
            snapshot.quic_stats.map_or(0, |stats| stats.lost),
            snapshot.quic_stats.map_or(0, |stats| stats.total_pto_count),
            snapshot.quic_stats.map_or(0.0, |stats| {
                stats.delivery_rate_bps as f64 * 8.0 / 1_000_000.0
            }),
            snapshot.quic_stats.map_or(0, |stats| stats.dgram_recv),
            snapshot.quic_stats.map_or(0, |stats| stats.dgram_sent),
            self.wg_flushes as f64 / secs,
            self.socket_event_batches as f64 / secs,
            self.socket_events as f64 / secs,
            self.full_tcp_sweeps as f64 / secs,
            self.targeted_tcp_sweeps as f64 / secs,
            snapshot.sockets,
            snapshot.udp_sessions,
            snapshot.dns_groups,
            snapshot.pending_from_client_bytes,
            snapshot.pending_to_client_bytes,
            snapshot.rx_queue_len,
            snapshot.tx_queue_len,
            snapshot.rx_drops,
            snapshot.tx_drops,
            snapshot.cmd_queue_len,
            snapshot.udp_queue_len,
            snapshot.incoming_queue_len,
            snapshot.ready_tcp_queue_len,
            snapshot.transport_pending_send_packets,
        );
        self.last_report = Instant::now();
        self.rx_packets = 0;
        self.rx_bytes = 0;
        self.tx_packets = 0;
        self.tx_bytes = 0;
        self.poll_count = 0;
        self.loop_iterations = 0;
        self.scheduler_yields = 0;
        self.masque_blocked_events = 0;
        self.masque_send_batches = 0;
        self.masque_send_packets = 0;
        self.quic_socket_blocked = 0;
        self.quic_send_enobufs = 0;
        self.quic_pacing_events = 0;
        self.wg_flushes = 0;
        self.socket_event_batches = 0;
        self.socket_events = 0;
        self.full_tcp_sweeps = 0;
        self.targeted_tcp_sweeps = 0;
    }
}
