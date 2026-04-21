use bytes::BytesMut;
use smoltcp::iface::{
    Config, Interface, PollIngressSingleResult, PollResult, SocketHandle, SocketSet,
};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket, UdpMetadata};
use smoltcp::socket::{
    Socket,
    tcp::{CongestionControl, Socket as TcpSocket, SocketBuffer, State as TcpState},
};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};
use thiserror::Error;

const DROP_LOG_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) type BufferPool = Arc<Mutex<Vec<BytesMut>>>;

#[derive(Clone, Debug)]
pub struct StackTunables {
    pub device_queue_capacity: usize,
    pub buffer_pool_size: usize,
    pub tcp_ack_delay: Option<Duration>,
    pub tcp_keepalive: Option<Duration>,
    pub tcp_timeout: Option<Duration>,
    pub udp_socket_metadata_capacity: usize,
    pub udp_socket_buffer_size: usize,
}

impl Default for StackTunables {
    fn default() -> Self {
        Self {
            device_queue_capacity: 4096,
            buffer_pool_size: 256,
            tcp_ack_delay: Some(Duration::from_millis(10)),
            tcp_keepalive: Some(Duration::from_secs(28)),
            tcp_timeout: Some(Duration::from_secs(7200)),
            udp_socket_metadata_capacity: 16,
            udp_socket_buffer_size: 64 * 1024,
        }
    }
}

impl StackTunables {
    pub fn from_env() -> Self {
        fn env_usize(name: &str, default: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        fn env_optional_duration_ms(name: &str, default: Option<Duration>) -> Option<Duration> {
            match std::env::var(name) {
                Ok(v) => match v.parse::<u64>() {
                    Ok(0) => None,
                    Ok(ms) => Some(Duration::from_millis(ms)),
                    Err(_) => default,
                },
                Err(_) => default,
            }
        }

        fn env_optional_duration_secs(name: &str, default: Option<Duration>) -> Option<Duration> {
            match std::env::var(name) {
                Ok(v) => match v.parse::<u64>() {
                    Ok(0) => None,
                    Ok(secs) => Some(Duration::from_secs(secs)),
                    Err(_) => default,
                },
                Err(_) => default,
            }
        }

        let defaults = Self::default();
        Self {
            device_queue_capacity: env_usize(
                "USQUE_STACK_QUEUE_CAPACITY",
                defaults.device_queue_capacity,
            ),
            buffer_pool_size: env_usize("USQUE_STACK_BUFFER_POOL_SIZE", defaults.buffer_pool_size),
            tcp_ack_delay: env_optional_duration_ms(
                "USQUE_TCP_ACK_DELAY_MS",
                defaults.tcp_ack_delay,
            ),
            tcp_keepalive: env_optional_duration_secs(
                "USQUE_TCP_KEEPALIVE_SECS",
                defaults.tcp_keepalive,
            ),
            tcp_timeout: env_optional_duration_secs("USQUE_TCP_TIMEOUT_SECS", defaults.tcp_timeout),
            udp_socket_metadata_capacity: env_usize(
                "USQUE_UDP_SOCKET_METADATA_CAPACITY",
                defaults.udp_socket_metadata_capacity,
            ),
            udp_socket_buffer_size: env_usize(
                "USQUE_UDP_SOCKET_BUFFER_SIZE",
                defaults.udp_socket_buffer_size,
            ),
        }
    }
}

struct DropLogger {
    label: &'static str,
    log_count: u64,  // for periodic warning logs
    perf_count: u64, // for PERF snapshot (reset every report)
    last_log: StdInstant,
}

impl DropLogger {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            log_count: 0,
            perf_count: 0,
            last_log: StdInstant::now(),
        }
    }

    fn log_drop(&mut self) {
        self.log_count += 1;
        self.perf_count += 1;
        let now = StdInstant::now();
        if now.duration_since(self.last_log) >= DROP_LOG_INTERVAL {
            log::warn!(
                "{} queue full, dropped {} packets",
                self.label,
                self.log_count
            );
            self.log_count = 0;
            self.last_log = now;
        }
    }

    fn take_perf_count(&mut self) -> u64 {
        let count = self.perf_count;
        self.perf_count = 0;
        count
    }
}

pub struct VirtualDevice {
    rx_queue: VecDeque<BytesMut>,
    tx_queue: VecDeque<BytesMut>,
    buffer_pool: BufferPool,
    mtu: usize,
    queue_capacity: usize,
    pool_capacity: usize,
    rx_drop_logger: DropLogger,
    tx_drop_logger: DropLogger,
}

impl VirtualDevice {
    pub fn new(mtu: usize, buffer_pool: BufferPool, tunables: &StackTunables) -> Self {
        Self {
            rx_queue: VecDeque::with_capacity(1024),
            tx_queue: VecDeque::with_capacity(1024),
            buffer_pool,
            mtu,
            queue_capacity: tunables.device_queue_capacity,
            pool_capacity: tunables.buffer_pool_size,
            rx_drop_logger: DropLogger::new("RX"),
            tx_drop_logger: DropLogger::new("TX"),
        }
    }

    fn get_buffer(&self, capacity: usize) -> BytesMut {
        let mut pool = match self.buffer_pool.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(mut buf) = pool.pop() {
            buf.clear();
            if buf.capacity() < capacity {
                buf.reserve(capacity - buf.capacity());
            }
            buf
        } else {
            BytesMut::with_capacity(capacity)
        }
    }

    fn return_buffer(&self, mut buf: BytesMut) {
        buf.clear();
        let mut pool = match self.buffer_pool.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if pool.len() < self.pool_capacity {
            pool.push(buf);
        }
    }

    pub fn inject_packet(&mut self, data: &[u8]) {
        while self.rx_queue.len() >= self.queue_capacity {
            if let Some(old) = self.rx_queue.pop_front() {
                self.return_buffer(old);
            }
            self.rx_drop_logger.log_drop();
        }
        let mut buf = self.get_buffer(self.mtu);
        buf.extend_from_slice(data);
        self.rx_queue.push_back(buf);
    }

    pub fn inject_packet_owned(&mut self, data: BytesMut) {
        while self.rx_queue.len() >= self.queue_capacity {
            if let Some(old) = self.rx_queue.pop_front() {
                self.return_buffer(old);
            }
            self.rx_drop_logger.log_drop();
        }
        self.rx_queue.push_back(data);
    }

    pub fn take_packet(&mut self) -> Option<BytesMut> {
        self.tx_queue.pop_front()
    }

    pub fn requeue_packet_front(&mut self, packet: BytesMut) {
        self.tx_queue.push_front(packet);
    }

    pub fn recycle_tx_buffer(&mut self, buf: BytesMut) {
        self.return_buffer(buf);
    }

    pub fn queue_lengths(&self) -> (usize, usize) {
        (self.rx_queue.len(), self.tx_queue.len())
    }

    pub fn take_drop_counts(&mut self) -> (u64, u64) {
        (
            self.rx_drop_logger.take_perf_count(),
            self.tx_drop_logger.take_perf_count(),
        )
    }

    pub fn buffer_pool(&self) -> BufferPool {
        self.buffer_pool.clone()
    }

    fn has_tx_capacity(&self) -> bool {
        self.tx_queue.len() < self.queue_capacity
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtualRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if !self.has_tx_capacity() {
            return None;
        }
        let packet = self.rx_queue.pop_front()?;
        let buffer = self.get_buffer(self.mtu);
        Some((
            VirtualRxToken {
                data: packet,
                buffer_pool: self.buffer_pool.clone(),
                pool_capacity: self.pool_capacity,
            },
            VirtualTxToken {
                queue: &mut self.tx_queue,
                buffer,
                buffer_pool: self.buffer_pool.clone(),
                queue_capacity: self.queue_capacity,
                pool_capacity: self.pool_capacity,
                drop_logger: &mut self.tx_drop_logger,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if !self.has_tx_capacity() {
            return None;
        }
        let buffer = self.get_buffer(self.mtu);
        Some(VirtualTxToken {
            queue: &mut self.tx_queue,
            buffer,
            buffer_pool: self.buffer_pool.clone(),
            queue_capacity: self.queue_capacity,
            pool_capacity: self.pool_capacity,
            drop_logger: &mut self.tx_drop_logger,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // RX packets are already integrity-protected by QUIC, skip RX checksum verification.
        // Only compute checksums on TX.
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps.checksum.icmpv6 = Checksum::Tx;
        caps
    }
}

pub struct VirtualRxToken {
    data: BytesMut,
    buffer_pool: BufferPool,
    pool_capacity: usize,
}

impl Drop for VirtualRxToken {
    fn drop(&mut self) {
        // Return the buffer to the pool for reuse; content is cleared on return.
        let mut buf = std::mem::take(&mut self.data);
        buf.clear();
        let mut pool = match self.buffer_pool.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if pool.len() < self.pool_capacity {
            pool.push(buf);
        }
    }
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.data)
    }
}

pub struct VirtualTxToken<'a> {
    queue: &'a mut VecDeque<BytesMut>,
    buffer: BytesMut,
    buffer_pool: BufferPool,
    queue_capacity: usize,
    pool_capacity: usize,
    drop_logger: &'a mut DropLogger,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(mut self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.buffer.clear();
        self.buffer.resize(len, 0);
        let result = f(&mut self.buffer);

        if self.queue.len() >= self.queue_capacity {
            self.drop_logger.log_drop();
            let mut dropped = std::mem::take(&mut self.buffer);
            dropped.clear();
            let mut pool = match self.buffer_pool.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if pool.len() < self.pool_capacity {
                pool.push(dropped);
            }
            return result;
        }

        self.queue.push_back(self.buffer);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::Device;

    fn test_buffer_pool() -> BufferPool {
        Arc::new(Mutex::new(Vec::new()))
    }

    #[test]
    fn receive_preserves_rx_packet_when_tx_queue_is_full() {
        let tunables = StackTunables::default();
        let mut device = VirtualDevice::new(1500, test_buffer_pool(), &tunables);
        device.inject_packet(&[1, 2, 3, 4]);

        for _ in 0..tunables.device_queue_capacity {
            device.tx_queue.push_back(BytesMut::from(&b"x"[..]));
        }

        let received = device.receive(SmolInstant::now());
        assert!(
            received.is_none(),
            "receive must defer when tx queue is full"
        );
        assert_eq!(device.rx_queue.len(), 1, "rx packet must stay queued");

        device.tx_queue.pop_front();

        let received = device.receive(SmolInstant::now());
        assert!(
            received.is_some(),
            "receive must resume after tx queue drains"
        );
        assert!(
            device.rx_queue.is_empty(),
            "rx packet should be consumed once accepted"
        );
    }

    #[test]
    fn transmit_returns_none_when_tx_queue_is_full() {
        let tunables = StackTunables::default();
        let mut device = VirtualDevice::new(1500, test_buffer_pool(), &tunables);
        for _ in 0..tunables.device_queue_capacity {
            device.tx_queue.push_back(BytesMut::from(&b"x"[..]));
        }

        assert!(
            device.transmit(SmolInstant::now()).is_none(),
            "transmit must apply backpressure instead of dropping packets"
        );
    }

    #[test]
    fn requeue_packet_front_restores_packet_order() {
        let tunables = StackTunables::default();
        let mut device = VirtualDevice::new(1500, test_buffer_pool(), &tunables);
        device.tx_queue.push_back(BytesMut::from(&b"b"[..]));
        device.requeue_packet_front(BytesMut::from(&b"a"[..]));

        let first = device.take_packet().expect("first packet");
        let second = device.take_packet().expect("second packet");

        assert_eq!(&first[..], b"a");
        assert_eq!(&second[..], b"b");
    }
}

#[derive(Error, Debug)]
pub enum StackError {
    #[error("socket error: {0}")]
    SocketError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("smoltcp poll panicked")]
    PollPanic,
}

pub struct DeviceStats {
    pub rx_queue_len: usize,
    pub tx_queue_len: usize,
    pub rx_drops: u64,
    pub tx_drops: u64,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct StackPollOutcome {
    pub ingress_processed: usize,
    pub more_ingress: bool,
    pub socket_state_changed: bool,
}

pub struct NetworkStack {
    device: VirtualDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    valid_handles: HashSet<SocketHandle>,
    local_ipv4: Option<Ipv4Address>,
    local_ipv6: Option<Ipv6Address>,
    buffer_pool: BufferPool,
    tunables: StackTunables,
}

impl NetworkStack {
    fn socket_snapshot(&self) -> String {
        const MAX_TCP_DETAILS: usize = 16;
        let mut total = 0usize;
        let mut tcp_count = 0usize;
        let mut udp_count = 0usize;
        let mut tcp_details = Vec::new();

        for (handle, socket) in self.sockets.iter() {
            total += 1;
            match socket {
                Socket::Tcp(sock) => {
                    tcp_count += 1;
                    if tcp_details.len() < MAX_TCP_DETAILS {
                        tcp_details.push(format!(
                            "{} state={:?} local={:?} remote={:?} tx={} rx={}",
                            handle,
                            sock.state(),
                            sock.local_endpoint(),
                            sock.remote_endpoint(),
                            sock.send_queue(),
                            sock.recv_queue()
                        ));
                    }
                }
                Socket::Udp(_) => {
                    udp_count += 1;
                }
                _ => {}
            }
        }

        let mut snapshot = format!(
            "local_ipv4={:?} local_ipv6={:?} sockets: total={}, tcp={}, udp={}",
            self.local_ipv4, self.local_ipv6, total, tcp_count, udp_count
        );

        if !tcp_details.is_empty() {
            snapshot.push_str("; tcp=[");
            snapshot.push_str(&tcp_details.join(", "));
            snapshot.push(']');
            if tcp_count > MAX_TCP_DETAILS {
                snapshot.push_str(" (truncated)");
            }
        }

        snapshot
    }

    pub fn new(
        ipv4: Option<&str>,
        ipv6: Option<&str>,
        mtu: usize,
        tunables: StackTunables,
    ) -> Self {
        let buffer_pool: BufferPool =
            Arc::new(Mutex::new(Vec::with_capacity(tunables.buffer_pool_size)));
        {
            let mut pool = match buffer_pool.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            for _ in 0..tunables.buffer_pool_size {
                pool.push(BytesMut::with_capacity(mtu));
            }
        }

        let mut device = VirtualDevice::new(mtu, buffer_pool.clone(), &tunables);

        let mut local_ipv4 = match ipv4.filter(|s| !s.trim().is_empty()) {
            Some(s) => match s.parse() {
                Ok(addr) => Some(addr),
                Err(e) => {
                    log::warn!("Invalid IPv4 address '{}': {}", s, e);
                    Some(Ipv4Address::new(10, 0, 0, 1))
                }
            },
            None => None,
        };
        let local_ipv6: Option<Ipv6Address> =
            ipv6.filter(|s| !s.trim().is_empty())
                .and_then(|s| match s.parse() {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        log::warn!("Invalid IPv6 address '{}': {}", s, e);
                        None
                    }
                });

        if local_ipv4.is_none() && local_ipv6.is_none() {
            log::warn!("No valid IP addresses configured, using fallback IPv4 10.0.0.1");
            local_ipv4 = Some(Ipv4Address::new(10, 0, 0, 1));
        }

        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        iface.update_ip_addrs(|addrs| {
            if let Some(v4) = local_ipv4 {
                // Use /0 prefix to match all addresses (virtual interface acts as gateway)
                addrs.push(IpCidr::new(IpAddress::Ipv4(v4), 0)).ok();
            }
            if let Some(v6) = local_ipv6 {
                addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 0)).ok();
            }
        });

        if let Some(v4) = local_ipv4 {
            iface
                .routes_mut()
                .add_default_ipv4_route(v4)
                .expect("IPv4 default route");
        }
        if let Some(v6) = local_ipv6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(v6)
                .expect("IPv6 default route");
        }
        iface.set_any_ip(true);

        let sockets = SocketSet::new(vec![]);

        Self {
            device,
            iface,
            sockets,
            valid_handles: HashSet::new(),
            local_ipv4,
            local_ipv6,
            buffer_pool,
            tunables,
        }
    }

    pub fn poll(&mut self) -> Result<(), StackError> {
        let timestamp = SmolInstant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.iface
                .poll(timestamp, &mut self.device, &mut self.sockets);
        }));
        if result.is_err() {
            log::error!(
                "smoltcp poll panicked, snapshot: {}",
                self.socket_snapshot()
            );
            return Err(StackError::PollPanic);
        }
        Ok(())
    }

    pub fn poll_bounded(&mut self, ingress_budget: usize) -> Result<StackPollOutcome, StackError> {
        let timestamp = SmolInstant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut outcome = StackPollOutcome::default();
            self.iface.poll_maintenance(timestamp);

            let ingress_budget = ingress_budget.max(1);
            for _ in 0..ingress_budget {
                match self
                    .iface
                    .poll_ingress_single(timestamp, &mut self.device, &mut self.sockets)
                {
                    PollIngressSingleResult::None => break,
                    PollIngressSingleResult::PacketProcessed => {
                        outcome.ingress_processed += 1;
                    }
                    PollIngressSingleResult::SocketStateChanged => {
                        outcome.ingress_processed += 1;
                        outcome.socket_state_changed = true;
                    }
                }
            }

            if outcome.ingress_processed == ingress_budget {
                outcome.more_ingress = self.device.queue_lengths().0 > 0;
            }

            if matches!(
                self.iface
                    .poll_egress(timestamp, &mut self.device, &mut self.sockets),
                PollResult::SocketStateChanged
            ) {
                outcome.socket_state_changed = true;
            }

            outcome
        }));
        match result {
            Ok(outcome) => Ok(outcome),
            Err(_) => {
                log::error!(
                    "smoltcp poll_bounded panicked, snapshot: {}",
                    self.socket_snapshot()
                );
                Err(StackError::PollPanic)
            }
        }
    }

    pub fn poll_egress(&mut self) -> Result<bool, StackError> {
        let timestamp = SmolInstant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            matches!(
                self.iface
                    .poll_egress(timestamp, &mut self.device, &mut self.sockets),
                PollResult::SocketStateChanged
            )
        }));
        match result {
            Ok(state_changed) => Ok(state_changed),
            Err(_) => {
                log::error!(
                    "smoltcp poll_egress panicked, snapshot: {}",
                    self.socket_snapshot()
                );
                Err(StackError::PollPanic)
            }
        }
    }

    /// Returns the optimal delay before the next poll, based on smoltcp's internal timers
    /// (TCP retransmission, delayed ACK, etc.). Returns None if immediate polling is needed.
    pub fn poll_delay(&mut self) -> Option<Duration> {
        let timestamp = SmolInstant::now();
        self.iface
            .poll_delay(timestamp, &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
    }

    fn get_tcp_socket_mut(&mut self, handle: SocketHandle) -> Option<&mut TcpSocket<'static>> {
        if self.valid_handles.contains(&handle) {
            Some(self.sockets.get_mut::<TcpSocket>(handle))
        } else {
            None
        }
    }

    fn get_udp_socket_mut(&mut self, handle: SocketHandle) -> Option<&mut UdpSocket<'static>> {
        if self.valid_handles.contains(&handle) {
            Some(self.sockets.get_mut::<UdpSocket>(handle))
        } else {
            None
        }
    }

    pub fn create_tcp_socket_with_buffer(&mut self, buffer_size: usize) -> SocketHandle {
        let rx_buffer = SocketBuffer::new(vec![0; buffer_size]);
        let tx_buffer = SocketBuffer::new(vec![0; buffer_size]);
        let mut socket = TcpSocket::new(rx_buffer, tx_buffer);
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(self.tunables.tcp_ack_delay.map(Into::into));
        socket.set_keep_alive(self.tunables.tcp_keepalive.map(Into::into));
        socket.set_congestion_control(CongestionControl::Cubic);
        socket.set_timeout(self.tunables.tcp_timeout.map(Into::into));
        let handle = self.sockets.add(socket);
        self.valid_handles.insert(handle);
        handle
    }

    pub fn connect_tcp(
        &mut self,
        handle: SocketHandle,
        remote_ip: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<(), StackError> {
        if !self.valid_handles.contains(&handle) {
            return Err(StackError::SocketError("invalid socket handle".into()));
        }
        let cx = self.iface.context();
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket
            .connect(cx, (remote_ip, remote_port), local_port)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) -> Result<usize, StackError> {
        let socket = self
            .get_tcp_socket_mut(handle)
            .ok_or_else(|| StackError::SocketError("invalid socket handle".into()))?;
        socket
            .send_slice(data)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn tcp_recv(&mut self, handle: SocketHandle, buf: &mut [u8]) -> Result<usize, StackError> {
        let socket = self
            .get_tcp_socket_mut(handle)
            .ok_or_else(|| StackError::SocketError("invalid socket handle".into()))?;
        socket
            .recv_slice(buf)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn tcp_is_active(&mut self, handle: SocketHandle) -> bool {
        self.get_tcp_socket_mut(handle)
            .map(|s| s.is_active())
            .unwrap_or(false)
    }

    pub fn tcp_may_send(&mut self, handle: SocketHandle) -> bool {
        self.get_tcp_socket_mut(handle)
            .map(|s| s.may_send())
            .unwrap_or(false)
    }

    pub fn tcp_may_recv(&mut self, handle: SocketHandle) -> bool {
        self.get_tcp_socket_mut(handle)
            .map(|s| s.may_recv())
            .unwrap_or(false)
    }

    pub fn tcp_is_past_handshake(&mut self, handle: SocketHandle) -> bool {
        self.get_tcp_socket_mut(handle)
            .map(|s| {
                !matches!(
                    s.state(),
                    TcpState::Listen | TcpState::SynSent | TcpState::SynReceived
                )
            })
            .unwrap_or(false)
    }

    pub fn tcp_close(&mut self, handle: SocketHandle) {
        if let Some(socket) = self.get_tcp_socket_mut(handle) {
            socket.close();
        }
    }

    pub fn remove_socket(&mut self, handle: SocketHandle) {
        if self.valid_handles.remove(&handle) {
            self.sockets.remove(handle);
        }
    }

    pub fn inject_packet(&mut self, packet: &[u8]) {
        self.device.inject_packet(packet);
    }

    pub fn inject_packet_owned(&mut self, packet: BytesMut) {
        self.device.inject_packet_owned(packet);
    }

    pub fn take_packet(&mut self) -> Option<BytesMut> {
        self.device.take_packet()
    }

    pub fn requeue_packet_front(&mut self, packet: BytesMut) {
        self.device.requeue_packet_front(packet);
    }

    pub fn recycle_tx_buffer(&mut self, buf: BytesMut) {
        self.device.recycle_tx_buffer(buf);
    }

    pub fn buffer_pool(&self) -> BufferPool {
        self.buffer_pool.clone()
    }

    pub fn queue_lengths(&self) -> (usize, usize) {
        self.device.queue_lengths()
    }

    pub fn has_rx_packets(&self) -> bool {
        self.device.queue_lengths().0 > 0
    }

    pub fn has_tx_packets(&self) -> bool {
        self.device.queue_lengths().1 > 0
    }

    pub fn take_device_stats(&mut self) -> DeviceStats {
        let (rx_queue_len, tx_queue_len) = self.device.queue_lengths();
        let (rx_drops, tx_drops) = self.device.take_drop_counts();
        DeviceStats {
            rx_queue_len,
            tx_queue_len,
            rx_drops,
            tx_drops,
        }
    }

    fn local_addr_for_remote(&self, remote_ip: IpAddress) -> Result<IpAddress, StackError> {
        match remote_ip {
            IpAddress::Ipv4(_) => self
                .local_ipv4
                .map(IpAddress::Ipv4)
                .ok_or_else(|| StackError::SocketError("No IPv4 address configured".into())),
            IpAddress::Ipv6(_) => self
                .local_ipv6
                .map(IpAddress::Ipv6)
                .ok_or_else(|| StackError::SocketError("No IPv6 address configured".into())),
        }
    }

    fn local_addr_default(&self) -> Result<IpAddress, StackError> {
        if let Some(v4) = self.local_ipv4 {
            return Ok(IpAddress::Ipv4(v4));
        }
        if let Some(v6) = self.local_ipv6 {
            return Ok(IpAddress::Ipv6(v6));
        }
        Err(StackError::SocketError("No IP address configured".into()))
    }

    fn bind_udp_socket(
        &mut self,
        local_addr: IpAddress,
        local_port: u16,
    ) -> Result<SocketHandle, StackError> {
        let metadata_capacity = self.tunables.udp_socket_metadata_capacity;
        let buffer_size = self.tunables.udp_socket_buffer_size;
        let rx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; metadata_capacity],
            vec![0; buffer_size],
        );
        let tx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; metadata_capacity],
            vec![0; buffer_size],
        );
        let mut socket = UdpSocket::new(rx_buffer, tx_buffer);

        let local_endpoint = IpEndpoint::new(local_addr, local_port);
        socket
            .bind(local_endpoint)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))?;

        let handle = self.sockets.add(socket);
        self.valid_handles.insert(handle);
        Ok(handle)
    }

    // UDP socket methods for DNS resolution and UDP associate
    pub fn create_udp_socket_for(
        &mut self,
        local_port: u16,
        remote_ip: IpAddress,
    ) -> Result<SocketHandle, StackError> {
        let local_addr = self.local_addr_for_remote(remote_ip)?;
        self.bind_udp_socket(local_addr, local_port)
    }

    pub fn create_udp_socket_default(
        &mut self,
        local_port: u16,
    ) -> Result<SocketHandle, StackError> {
        let local_addr = self.local_addr_default()?;
        self.bind_udp_socket(local_addr, local_port)
    }

    pub fn udp_send(
        &mut self,
        handle: SocketHandle,
        remote_ip: IpAddress,
        remote_port: u16,
        data: &[u8],
    ) -> Result<(), StackError> {
        let socket = self
            .get_udp_socket_mut(handle)
            .ok_or_else(|| StackError::SocketError("invalid socket handle".into()))?;
        let endpoint = IpEndpoint::new(remote_ip, remote_port);
        socket
            .send_slice(data, endpoint)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn udp_recv(
        &mut self,
        handle: SocketHandle,
        buf: &mut [u8],
    ) -> Result<(usize, UdpMetadata), StackError> {
        let socket = self
            .get_udp_socket_mut(handle)
            .ok_or_else(|| StackError::SocketError("invalid socket handle".into()))?;
        socket
            .recv_slice(buf)
            .map_err(|e| StackError::SocketError(format!("{:?}", e)))
    }

    pub fn udp_can_recv(&mut self, handle: SocketHandle) -> bool {
        self.get_udp_socket_mut(handle)
            .map(|s| s.can_recv())
            .unwrap_or(false)
    }
}
