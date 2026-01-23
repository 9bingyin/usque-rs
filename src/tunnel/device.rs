use bytes::BytesMut;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;
use std::collections::VecDeque;
use std::time::{Duration, Instant as StdInstant};

const MAX_QUEUE_SIZE: usize = 4096;
const BUFFER_POOL_SIZE: usize = 256;
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(1);

struct DropLogger {
    label: &'static str,
    count: u64,
    last_log: StdInstant,
}

impl DropLogger {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            count: 0,
            last_log: StdInstant::now(),
        }
    }

    fn log_drop(&mut self) {
        self.count += 1;
        let now = StdInstant::now();
        if now.duration_since(self.last_log) >= DROP_LOG_INTERVAL {
            log::warn!("{} queue full, dropped {} packets", self.label, self.count);
            self.count = 0;
            self.last_log = now;
        }
    }
}

pub struct VirtualDevice {
    rx_queue: VecDeque<BytesMut>,
    tx_queue: VecDeque<BytesMut>,
    buffer_pool: Vec<BytesMut>,
    mtu: usize,
    rx_drop_logger: DropLogger,
    tx_drop_logger: DropLogger,
}

impl VirtualDevice {
    pub fn new(mtu: usize) -> Self {
        let buffer_pool = (0..BUFFER_POOL_SIZE)
            .map(|_| BytesMut::with_capacity(mtu))
            .collect();

        Self {
            rx_queue: VecDeque::with_capacity(1024),
            tx_queue: VecDeque::with_capacity(1024),
            buffer_pool,
            mtu,
            rx_drop_logger: DropLogger::new("RX"),
            tx_drop_logger: DropLogger::new("TX"),
        }
    }

    fn get_buffer(&mut self) -> BytesMut {
        self.buffer_pool
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(self.mtu))
    }

    fn return_buffer(&mut self, mut buf: BytesMut) {
        if self.buffer_pool.len() < BUFFER_POOL_SIZE {
            buf.clear();
            self.buffer_pool.push(buf);
        }
    }

    pub fn inject_packet(&mut self, data: &[u8]) {
        while self.rx_queue.len() >= MAX_QUEUE_SIZE {
            if let Some(old) = self.rx_queue.pop_front() {
                self.return_buffer(old);
            }
            self.rx_drop_logger.log_drop();
        }
        let mut buf = self.get_buffer();
        buf.extend_from_slice(data);
        self.rx_queue.push_back(buf);
    }

    pub fn take_packet(&mut self) -> Option<BytesMut> {
        self.tx_queue.pop_front()
    }

    pub fn recycle_tx_buffer(&mut self, buf: BytesMut) {
        self.return_buffer(buf);
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken where Self: 'a;
    type TxToken<'a> = VirtualTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            VirtualRxToken { data: packet },
            VirtualTxToken {
                queue: &mut self.tx_queue,
                mtu: self.mtu,
                drop_logger: &mut self.tx_drop_logger,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            queue: &mut self.tx_queue,
            mtu: self.mtu,
            drop_logger: &mut self.tx_drop_logger,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct VirtualRxToken {
    data: BytesMut,
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
    mtu: usize,
    drop_logger: &'a mut DropLogger,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = BytesMut::with_capacity(self.mtu.max(len));
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        while self.queue.len() >= MAX_QUEUE_SIZE {
            let _ = self.queue.pop_front();
            self.drop_logger.log_drop();
        }
        self.queue.push_back(buffer);
        result
    }
}
