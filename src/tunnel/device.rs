use bytes::BytesMut;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;

const MAX_QUEUE_SIZE: usize = 4096;
const BUFFER_POOL_SIZE: usize = 256;

pub struct VirtualDevice {
    rx_queue: VecDeque<BytesMut>,
    tx_queue: VecDeque<BytesMut>,
    buffer_pool: Vec<BytesMut>,
    mtu: usize,
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
            log::warn!("RX queue full, dropping oldest packet");
        }
        let mut buf = self.get_buffer();
        buf.extend_from_slice(data);
        self.rx_queue.push_back(buf);
    }

    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front().map(|buf| {
            let data = buf.to_vec();
            self.return_buffer(buf);
            data
        })
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken where Self: 'a;
    type TxToken<'a> = VirtualTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            VirtualRxToken { data: packet },
            VirtualTxToken {
                queue: &mut self.tx_queue,
                mtu: self.mtu,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            queue: &mut self.tx_queue,
            mtu: self.mtu,
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
            log::warn!("TX queue full, dropping oldest packet");
        }
        self.queue.push_back(buffer);
        result
    }
}
