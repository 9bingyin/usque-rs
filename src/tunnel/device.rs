use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub struct VirtualDevice {
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    mtu: usize,
}

impl VirtualDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            tx_queue: Arc::new(Mutex::new(VecDeque::new())),
            mtu,
        }
    }

    pub fn rx_queue(&self) -> Arc<Mutex<VecDeque<Vec<u8>>>> {
        self.rx_queue.clone()
    }

    pub fn tx_queue(&self) -> Arc<Mutex<VecDeque<Vec<u8>>>> {
        self.tx_queue.clone()
    }

    pub fn inject_packet(&self, packet: Vec<u8>) {
        if let Ok(mut queue) = self.rx_queue.lock() {
            queue.push_back(packet);
        }
    }

    pub fn take_packet(&self) -> Option<Vec<u8>> {
        if let Ok(mut queue) = self.tx_queue.lock() {
            queue.pop_front()
        } else {
            None
        }
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken where Self: 'a;
    type TxToken<'a> = VirtualTxToken where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let has_packet = self.rx_queue.lock().ok()?.front().is_some();
        if has_packet {
            Some((
                VirtualRxToken {
                    queue: self.rx_queue.clone(),
                },
                VirtualTxToken {
                    queue: self.tx_queue.clone(),
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            queue: self.tx_queue.clone(),
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
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let packet = self
            .queue
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front())
            .unwrap_or_default();
        f(&packet)
    }
}

pub struct VirtualTxToken {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl TxToken for VirtualTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        if let Ok(mut queue) = self.queue.lock() {
            queue.push_back(buffer);
        }
        result
    }
}
