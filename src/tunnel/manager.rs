use crate::tunnel::masque::MasqueTunnel;
use crate::tunnel::stack::NetworkStack;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct TunnelManager {
    pub stack: Arc<Mutex<NetworkStack>>,
    tunnel: Arc<Mutex<MasqueTunnel>>,
    running: Arc<Mutex<bool>>,
}

impl TunnelManager {
    pub fn new(tunnel: MasqueTunnel, ipv4: &str, ipv6: Option<&str>) -> Self {
        let stack = NetworkStack::new(ipv4, ipv6, 1280);
        Self {
            stack: Arc::new(Mutex::new(stack)),
            tunnel: Arc::new(Mutex::new(tunnel)),
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn start(&self) {
        *self.running.lock().unwrap() = true;

        let stack = self.stack.clone();
        let tunnel = self.tunnel.clone();
        let running = self.running.clone();

        // QUIC I/O thread: process incoming QUIC packets and receive datagrams
        let stack_rx = stack.clone();
        let tunnel_rx = tunnel.clone();
        let running_rx = running.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 65535];
            while *running_rx.lock().unwrap() {
                if let Ok(mut t) = tunnel_rx.lock() {
                    // Process incoming QUIC packets from socket
                    if let Err(e) = t.process_quic() {
                        log::warn!("process_quic error: {:?}", e);
                    }

                    // Receive datagrams and inject to stack
                    loop {
                        match t.recv_datagram(&mut buf) {
                            Ok(len) if len > 0 => {
                                log::debug!("Received {} bytes from tunnel", len);
                                let packet = buf[..len].to_vec();
                                if let Ok(mut s) = stack_rx.lock() {
                                    s.inject_packet(packet);
                                }
                            }
                            _ => break,
                        }
                    }
                }
                thread::sleep(Duration::from_micros(100));
            }
        });

        // Stack -> Tunnel (take from stack, send to MASQUE)
        let stack_tx = stack.clone();
        let tunnel_tx = tunnel.clone();
        let running_tx = running.clone();
        thread::spawn(move || {
            while *running_tx.lock().unwrap() {
                if let Ok(mut s) = stack_tx.lock() {
                    while let Some(packet) = s.take_packet() {
                        if let Ok(mut t) = tunnel_tx.lock() {
                            let _ = t.send_datagram(&packet);
                            let _ = t.quic_conn.send();
                        }
                    }
                }
                thread::sleep(Duration::from_micros(100));
            }
        });

        // Poll stack
        let stack_poll = stack.clone();
        let running_poll = running.clone();
        thread::spawn(move || {
            while *running_poll.lock().unwrap() {
                if let Ok(mut s) = stack_poll.lock() {
                    s.poll();
                }
                thread::sleep(Duration::from_micros(100));
            }
        });
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }
}
