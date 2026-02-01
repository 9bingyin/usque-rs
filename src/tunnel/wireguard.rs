use bytes::BytesMut;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Packet, WgKind};
use ring::rand::SecureRandom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

#[derive(Error, Debug)]
pub enum WgTunnelError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("WireGuard error: {0}")]
    WireGuard(String),
    #[error("handshake timeout")]
    HandshakeTimeout,
    #[error("handshake initiation failed")]
    HandshakeInitFailed,
}

pub struct WgTunnel {
    tunn: Tunn,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    client_id: [u8; 3],
}

impl WgTunnel {
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        client_id: [u8; 3],
        keepalive: Option<u16>,
    ) -> Self {
        let static_secret = gotatun::x25519::StaticSecret::from(private_key);
        let static_public = gotatun::x25519::PublicKey::from(&static_secret);
        let peer_public = gotatun::x25519::PublicKey::from(peer_public_key);

        let rate_limiter = Arc::new(RateLimiter::new(&static_public, 100));

        let rng = ring::rand::SystemRandom::new();
        let mut idx_bytes = [0u8; 4];
        if rng.fill(&mut idx_bytes).is_err() {
            log::warn!("Failed to generate random tunnel index, using fallback");
            idx_bytes = [0x01, 0x00, 0x00, 0x00];
        }
        let index = u32::from_le_bytes(idx_bytes);

        let tunn = Tunn::new(
            static_secret,
            peer_public,
            None,
            keepalive,
            index,
            rate_limiter,
        );

        Self {
            tunn,
            socket,
            peer_addr,
            client_id,
        }
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Initiate WG handshake and wait for completion.
    pub async fn establish(&mut self, timeout: Duration) -> Result<(), WgTunnelError> {
        let init = self
            .tunn
            .format_handshake_initiation(true)
            .ok_or(WgTunnelError::HandshakeInitFailed)?;
        self.send_wg_packet(init.into()).await?;
        log::debug!("WireGuard handshake initiation sent");

        let start = std::time::Instant::now();
        let mut buf = vec![0u8; 65535];
        let timer_interval = Duration::from_millis(250);
        let timer = tokio::time::sleep(timer_interval);
        tokio::pin!(timer);

        loop {
            if start.elapsed() > timeout {
                return Err(WgTunnelError::HandshakeTimeout);
            }

            tokio::select! {
                biased;
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, _from)) => {
                            let _ = self.process_incoming_udp(&mut buf[..len]).await;
                            if self.tunn.time_since_last_handshake().is_some() {
                                log::info!("WireGuard handshake completed");
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            log::warn!("UDP recv error during handshake: {}", e);
                        }
                    }
                }
                _ = &mut timer => {
                    self.tick_timers().await?;
                    timer.as_mut().reset(tokio::time::Instant::now() + timer_interval);
                }
            }
        }
    }

    /// Encrypt an IP packet and send it through the WG tunnel via UDP.
    pub async fn send_ip_packet(&mut self, ip_data: &[u8]) -> Result<(), WgTunnelError> {
        let packet = Packet::from_bytes(BytesMut::from(ip_data));
        if let Some(wg_kind) = self.tunn.handle_outgoing_packet(packet) {
            self.send_wg_packet(wg_kind).await?;
        }
        self.flush_queued_packets().await;
        Ok(())
    }

    /// Process incoming UDP data: strip reserved bytes, decrypt, return IP packets
    /// that should be injected into the smoltcp stack.
    pub async fn process_incoming_udp(&mut self, data: &mut [u8]) -> Vec<Vec<u8>> {
        strip_reserved(data);

        let packet = Packet::from_bytes(BytesMut::from(&data[..]));
        let wg_kind = match packet.try_into_wg() {
            Ok(wg) => wg,
            Err(e) => {
                log::debug!("Failed to parse WG packet: {}", e);
                return vec![];
            }
        };

        let result = self.tunn.handle_incoming_packet(wg_kind);
        let mut ip_packets = Vec::new();

        self.handle_tunn_result(result, &mut ip_packets).await;
        self.flush_queued_packets().await;

        ip_packets
    }

    /// Drive WG internal timers (keepalive, rekey, handshake retransmission).
    pub async fn tick_timers(&mut self) -> Result<(), WgTunnelError> {
        match self.tunn.update_timers() {
            Ok(Some(wg_kind)) => {
                self.send_wg_packet(wg_kind).await?;
                self.flush_queued_packets().await;
            }
            Ok(None) => {}
            Err(e) => {
                return Err(WgTunnelError::WireGuard(format!("{:?}", e)));
            }
        }
        Ok(())
    }

    pub fn is_expired(&self) -> bool {
        self.tunn.is_expired()
    }

    /// Collect and send all queued packets (avoids borrow conflict with iterator).
    async fn flush_queued_packets(&mut self) {
        let queued: Vec<WgKind> = self.tunn.get_queued_packets().collect();
        for packet in queued {
            if let Err(e) = self.send_wg_packet(packet).await {
                log::warn!("Failed to send queued WG packet: {}", e);
            }
        }
    }

    async fn handle_tunn_result(&mut self, result: TunnResult, ip_packets: &mut Vec<Vec<u8>>) {
        match result {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                log::debug!("WG tunnel error: {:?}", e);
            }
            TunnResult::WriteToNetwork(response) => {
                if let Err(e) = self.send_wg_packet(response).await {
                    log::warn!("Failed to send WG response: {}", e);
                }
            }
            TunnResult::WriteToTunnel(packet) => {
                let raw: &[u8] = &packet;
                if !raw.is_empty() {
                    ip_packets.push(raw.to_vec());
                }
            }
        }
    }

    /// Inject WARP client_id into reserved bytes and send via UDP.
    async fn send_wg_packet(&self, wg_kind: WgKind) -> Result<(), WgTunnelError> {
        let mut packet: Packet = wg_kind.into();
        let buf = packet.buf_mut();
        if buf.len() >= 4 {
            buf[1..4].copy_from_slice(&self.client_id);
        }
        let data: &[u8] = &packet;
        self.socket.send_to(data, self.peer_addr).await?;
        Ok(())
    }
}

/// Strip WARP reserved bytes from incoming WG packet (set positions 1-3 to zero).
/// All WG packet types use bytes 1-3 as reserved zeros; WARP repurposes them as client_id.
fn strip_reserved(buf: &mut [u8]) {
    if buf.len() >= 4 {
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
    }
}
