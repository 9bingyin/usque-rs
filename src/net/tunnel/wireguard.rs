use bytes::BytesMut;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Packet, PacketBufPool, WgKind};
use ring::rand::SecureRandom;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

use super::stack::NetworkStack;

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
    client_id: [u8; 3],
    packet_pool: PacketBufPool,
    send_queue: Vec<Packet>,
}

impl WgTunnel {
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        socket: Arc<UdpSocket>,
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

        let packet_pool = PacketBufPool::new(256);

        Self {
            tunn,
            socket,
            client_id,
            packet_pool,
            send_queue: Vec::with_capacity(64),
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
                result = self.socket.recv(&mut buf) => {
                    match result {
                        Ok(len) => {
                            self.process_handshake_packet(&mut buf[..len]).await;
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

    /// Encrypt an IP packet synchronously and buffer it for batch sending.
    /// Call flush_send_queue() after processing all pending packets.
    pub fn encrypt_ip_packet(&mut self, ip_data: &[u8]) {
        let mut packet = self.packet_pool.get();
        packet.truncate(ip_data.len());
        packet.copy_from_slice(ip_data);
        if let Some(wg_kind) = self.tunn.handle_outgoing_packet(packet) {
            self.prepare_and_queue(wg_kind);
        }
    }

    /// Batch send all buffered encrypted packets and queued control packets.
    pub async fn flush_send_queue(&mut self) {
        // Drain queued control packets (keepalive, rekey) into send_queue
        loop {
            let next = self.tunn.get_queued_packets().next();
            match next {
                Some(wg_kind) => self.prepare_and_queue(wg_kind),
                None => break,
            }
        }
        let mut queue = std::mem::take(&mut self.send_queue);
        for packet in &queue {
            let data: &[u8] = packet;
            if let Err(e) = self.try_send_udp(data).await {
                log::warn!("Failed to send WG packet: {}", e);
            }
        }
        queue.clear();
        self.send_queue = queue;
    }

    /// Synchronously decrypt an incoming WG packet and inject IP payload into smoltcp.
    /// WG control responses (handshake, cookie) are queued in send_queue for batch sending.
    /// Call drain_queued_to_send_queue() + flush_send_queue() after processing a batch.
    pub fn decrypt_incoming(&mut self, data: &mut BytesMut, stack: &mut NetworkStack) {
        strip_reserved(data.as_mut());

        let packet_buf = data.split();
        let packet = Packet::from_bytes(packet_buf);
        let wg_kind = match packet.try_into_wg() {
            Ok(wg) => wg,
            Err(e) => {
                log::debug!("Failed to parse WG packet: {}", e);
                return;
            }
        };

        let result = self.tunn.handle_incoming_packet(wg_kind);
        match result {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                log::debug!("WG tunnel error: {:?}", e);
            }
            TunnResult::WriteToNetwork(response) => {
                self.prepare_and_queue(response);
            }
            TunnResult::WriteToTunnel(packet) => {
                let raw: &[u8] = &packet;
                if !raw.is_empty() {
                    stack.inject_packet(raw);
                }
            }
        }
    }

    /// Move tunn's internally queued control packets (keepalive, rekey) into send_queue.
    pub fn drain_queued_to_send_queue(&mut self) {
        loop {
            let next = self.tunn.get_queued_packets().next();
            match next {
                Some(wg_kind) => self.prepare_and_queue(wg_kind),
                None => break,
            }
        }
    }

    /// Process incoming packet during handshake (no stack injection needed).
    async fn process_handshake_packet(&mut self, data: &mut [u8]) {
        strip_reserved(data);

        let packet = Packet::from_bytes(BytesMut::from(&data[..]));
        let wg_kind = match packet.try_into_wg() {
            Ok(wg) => wg,
            Err(e) => {
                log::debug!("Failed to parse WG packet: {}", e);
                return;
            }
        };

        let result = self.tunn.handle_incoming_packet(wg_kind);
        self.handle_tunn_result_handshake(result).await;
        self.flush_queued_packets().await;
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

    /// Send queued packets one at a time, leveraging NLL to release the mutable
    /// borrow on self.tunn between iterations (avoids collecting into Vec).
    async fn flush_queued_packets(&mut self) {
        loop {
            let next = self.tunn.get_queued_packets().next();
            match next {
                Some(wg_kind) => {
                    if let Err(e) = self.send_wg_packet(wg_kind).await {
                        log::warn!("Failed to send queued WG packet: {}", e);
                    }
                }
                None => break,
            }
        }
    }

    async fn handle_tunn_result_handshake(&mut self, result: TunnResult) {
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
            TunnResult::WriteToTunnel(_) => {}
        }
    }

    /// Inject WARP client_id into reserved bytes and push to send_queue.
    fn prepare_and_queue(&mut self, wg_kind: WgKind) {
        let mut packet: Packet = wg_kind.into();
        let buf = packet.buf_mut();
        if buf.len() >= 4 {
            buf[1..4].copy_from_slice(&self.client_id);
        }
        self.send_queue.push(packet);
    }

    /// try_send fast path; fall back to send().await on WouldBlock.
    async fn try_send_udp(&self, data: &[u8]) -> Result<(), WgTunnelError> {
        match self.socket.try_send(data) {
            Ok(_) => Ok(()),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.socket.send(data).await?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Inject WARP client_id into reserved bytes and send via connected UDP socket.
    async fn send_wg_packet(&self, wg_kind: WgKind) -> Result<(), WgTunnelError> {
        let mut packet: Packet = wg_kind.into();
        let buf = packet.buf_mut();
        if buf.len() >= 4 {
            buf[1..4].copy_from_slice(&self.client_id);
        }
        let data: &[u8] = &packet;
        self.socket.send(data).await?;
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
