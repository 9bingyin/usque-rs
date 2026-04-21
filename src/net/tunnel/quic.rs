use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use thiserror::Error;
use tokio::net::UdpSocket;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[derive(Debug, Clone, Copy, Default)]
pub enum CongestionControl {
    Reno,
    Cubic,
    #[default]
    Bbr2,
}

impl std::str::FromStr for CongestionControl {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "reno" => Ok(CongestionControl::Reno),
            "cubic" => Ok(CongestionControl::Cubic),
            "bbr" | "bbr2" | "bbrv2" => Ok(CongestionControl::Bbr2),
            _ => Err(format!(
                "Unknown congestion control algorithm: {}. Valid options: reno, cubic, bbr2",
                s
            )),
        }
    }
}

impl std::fmt::Display for CongestionControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CongestionControl::Reno => write!(f, "reno"),
            CongestionControl::Cubic => write!(f, "cubic"),
            CongestionControl::Bbr2 => write!(f, "bbr2"),
        }
    }
}

impl CongestionControl {
    fn to_quiche(self) -> quiche::CongestionControlAlgorithm {
        match self {
            CongestionControl::Reno => quiche::CongestionControlAlgorithm::Reno,
            CongestionControl::Cubic => quiche::CongestionControlAlgorithm::CUBIC,
            CongestionControl::Bbr2 => quiche::CongestionControlAlgorithm::Bbr2Gcongestion,
        }
    }
}

#[derive(Error, Debug)]
pub enum QuicError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("QUIC error: {0}")]
    Quiche(#[from] quiche::Error),
    #[error("connection error: {0}")]
    ConnectionError(String),
    #[error("handshake timeout")]
    HandshakeTimeout,
    #[error("public key mismatch")]
    PublicKeyMismatch,
}

pub struct QuicConfig {
    pub idle_timeout: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub enable_dgram: bool,
    pub dgram_recv_max_queue_len: u64,
    pub dgram_send_max_queue_len: u64,
    pub initial_packet_size: u16,
    pub max_recv_udp_payload_size: usize,
    pub max_connection_window: u64,
    pub max_stream_window: u64,
    pub send_capacity_factor: f64,
    pub congestion_control: CongestionControl,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            idle_timeout: 30_000,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_stream_data_uni: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            enable_dgram: true,
            dgram_recv_max_queue_len: 10000,
            dgram_send_max_queue_len: 10000,
            initial_packet_size: 1242,
            max_recv_udp_payload_size: 1350,
            max_connection_window: 20_000_000,
            max_stream_window: 8_000_000,
            send_capacity_factor: 2.0,
            congestion_control: CongestionControl::Cubic,
        }
    }
}

pub fn create_quiche_config(
    quic_cfg: &QuicConfig,
    cert_der: &[u8],
    key_der: &[u8],
    _sni: &str,
) -> Result<quiche::Config, QuicError> {
    use boring::ec::EcKey;
    use boring::pkey::PKey;
    use boring::ssl::{SslContextBuilder, SslMethod};
    use boring::x509::X509;

    // Load certificate and private key from memory
    let cert = X509::from_der(cert_der)
        .map_err(|e| QuicError::ConnectionError(format!("cert error: {}", e)))?;
    // Parse SEC1 format EC private key (same as Go's x509.MarshalECPrivateKey)
    let ec_key = EcKey::private_key_from_der(key_der)
        .map_err(|e| QuicError::ConnectionError(format!("ec key error: {}", e)))?;
    let pkey = PKey::from_ec_key(ec_key)
        .map_err(|e| QuicError::ConnectionError(format!("pkey error: {}", e)))?;

    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| QuicError::ConnectionError(format!("ssl context error: {}", e)))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| QuicError::ConnectionError(format!("set cert error: {}", e)))?;
    builder
        .set_private_key(&pkey)
        .map_err(|e| QuicError::ConnectionError(format!("set key error: {}", e)))?;

    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)?;

    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;

    if quic_cfg.enable_dgram {
        config.enable_dgram(
            true,
            quic_cfg.dgram_recv_max_queue_len as usize,
            quic_cfg.dgram_send_max_queue_len as usize,
        );
    }

    config.set_max_idle_timeout(quic_cfg.idle_timeout);
    config.set_max_recv_udp_payload_size(quic_cfg.max_recv_udp_payload_size);
    config.set_initial_max_data(quic_cfg.initial_max_data);
    config.set_initial_max_stream_data_bidi_local(quic_cfg.initial_max_stream_data_bidi_local);
    config.set_initial_max_stream_data_bidi_remote(quic_cfg.initial_max_stream_data_bidi_remote);
    config.set_initial_max_stream_data_uni(quic_cfg.initial_max_stream_data_uni);
    config.set_initial_max_streams_bidi(quic_cfg.initial_max_streams_bidi);
    config.set_initial_max_streams_uni(quic_cfg.initial_max_streams_uni);
    config.set_disable_active_migration(true);
    config.set_max_connection_window(quic_cfg.max_connection_window);
    config.set_max_stream_window(quic_cfg.max_stream_window);
    config.set_send_capacity_factor(quic_cfg.send_capacity_factor);

    config.verify_peer(false);

    // Disable GREASE to avoid potential issues with Cloudflare's server
    config.grease(false);

    // Set max UDP payload size (same as Go's InitialPacketSize: 1242)
    config.set_max_send_udp_payload_size(quic_cfg.initial_packet_size as usize);

    // Set congestion control algorithm (default: BBR2)
    config.set_cc_algorithm(quic_cfg.congestion_control.to_quiche());
    config.enable_pacing(true);
    if let Some(max_pacing_rate_mbps) = std::env::var("USQUE_QUIC_MAX_PACING_RATE_MBPS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
    {
        config.set_max_pacing_rate(max_pacing_rate_mbps * 1_000_000);
    }

    Ok(config)
}

pub struct QuicConnection {
    pub conn: quiche::Connection,
    pub socket: Arc<UdpSocket>,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    send_buf: Vec<u8>,
    pending_buf: Vec<u8>,
    pending_len: usize,
    pending_at: Option<Instant>,
    pending_socket_blocked: bool,
    flush_pending: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct QuicSendStatus {
    pub bytes_sent: usize,
    pub packets_sent: usize,
    pub blocked: bool,
    pub enobufs: bool,
    pub paced: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct QuicPerfStats {
    pub rtt_ms: u64,
    pub cwnd: usize,
    pub lost: usize,
    pub total_pto_count: usize,
    pub delivery_rate_bps: u64,
    pub dgram_recv: usize,
    pub dgram_sent: usize,
}

impl QuicSendStatus {
    fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes;
        self.packets_sent += 1;
    }
}

impl QuicConnection {
    pub async fn send_async(&mut self) -> Result<QuicSendStatus, QuicError> {
        let mut status = QuicSendStatus::default();

        loop {
            if self.pending_len > 0 {
                let now = Instant::now();
                if let Some(pending_at) = self.pending_at
                    && pending_at > now
                {
                    status.paced = true;
                    break;
                }

                match self.try_send_pending_packet() {
                    Ok(sent) => {
                        status.record_sent(sent);
                        continue;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        self.pending_socket_blocked = true;
                        status.blocked = true;
                        break;
                    }
                    Err(e) if is_enobufs(&e) => {
                        self.pending_socket_blocked = true;
                        status.blocked = true;
                        status.enobufs = true;
                        break;
                    }
                    Err(e) => return Err(QuicError::IoError(e)),
                }
            }

            let (write, send_info) = match self.conn.send(&mut self.send_buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(QuicError::Quiche(e)),
            };

            let now = Instant::now();
            if send_info.at > now {
                self.cache_pending_packet(write, send_info.at);
                status.paced = true;
                break;
            }

            match self.socket.try_send(&self.send_buf[..write]) {
                Ok(sent) => {
                    if sent != write {
                        return Err(QuicError::ConnectionError(format!(
                            "partial UDP datagram send: sent {} of {} bytes",
                            sent, write
                        )));
                    }
                    status.record_sent(sent);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.cache_pending_packet(write, send_info.at);
                    self.pending_socket_blocked = true;
                    status.blocked = true;
                    break;
                }
                Err(e) if is_enobufs(&e) => {
                    self.cache_pending_packet(write, send_info.at);
                    self.pending_socket_blocked = true;
                    status.blocked = true;
                    status.enobufs = true;
                    break;
                }
                Err(e) => return Err(QuicError::IoError(e)),
            }
        }

        Ok(status)
    }

    pub fn is_established(&self) -> bool {
        self.conn.is_established()
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    pub fn has_pending_send(&self) -> bool {
        self.pending_len > 0
    }

    pub fn has_pending_send_work(&self) -> bool {
        self.flush_pending
    }

    pub fn pending_send_packets(&self) -> usize {
        usize::from(self.pending_len > 0)
    }

    pub fn next_send_at(&self) -> Option<Instant> {
        if self.pending_len > 0 {
            self.pending_at
                .filter(|deadline| *deadline > Instant::now())
        } else {
            None
        }
    }

    pub fn needs_socket_writable(&self) -> bool {
        self.pending_len > 0
            && self.pending_socket_blocked
            && self
                .pending_at
                .is_none_or(|deadline| deadline <= Instant::now())
    }

    pub fn mark_pending_send(&mut self) {
        self.flush_pending = true;
    }

    pub fn take_pending_send(&mut self) -> bool {
        std::mem::take(&mut self.flush_pending)
    }

    pub fn perf_stats(&self) -> Option<QuicPerfStats> {
        let path = self
            .conn
            .path_stats()
            .find(|stats| stats.active)
            .or_else(|| self.conn.path_stats().next())?;
        Some(QuicPerfStats {
            rtt_ms: path.rtt.as_millis().min(u128::from(u64::MAX)) as u64,
            cwnd: path.cwnd,
            lost: path.lost,
            total_pto_count: path.total_pto_count,
            delivery_rate_bps: path.delivery_rate,
            dgram_recv: path.dgram_recv,
            dgram_sent: path.dgram_sent,
        })
    }

    fn cache_pending_packet(&mut self, len: usize, send_at: Instant) {
        if self.pending_buf.len() < len {
            self.pending_buf.resize(len, 0);
        } else {
            self.pending_buf.truncate(len);
        }
        self.pending_buf[..len].copy_from_slice(&self.send_buf[..len]);
        self.pending_len = len;
        self.pending_at = Some(send_at);
        self.pending_socket_blocked = false;
    }

    fn try_send_pending_packet(&mut self) -> Result<usize, std::io::Error> {
        debug_assert!(self.pending_len > 0);
        let sent = self
            .socket
            .try_send(&self.pending_buf[..self.pending_len])?;
        if sent != self.pending_len {
            return Err(std::io::Error::other(format!(
                "partial UDP datagram send: sent {} of {} bytes",
                sent, self.pending_len
            )));
        }

        self.pending_len = 0;
        self.pending_at = None;
        self.pending_socket_blocked = false;
        Ok(sent)
    }
}

pub async fn connect(
    endpoint: SocketAddr,
    cert_der: &[u8],
    key_der: &[u8],
    sni: &str,
    timeout: Duration,
    quic_cfg: &QuicConfig,
) -> Result<QuicConnection, QuicError> {
    let mut config = create_quiche_config(quic_cfg, cert_der, key_der, sni)?;

    let socket = if endpoint.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0").await?
    } else {
        UdpSocket::bind("[::]:0").await?
    };
    socket.connect(endpoint).await?;
    let std_socket = socket.into_std()?;
    configure_udp_socket_buffers(
        &std_socket,
        env_usize("USQUE_QUIC_UDP_RECVBUF", 4 * 1024 * 1024),
        env_usize("USQUE_QUIC_UDP_SNDBUF", 2 * 1024 * 1024),
    );
    let socket = UdpSocket::from_std(std_socket)?;
    let local_addr = socket.local_addr()?;
    let socket = Arc::new(socket);

    let scid = generate_scid()?;
    let conn = quiche::connect(Some(sni), &scid, local_addr, endpoint, &mut config)?;

    let max_datagram_size = std::cmp::max(quic_cfg.initial_packet_size as usize, 1350);
    let mut quic_conn = QuicConnection {
        conn,
        socket,
        peer_addr: endpoint,
        local_addr,
        send_buf: vec![0u8; max_datagram_size],
        pending_buf: vec![0u8; max_datagram_size],
        pending_len: 0,
        pending_at: None,
        pending_socket_blocked: false,
        flush_pending: false,
    };

    let start = std::time::Instant::now();
    let mut buf = vec![0u8; env_usize("USQUE_QUIC_HANDSHAKE_BUFFER_SIZE", 64 * 1024)];
    let handshake_poll_timeout =
        Duration::from_millis(env_u64("USQUE_QUIC_HANDSHAKE_POLL_TIMEOUT_MS", 100));

    quic_conn.send_async().await?;

    while !quic_conn.is_established() {
        if start.elapsed() > timeout {
            return Err(QuicError::HandshakeTimeout);
        }

        match tokio::time::timeout(handshake_poll_timeout, quic_conn.socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                let recv_info = quiche::RecvInfo {
                    from: endpoint,
                    to: local_addr,
                };
                quic_conn.conn.recv(&mut buf[..len], recv_info)?;
            }
            Ok(Err(e)) => return Err(QuicError::IoError(e)),
            Err(_) => {} // timeout, continue
        }

        quic_conn.send_async().await?;

        if quic_conn.is_closed() {
            return Err(QuicError::ConnectionError("connection closed".into()));
        }
    }

    log::debug!("QUIC connection established to {}", endpoint);
    Ok(quic_conn)
}

fn configure_udp_socket_buffers(socket: &std::net::UdpSocket, recv_size: usize, send_size: usize) {
    let sock = socket2::SockRef::from(socket);

    if let Err(e) = sock.set_recv_buffer_size(recv_size) {
        log::warn!(
            "failed to set QUIC SO_RCVBUF to {}KB: {}",
            recv_size / 1024,
            e
        );
    }
    if let Err(e) = sock.set_send_buffer_size(send_size) {
        log::warn!(
            "failed to set QUIC SO_SNDBUF to {}KB: {}",
            send_size / 1024,
            e
        );
    }

    let actual_recv = sock.recv_buffer_size().unwrap_or(0);
    let actual_send = sock.send_buffer_size().unwrap_or(0);
    log::info!(
        "QUIC UDP socket buffers: recv={}KB (req {}KB), send={}KB (req {}KB)",
        actual_recv / 1024,
        recv_size / 1024,
        actual_send / 1024,
        send_size / 1024,
    );
}

pub async fn connect_with_pinning(
    endpoint: SocketAddr,
    cert_der: &[u8],
    key_der: &[u8],
    sni: &str,
    timeout: Duration,
    expected_pub_key: Option<&[u8]>,
    quic_cfg: &QuicConfig,
) -> Result<QuicConnection, QuicError> {
    let quic_conn = connect(endpoint, cert_der, key_der, sni, timeout, quic_cfg).await?;

    if let Some(expected_key) = expected_pub_key {
        if let Some(peer_cert) = quic_conn.conn.peer_cert() {
            if !verify_peer_public_key(peer_cert, expected_key) {
                return Err(QuicError::PublicKeyMismatch);
            }
            log::debug!("server public key verified");
        } else {
            log::warn!("no peer certificate for verification");
        }
    }

    Ok(quic_conn)
}

fn verify_peer_public_key(cert_der: &[u8], expected_pub_key_spki: &[u8]) -> bool {
    use der::{Decode, Encode};
    use x509_cert::Certificate;

    let cert = match Certificate::from_der(cert_der) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("failed to parse certificate: {}", e);
            return false;
        }
    };

    // Compare the entire SubjectPublicKeyInfo structure (DER encoded)
    let pub_key_info = &cert.tbs_certificate.subject_public_key_info;
    let cert_spki_der = match pub_key_info.to_der() {
        Ok(der) => der,
        Err(e) => {
            log::warn!("failed to encode SPKI: {}", e);
            return false;
        }
    };

    cert_spki_der == expected_pub_key_spki
}

fn generate_scid() -> Result<quiche::ConnectionId<'static>, QuicError> {
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut scid)
        .map_err(|e| QuicError::ConnectionError(format!("random generation failed: {}", e)))?;
    Ok(quiche::ConnectionId::from_vec(scid.to_vec()))
}

use ring::rand::SecureRandom;

// ENOBUFS: 55 on macOS/BSD, 105 on Linux
fn is_enobufs(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(55) | Some(105))
}
