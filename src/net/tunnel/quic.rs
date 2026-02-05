use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

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
    config.set_initial_max_data(quic_cfg.initial_max_data);
    config.set_initial_max_stream_data_bidi_local(quic_cfg.initial_max_stream_data_bidi_local);
    config.set_initial_max_stream_data_bidi_remote(quic_cfg.initial_max_stream_data_bidi_remote);
    config.set_initial_max_stream_data_uni(quic_cfg.initial_max_stream_data_uni);
    config.set_initial_max_streams_bidi(quic_cfg.initial_max_streams_bidi);
    config.set_initial_max_streams_uni(quic_cfg.initial_max_streams_uni);

    config.verify_peer(false);

    // Disable GREASE to avoid potential issues with Cloudflare's server
    config.grease(false);

    // Set max UDP payload size (same as Go's InitialPacketSize: 1242)
    config.set_max_send_udp_payload_size(quic_cfg.initial_packet_size as usize);

    // Set congestion control algorithm (default: BBR2)
    config.set_cc_algorithm(quic_cfg.congestion_control.to_quiche());

    Ok(config)
}

pub struct QuicConnection {
    pub conn: quiche::Connection,
    pub socket: Arc<UdpSocket>,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    send_buf: Vec<u8>,
}

impl QuicConnection {
    pub async fn send_async(&mut self) -> Result<usize, QuicError> {
        let mut total_sent = 0;

        loop {
            let (write, _send_info) = match self.conn.send(&mut self.send_buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(QuicError::Quiche(e)),
            };

            match self
                .socket
                .send_to(&self.send_buf[..write], self.peer_addr)
                .await
            {
                Ok(_) => {
                    total_sent += write;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    log::debug!("UDP send WouldBlock, dropping packet");
                    continue;
                }
                Err(e) if is_enobufs(&e) => {
                    log::debug!("UDP send ENOBUFS, dropping packet");
                    continue;
                }
                Err(e) => return Err(QuicError::IoError(e)),
            }
        }

        Ok(total_sent)
    }

    pub fn is_established(&self) -> bool {
        self.conn.is_established()
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
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
    };

    let start = std::time::Instant::now();
    let mut buf = [0u8; 65535];

    quic_conn.send_async().await?;

    while !quic_conn.is_established() {
        if start.elapsed() > timeout {
            return Err(QuicError::HandshakeTimeout);
        }

        match tokio::time::timeout(
            Duration::from_millis(100),
            quic_conn.socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((len, from))) => {
                let recv_info = quiche::RecvInfo {
                    from,
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

    log::info!("QUIC connection established to {}", endpoint);
    Ok(quic_conn)
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
            log::info!("Server public key verified");
        } else {
            log::warn!("No peer certificate available for verification");
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
            log::warn!("Failed to parse certificate: {}", e);
            return false;
        }
    };

    // Compare the entire SubjectPublicKeyInfo structure (DER encoded)
    let pub_key_info = &cert.tbs_certificate.subject_public_key_info;
    let cert_spki_der = match pub_key_info.to_der() {
        Ok(der) => der,
        Err(e) => {
            log::warn!("Failed to encode SPKI: {}", e);
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
