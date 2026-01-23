use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub const DEFAULT_PORT: u16 = 443;

#[derive(Error, Debug)]
pub enum QuicError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("QUIC error: {0}")]
    QuicError(#[from] quiche::Error),
    #[error("TLS error: {0}")]
    TlsError(String),
    #[error("connection error: {0}")]
    ConnectionError(String),
    #[error("handshake timeout")]
    HandshakeTimeout,
    #[error("public key mismatch")]
    PublicKeyMismatch,
}

const MAX_DATAGRAM_SIZE: usize = 1350;

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
        }
    }
}

pub fn create_quiche_config(
    quic_cfg: &QuicConfig,
    cert_der: &[u8],
    key_der: &[u8],
    _sni: &str,
) -> Result<quiche::Config, QuicError> {
    use base64::Engine;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

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

    let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(cert_der)
    );
    let key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(key_der)
    );

    let cert_file = std::env::temp_dir().join(format!("usque_cert_{}.pem", std::process::id()));
    let key_file = std::env::temp_dir().join(format!("usque_key_{}.pem", std::process::id()));

    std::fs::write(&cert_file, &cert_pem)?;
    std::fs::write(&key_file, &key_pem)?;

    config.load_cert_chain_from_pem_file(cert_file.to_str().unwrap())?;
    config.load_priv_key_from_pem_file(key_file.to_str().unwrap())?;

    let _ = std::fs::remove_file(&cert_file);
    let _ = std::fs::remove_file(&key_file);

    config.verify_peer(false);

    // Disable GREASE to avoid potential issues with Cloudflare's server
    config.grease(false);

    // Set max UDP payload size (same as Go's InitialPacketSize: 1242)
    config.set_max_send_udp_payload_size(1242);

    Ok(config)
}

pub struct QuicConnection {
    pub conn: quiche::Connection,
    pub socket: Arc<UdpSocket>,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
}

impl QuicConnection {
    pub async fn send_async(&mut self) -> Result<usize, QuicError> {
        let mut out = [0u8; MAX_DATAGRAM_SIZE];
        let mut total_sent = 0;

        loop {
            let (write, _send_info) = match self.conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(QuicError::QuicError(e)),
            };

            self.socket.send_to(&out[..write], self.peer_addr).await?;
            total_sent += write;
        }

        Ok(total_sent)
    }

    pub async fn recv_async(&mut self, buf: &mut [u8]) -> Result<usize, QuicError> {
        let (len, from) = self.socket.recv_from(buf).await?;

        let recv_info = quiche::RecvInfo {
            from,
            to: self.local_addr,
        };

        self.conn.recv(&mut buf[..len], recv_info)?;
        Ok(len)
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
) -> Result<QuicConnection, QuicError> {
    let quic_cfg = QuicConfig::default();
    let mut config = create_quiche_config(&quic_cfg, cert_der, key_der, sni)?;

    let socket = if endpoint.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0").await?
    } else {
        UdpSocket::bind("[::]:0").await?
    };

    let local_addr = socket.local_addr()?;
    let socket = Arc::new(socket);

    let scid = generate_scid();
    let conn = quiche::connect(Some(sni), &scid, local_addr, endpoint, &mut config)?;

    let mut quic_conn = QuicConnection {
        conn,
        socket,
        peer_addr: endpoint,
        local_addr,
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
        ).await {
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
) -> Result<QuicConnection, QuicError> {
    let quic_conn = connect(endpoint, cert_der, key_der, sni, timeout).await?;

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
    use x509_cert::Certificate;
    use der::{Decode, Encode};

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

fn generate_scid() -> quiche::ConnectionId<'static> {
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut scid)
        .expect("failed to generate connection ID");
    quiche::ConnectionId::from_vec(scid.to_vec())
}

use ring::rand::SecureRandom;
