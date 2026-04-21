use crate::net::tunnel::quic::{
    QuicConfig, QuicError, build_tokio_quiche_connection_params, configure_udp_socket_buffers,
    fetch_dgram_max_writable_len, fetch_peer_cert, fetch_perf_stats, verify_peer_public_key,
};
use bytes::{Bytes, BytesMut};
use futures::SinkExt;
use quiche::h3::NameValue;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio_quiche::ClientH3Controller;
use tokio_quiche::ClientH3Driver;
use tokio_quiche::QuicConnection;
use tokio_quiche::datagram_socket::DgramBuffer;
use tokio_quiche::http3::driver::{
    ClientH3Event, H3Event, InboundFrameStream, NewClientRequest, OutboundFrame,
    OutboundFrameSender,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::{ConnectionShutdownBehaviour, QuicCommand};
use tokio_quiche::socket::Socket as TokioQuicSocket;

// Context ID = 0 for IP packets (RFC 9484)
const CONTEXT_ID_ZERO: u8 = 0x00;
const CONNECT_REQUEST_ID: u64 = 1;

#[derive(Error, Debug)]
pub enum MasqueError {
    #[error("QUIC error: {0}")]
    QuicError(#[from] QuicError),
    #[error("connection error: {0}")]
    ConnectionError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("tokio-quiche error: {0}")]
    TokioQuiche(String),
    #[error("connect-ip failed: {0}")]
    ConnectIpFailed(String),
    #[error("timeout")]
    Timeout,
}

pub enum DatagramSendState {
    Sent,
    Dropped,
    PacketTooBig(Vec<u8>),
    Blocked,
}

pub struct MasqueTunnel {
    pub quic_conn: QuicConnection,
    pub controller: ClientH3Controller,
    pub connect_stream_id: u64,
    pub connect_recv: InboundFrameStream,
    pub flow_id: u64,
    pub flow_send: OutboundFrameSender,
    pub flow_recv: InboundFrameStream,
    pub socket: Arc<UdpSocket>,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub max_h3_dgram_len: Option<usize>,
    dgram_recv_buf: Vec<u8>,
    dgram_send_buf: Vec<u8>,
    control_state: MasqueControlState,
}

#[derive(Default)]
struct MasqueControlState {
    recv_buf: BytesMut,
    assigned_addresses: Vec<String>,
    advertised_routes: Vec<String>,
}

impl MasqueTunnel {
    pub async fn connect(
        endpoint: SocketAddr,
        cert_der: &[u8],
        key_der: &[u8],
        sni: &str,
        timeout: Duration,
        expected_pub_key: Option<&[u8]>,
        quic_cfg: &QuicConfig,
    ) -> Result<Self, MasqueError> {
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
        let socket: TokioQuicSocket<Arc<UdpSocket>, Arc<UdpSocket>> =
            TokioQuicSocket::<Arc<UdpSocket>, Arc<UdpSocket>>::from_udp(socket)?;
        #[cfg(target_os = "linux")]
        let socket = {
            let mut socket = socket;
            let apply_max_capabilities = std::env::var("USQUE_QUIC_APPLY_MAX_CAPABILITIES")
                .ok()
                .and_then(|value| value.parse::<bool>().ok())
                .unwrap_or(true);
            if apply_max_capabilities {
                socket.apply_max_capabilities();
                log::debug!(
                    "tokio-quiche socket capabilities: {:?}",
                    socket.capabilities
                );
            }
            socket
        };
        let socket_ref = socket.send.clone();
        let local_addr = socket.local_addr;
        let peer_addr = socket.peer_addr;

        let (driver, mut controller) = ClientH3Driver::new(Http3Settings::default());
        let params = build_tokio_quiche_connection_params(quic_cfg, cert_der, key_der);
        let quic_conn = tokio_quiche::quic::connect_with_config(socket, Some(sni), &params, driver)
            .await
            .map_err(|e| MasqueError::TokioQuiche(e.to_string()))?;

        if let Some(expected_key) = expected_pub_key {
            match fetch_peer_cert(&controller).await? {
                Some(peer_cert) if verify_peer_public_key(&peer_cert, expected_key) => {
                    log::debug!("server public key verified");
                }
                Some(_) => return Err(MasqueError::QuicError(QuicError::PublicKeyMismatch)),
                None => log::warn!("no peer certificate for verification"),
            }
        }

        controller
            .request_sender()
            .send(NewClientRequest {
                request_id: CONNECT_REQUEST_ID,
                headers: connect_ip_headers(),
                body_writer: None,
            })
            .map_err(|_| {
                MasqueError::ConnectionError("CONNECT-IP request channel closed".into())
            })?;

        let started_at = std::time::Instant::now();
        let mut connect_stream_id = None;
        let mut connect_recv = None;
        let mut connect_established = false;
        let mut flow = None;

        while !connect_established || flow.is_none() || connect_recv.is_none() {
            let remaining = timeout
                .checked_sub(started_at.elapsed())
                .ok_or(MasqueError::Timeout)?;
            let event = tokio::time::timeout(remaining, controller.event_receiver_mut().recv())
                .await
                .map_err(|_| MasqueError::Timeout)?
                .ok_or_else(|| {
                    MasqueError::ConnectionError("tokio-quiche event channel closed".into())
                })?;

            match event {
                ClientH3Event::NewOutboundRequest {
                    stream_id,
                    request_id,
                } if request_id == CONNECT_REQUEST_ID => {
                    connect_stream_id = Some(stream_id);
                    log::debug!("Connect-IP request sent (stream={})", stream_id);
                }
                ClientH3Event::Core(H3Event::NewFlow {
                    flow_id,
                    send,
                    recv,
                }) => {
                    if flow.is_none() {
                        log::debug!("MASQUE datagram flow established (flow={})", flow_id);
                        flow = Some((flow_id, send, recv));
                    }
                }
                ClientH3Event::Core(H3Event::IncomingHeaders(headers)) => {
                    if Some(headers.stream_id) != connect_stream_id {
                        continue;
                    }
                    connect_recv = Some(headers.recv);
                    let status = headers
                        .headers
                        .iter()
                        .find(|header| header.name() == b":status")
                        .and_then(|header| std::str::from_utf8(header.value()).ok())
                        .unwrap_or("unknown");
                    log::debug!("Connect-IP response: status={}", status);
                    if status == "200" {
                        connect_established = true;
                    } else {
                        return Err(MasqueError::ConnectIpFailed(format!("status: {}", status)));
                    }
                }
                ClientH3Event::Core(H3Event::ConnectionError(err)) => {
                    return Err(MasqueError::ConnectionError(format!("H3 error: {:?}", err)));
                }
                ClientH3Event::Core(H3Event::ConnectionShutdown(err)) => {
                    return Err(MasqueError::ConnectionError(format!(
                        "H3 shutdown: {:?}",
                        err
                    )));
                }
                _ => {}
            }
        }

        let (flow_id, flow_send, flow_recv) = flow.expect("flow must exist");
        let max_h3_dgram_len = fetch_dgram_max_writable_len(&controller)
            .await?
            .map(|max_len| max_len.saturating_sub(varint_len(flow_id)));

        log::info!("MASQUE tunnel established");
        Ok(Self {
            quic_conn,
            controller,
            connect_stream_id: connect_stream_id.expect("stream id must exist"),
            connect_recv: connect_recv.expect("connect recv must exist"),
            flow_id,
            flow_send,
            flow_recv,
            socket: socket_ref,
            peer_addr,
            local_addr,
            max_h3_dgram_len,
            dgram_recv_buf: Vec::new(),
            dgram_send_buf: Vec::new(),
            control_state: MasqueControlState::default(),
        })
    }

    pub fn max_ip_packet_len(&self) -> usize {
        self.max_h3_dgram_len
            .map(|len| len.saturating_sub(1))
            .unwrap_or(1280)
    }

    pub async fn send_datagram(
        &mut self,
        packet: &BytesMut,
    ) -> Result<DatagramSendState, MasqueError> {
        let dgram_len = 1 + packet.len();
        if self.dgram_send_buf.len() < dgram_len {
            self.dgram_send_buf.resize(dgram_len, 0);
        } else {
            self.dgram_send_buf.truncate(dgram_len);
        }

        self.dgram_send_buf[0] = CONTEXT_ID_ZERO;
        self.dgram_send_buf[1..].copy_from_slice(packet.as_ref());

        if !process_outgoing_ip_packet(&mut self.dgram_send_buf[1..])? {
            return Ok(DatagramSendState::Dropped);
        }

        if let Some(max_len) = self.max_h3_dgram_len
            && self.dgram_send_buf.len() > max_len
        {
            log::debug!(
                "Datagram too large: {} bytes > max {} bytes, generating ICMP Packet Too Big",
                self.dgram_send_buf.len(),
                max_len
            );
            return Ok(
                match compose_icmp_packet_too_big(packet.as_ref(), MIN_MTU) {
                    Some(icmp) => DatagramSendState::PacketTooBig(icmp),
                    None => DatagramSendState::Dropped,
                },
            );
        }

        let frame =
            OutboundFrame::Datagram(DgramBuffer::from_slice(&self.dgram_send_buf), self.flow_id);

        let sender = self.flow_send.get_ref().ok_or_else(|| {
            MasqueError::ConnectionError("datagram flow sender unavailable".into())
        })?;

        match sender.try_send(frame) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(frame)) => {
                self.flow_send.send(frame).await.map_err(|e| {
                    MasqueError::ConnectionError(format!(
                        "datagram send failed after waiting: {}",
                        e
                    ))
                })?;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err(MasqueError::ConnectionError(
                    "datagram flow sender closed".into(),
                ));
            }
        }

        Ok(DatagramSendState::Sent)
    }

    pub fn decode_datagram(
        &mut self,
        dgram: DgramBuffer,
        buf: &mut [u8],
    ) -> Result<usize, MasqueError> {
        let needed = dgram.len();
        if self.dgram_recv_buf.len() < needed {
            self.dgram_recv_buf.resize(needed, 0);
        } else {
            self.dgram_recv_buf.truncate(needed);
        }
        self.dgram_recv_buf[..needed].copy_from_slice(dgram.as_slice());

        let (context_id, ctx_len) = decode_varint(&self.dgram_recv_buf)?;
        if context_id != 0 {
            return Ok(0);
        }

        let payload_len = needed.saturating_sub(ctx_len);
        if payload_len > buf.len() {
            return Err(MasqueError::ConnectionError("Buffer too small".into()));
        }

        buf[..payload_len].copy_from_slice(&self.dgram_recv_buf[ctx_len..needed]);
        Ok(payload_len)
    }

    pub async fn sample_quic_stats(&self) -> Option<crate::net::tunnel::quic::QuicPerfStats> {
        fetch_perf_stats(&self.controller).await.ok().flatten()
    }

    pub fn process_control_chunk(&mut self, chunk: Bytes, fin: bool) -> Result<(), MasqueError> {
        self.control_state.recv_buf.extend_from_slice(&chunk);

        loop {
            let Some((capsule_type, capsule_type_len)) =
                try_decode_varint(self.control_state.recv_buf.as_ref())
            else {
                break;
            };
            let Some((capsule_len, capsule_len_len)) =
                try_decode_varint(&self.control_state.recv_buf[capsule_type_len..])
            else {
                break;
            };
            let frame_len = capsule_type_len
                .checked_add(capsule_len_len)
                .and_then(|len| len.checked_add(capsule_len as usize))
                .ok_or_else(|| {
                    MasqueError::ConnectionError("capsule frame length overflow".into())
                })?;
            if self.control_state.recv_buf.len() < frame_len {
                break;
            }

            let frame = self.control_state.recv_buf.split_to(frame_len);
            let payload_offset = capsule_type_len + capsule_len_len;
            let payload = &frame[payload_offset..];
            self.control_state.process_capsule(capsule_type, payload)?;
        }

        if fin && !self.control_state.recv_buf.is_empty() {
            return Err(MasqueError::ConnectionError(
                "truncated MASQUE control capsule".into(),
            ));
        }

        Ok(())
    }

    pub fn assigned_addresses(&self) -> &[String] {
        &self.control_state.assigned_addresses
    }

    pub fn advertised_routes(&self) -> &[String] {
        &self.control_state.advertised_routes
    }

    pub fn close(&self) {
        let _ = self
            .controller
            .cmd_sender()
            .send(QuicCommand::ConnectionClose(ConnectionShutdownBehaviour {
                send_application_close: true,
                error_code: 0,
                reason: Vec::new(),
            }));
    }
}

impl MasqueControlState {
    fn process_capsule(&mut self, capsule_type: u64, payload: &[u8]) -> Result<(), MasqueError> {
        match capsule_type {
            0x01 => {
                let addresses = parse_address_assign_capsule(payload)?;
                if !addresses.is_empty() {
                    log::debug!("MASQUE AddressAssign: {}", addresses.join(", "));
                    self.assigned_addresses.extend(addresses);
                }
            }
            0x03 => {
                let routes = parse_route_advertisement_capsule(payload)?;
                if !routes.is_empty() {
                    log::debug!("MASQUE RouteAdvertisement: {}", routes.join(", "));
                    self.advertised_routes.extend(routes);
                }
            }
            _ => {
                log::trace!(
                    "ignored MASQUE control capsule type={} len={}",
                    capsule_type,
                    payload.len()
                );
            }
        }

        Ok(())
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn connect_ip_headers() -> Vec<quiche::h3::Header> {
    vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"user-agent", b""),
    ]
}

// QUIC varint encoding (RFC 9000)
// 2-bit length prefix: 00=1byte, 01=2bytes, 10=4bytes, 11=8bytes

fn varint_len(value: u64) -> usize {
    if value < 64 {
        1
    } else if value < 16384 {
        2
    } else if value < 1073741824 {
        4
    } else {
        8
    }
}

fn decode_varint(buf: &[u8]) -> Result<(u64, usize), MasqueError> {
    if buf.is_empty() {
        return Err(MasqueError::ConnectionError("Empty buffer".into()));
    }

    let prefix = buf[0] >> 6;
    let len = 1 << prefix;

    if buf.len() < len {
        return Err(MasqueError::ConnectionError("Buffer too short".into()));
    }

    let value = match len {
        1 => (buf[0] & 0x3f) as u64,
        2 => ((buf[0] & 0x3f) as u64) << 8 | buf[1] as u64,
        4 => {
            ((buf[0] & 0x3f) as u64) << 24
                | (buf[1] as u64) << 16
                | (buf[2] as u64) << 8
                | buf[3] as u64
        }
        8 => {
            ((buf[0] & 0x3f) as u64) << 56
                | (buf[1] as u64) << 48
                | (buf[2] as u64) << 40
                | (buf[3] as u64) << 32
                | (buf[4] as u64) << 24
                | (buf[5] as u64) << 16
                | (buf[6] as u64) << 8
                | buf[7] as u64
        }
        _ => unreachable!(),
    };

    Ok((value, len))
}

fn try_decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    decode_varint(buf).ok()
}

fn parse_address_assign_capsule(payload: &[u8]) -> Result<Vec<String>, MasqueError> {
    let mut offset = 0usize;
    let mut addresses = Vec::new();

    while offset < payload.len() {
        let (_, request_id_len) = decode_varint(&payload[offset..])?;
        offset += request_id_len;
        let ip_version = *payload.get(offset).ok_or_else(|| {
            MasqueError::ConnectionError("truncated AddressAssign capsule".into())
        })?;
        offset += 1;

        let entry = match ip_version {
            4 => {
                let addr = payload.get(offset..offset + 4).ok_or_else(|| {
                    MasqueError::ConnectionError("truncated AddressAssign IPv4".into())
                })?;
                offset += 4;
                let prefix = *payload.get(offset).ok_or_else(|| {
                    MasqueError::ConnectionError("missing AddressAssign IPv4 prefix".into())
                })?;
                offset += 1;
                format!(
                    "{}/{}",
                    IpAddr::from([addr[0], addr[1], addr[2], addr[3]]),
                    prefix
                )
            }
            6 => {
                let addr = payload.get(offset..offset + 16).ok_or_else(|| {
                    MasqueError::ConnectionError("truncated AddressAssign IPv6".into())
                })?;
                offset += 16;
                let prefix = *payload.get(offset).ok_or_else(|| {
                    MasqueError::ConnectionError("missing AddressAssign IPv6 prefix".into())
                })?;
                offset += 1;
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(addr);
                format!("{}/{}", IpAddr::from(bytes), prefix)
            }
            other => {
                return Err(MasqueError::ConnectionError(format!(
                    "invalid AddressAssign IP version: {}",
                    other
                )));
            }
        };

        addresses.push(entry);
    }

    Ok(addresses)
}

fn parse_route_advertisement_capsule(payload: &[u8]) -> Result<Vec<String>, MasqueError> {
    let mut offset = 0usize;
    let mut routes = Vec::new();

    while offset < payload.len() {
        let ip_version = *payload.get(offset).ok_or_else(|| {
            MasqueError::ConnectionError("truncated RouteAdvertisement capsule".into())
        })?;
        offset += 1;

        let route = match ip_version {
            4 => {
                let start = payload.get(offset..offset + 4).ok_or_else(|| {
                    MasqueError::ConnectionError("truncated RouteAdvertisement IPv4".into())
                })?;
                offset += 4;
                let end = payload.get(offset..offset + 4).ok_or_else(|| {
                    MasqueError::ConnectionError("truncated RouteAdvertisement IPv4".into())
                })?;
                offset += 4;
                let ip_proto = *payload.get(offset).ok_or_else(|| {
                    MasqueError::ConnectionError("missing RouteAdvertisement IPv4 protocol".into())
                })?;
                offset += 1;
                format!(
                    "{}-{} proto={}",
                    IpAddr::from([start[0], start[1], start[2], start[3]]),
                    IpAddr::from([end[0], end[1], end[2], end[3]]),
                    ip_proto
                )
            }
            6 => {
                let start = payload.get(offset..offset + 16).ok_or_else(|| {
                    MasqueError::ConnectionError("truncated RouteAdvertisement IPv6".into())
                })?;
                offset += 16;
                let end = payload.get(offset..offset + 16).ok_or_else(|| {
                    MasqueError::ConnectionError("truncated RouteAdvertisement IPv6".into())
                })?;
                offset += 16;
                let ip_proto = *payload.get(offset).ok_or_else(|| {
                    MasqueError::ConnectionError("missing RouteAdvertisement IPv6 protocol".into())
                })?;
                offset += 1;
                let mut start_bytes = [0u8; 16];
                start_bytes.copy_from_slice(start);
                let mut end_bytes = [0u8; 16];
                end_bytes.copy_from_slice(end);
                format!(
                    "{}-{} proto={}",
                    IpAddr::from(start_bytes),
                    IpAddr::from(end_bytes),
                    ip_proto
                )
            }
            other => {
                return Err(MasqueError::ConnectionError(format!(
                    "invalid RouteAdvertisement IP version: {}",
                    other
                )));
            }
        };

        routes.push(route);
    }

    Ok(routes)
}

// IPv4 header length
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

// ICMP constants
const ICMP_DEST_UNREACHABLE: u8 = 3;
const ICMP_CODE_FRAG_NEEDED: u8 = 4;
const ICMPV6_PACKET_TOO_BIG: u8 = 2;

// Minimum MTU for ICMP Packet Too Big
const MIN_MTU: u16 = 1280;

// Process outgoing IP packet: decrement TTL/Hop Limit, recalculate checksum
// Returns false if packet should be dropped
fn process_outgoing_ip_packet(packet: &mut [u8]) -> Result<bool, MasqueError> {
    if packet.is_empty() {
        return Ok(false);
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            if packet.len() < IPV4_HEADER_LEN {
                return Ok(false);
            }
            // Check TTL (byte 8)
            let ttl = packet[8];
            if ttl <= 1 {
                log::trace!("dropped packet: TTL={}", ttl);
                return Ok(false);
            }
            // Decrement TTL
            packet[8] = ttl - 1;
            // Recalculate checksum
            let checksum = calculate_ipv4_checksum(&packet[..IPV4_HEADER_LEN]);
            packet[10] = (checksum >> 8) as u8;
            packet[11] = checksum as u8;
            Ok(true)
        }
        6 => {
            if packet.len() < IPV6_HEADER_LEN {
                return Ok(false);
            }
            // Check Hop Limit (byte 7)
            let hop_limit = packet[7];
            if hop_limit <= 1 {
                log::trace!("dropped packet: Hop Limit={}", hop_limit);
                return Ok(false);
            }
            // Decrement Hop Limit
            packet[7] = hop_limit - 1;
            Ok(true)
        }
        _ => {
            log::trace!("unknown IP version: {}", version);
            Ok(false)
        }
    }
}

// Calculate IPv4 header checksum
fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words, skipping checksum field (bytes 10-11)
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum += word;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

// Compose ICMP Packet Too Big message for the given original packet
// Returns a complete IP packet containing the ICMP message
pub fn compose_icmp_packet_too_big(original_packet: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if original_packet.is_empty() {
        return None;
    }

    let version = original_packet[0] >> 4;
    match version {
        4 => compose_icmpv4_packet_too_big(original_packet, mtu),
        6 => compose_icmpv6_packet_too_big(original_packet, mtu),
        _ => None,
    }
}

// Compose ICMPv4 Destination Unreachable (Fragmentation Needed) message
// ICMP Type 3, Code 4
fn compose_icmpv4_packet_too_big(original_packet: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if original_packet.len() < IPV4_HEADER_LEN {
        return None;
    }

    // Extract source and destination from original packet
    let orig_src = &original_packet[12..16];
    let orig_dst = &original_packet[16..20];

    // ICMP payload: original IP header + first 8 bytes of original data
    let icmp_payload_len = std::cmp::min(original_packet.len(), IPV4_HEADER_LEN + 8);
    let icmp_payload = &original_packet[..icmp_payload_len];

    // ICMP header: Type(1) + Code(1) + Checksum(2) + Unused(2) + Next-Hop MTU(2) = 8 bytes
    let icmp_len = 8 + icmp_payload_len;
    let total_len = IPV4_HEADER_LEN + icmp_len;

    let mut packet = vec![0u8; total_len];

    // Build IPv4 header
    packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    packet[1] = 0x00; // DSCP/ECN
    packet[2] = (total_len >> 8) as u8;
    packet[3] = total_len as u8;
    packet[4] = 0x00; // Identification
    packet[5] = 0x00;
    packet[6] = 0x00; // Flags + Fragment Offset
    packet[7] = 0x00;
    packet[8] = 64; // TTL
    packet[9] = 1; // Protocol: ICMP
    // Checksum at [10..12] - calculated later
    // Source: original destination (we are the "router" sending ICMP)
    packet[12..16].copy_from_slice(orig_dst);
    // Destination: original source
    packet[16..20].copy_from_slice(orig_src);

    // Calculate IPv4 header checksum
    let ip_checksum = calculate_ipv4_checksum(&packet[..IPV4_HEADER_LEN]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = ip_checksum as u8;

    // Build ICMP header
    let icmp_start = IPV4_HEADER_LEN;
    packet[icmp_start] = ICMP_DEST_UNREACHABLE; // Type 3
    packet[icmp_start + 1] = ICMP_CODE_FRAG_NEEDED; // Code 4
    // Checksum at [icmp_start + 2..4] - calculated later
    packet[icmp_start + 4] = 0x00; // Unused
    packet[icmp_start + 5] = 0x00;
    packet[icmp_start + 6] = (mtu >> 8) as u8; // Next-Hop MTU
    packet[icmp_start + 7] = mtu as u8;

    // Copy original packet data as ICMP payload
    packet[icmp_start + 8..].copy_from_slice(icmp_payload);

    // Calculate ICMP checksum
    let icmp_checksum = calculate_icmp_checksum(&packet[icmp_start..]);
    packet[icmp_start + 2] = (icmp_checksum >> 8) as u8;
    packet[icmp_start + 3] = icmp_checksum as u8;

    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(mut value: u64) -> Vec<u8> {
        if value < 64 {
            vec![value as u8]
        } else if value < 16384 {
            value |= 0x4000;
            value.to_be_bytes()[6..].to_vec()
        } else if value < 1073741824 {
            value |= 0x8000_0000;
            value.to_be_bytes()[4..].to_vec()
        } else {
            value |= 0xc000_0000_0000_0000;
            value.to_be_bytes().to_vec()
        }
    }

    fn build_capsule(capsule_type: u64, payload: &[u8]) -> Bytes {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode_varint(capsule_type));
        bytes.extend_from_slice(&encode_varint(payload.len() as u64));
        bytes.extend_from_slice(payload);
        Bytes::from(bytes)
    }

    #[test]
    fn parses_address_assign_capsule() {
        let payload = [0x00, 0x04, 10, 0, 0, 2, 32];
        let addresses = parse_address_assign_capsule(&payload).unwrap();
        assert_eq!(addresses, vec!["10.0.0.2/32"]);
    }

    #[test]
    fn parses_fragmented_control_capsules() {
        let mut control = MasqueControlState::default();
        let capsule = build_capsule(0x01, &[0x00, 0x04, 10, 0, 0, 2, 32]);
        let split = 3;
        control.recv_buf.extend_from_slice(&capsule[..split]);
        assert!(control.assigned_addresses.is_empty());
        control.recv_buf.extend_from_slice(&capsule[split..]);
        while let Some((capsule_type, capsule_type_len)) =
            try_decode_varint(control.recv_buf.as_ref())
        {
            let (capsule_len, capsule_len_len) =
                try_decode_varint(&control.recv_buf[capsule_type_len..]).unwrap();
            let frame_len = capsule_type_len + capsule_len_len + capsule_len as usize;
            let frame = control.recv_buf.split_to(frame_len);
            control
                .process_capsule(capsule_type, &frame[capsule_type_len + capsule_len_len..])
                .unwrap();
        }
        assert_eq!(control.assigned_addresses, ["10.0.0.2/32"]);
    }

    #[test]
    fn ignores_unknown_capsules() {
        let mut control = MasqueControlState::default();
        let capsule = build_capsule(0xdead, &[1, 2, 3]);
        control.recv_buf.extend_from_slice(&capsule);
        let (capsule_type, capsule_type_len) =
            try_decode_varint(control.recv_buf.as_ref()).unwrap();
        let (capsule_len, capsule_len_len) =
            try_decode_varint(&control.recv_buf[capsule_type_len..]).unwrap();
        let frame_len = capsule_type_len + capsule_len_len + capsule_len as usize;
        let frame = control.recv_buf.split_to(frame_len);
        control
            .process_capsule(capsule_type, &frame[capsule_type_len + capsule_len_len..])
            .unwrap();
        assert!(control.assigned_addresses.is_empty());
        assert!(control.advertised_routes.is_empty());
    }
}

// Compose ICMPv6 Packet Too Big message
// ICMPv6 Type 2, Code 0
fn compose_icmpv6_packet_too_big(original_packet: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if original_packet.len() < IPV6_HEADER_LEN {
        return None;
    }

    // Extract source and destination from original packet
    let orig_src = &original_packet[8..24];
    let orig_dst = &original_packet[24..40];

    // ICMPv6 payload: as much of the original packet as possible
    // without exceeding minimum IPv6 MTU (1280)
    let max_icmp_payload = 1280 - IPV6_HEADER_LEN - 8; // 8 = ICMPv6 header
    let icmp_payload_len = std::cmp::min(original_packet.len(), max_icmp_payload);
    let icmp_payload = &original_packet[..icmp_payload_len];

    // ICMPv6 header: Type(1) + Code(1) + Checksum(2) + MTU(4) = 8 bytes
    let icmp_len = 8 + icmp_payload_len;
    let total_len = IPV6_HEADER_LEN + icmp_len;

    let mut packet = vec![0u8; total_len];

    // Build IPv6 header
    packet[0] = 0x60; // Version 6
    packet[1] = 0x00; // Traffic Class / Flow Label
    packet[2] = 0x00;
    packet[3] = 0x00;
    // Payload length (ICMPv6 header + payload)
    packet[4] = (icmp_len >> 8) as u8;
    packet[5] = icmp_len as u8;
    packet[6] = 58; // Next Header: ICMPv6
    packet[7] = 64; // Hop Limit
    // Source: original destination
    packet[8..24].copy_from_slice(orig_dst);
    // Destination: original source
    packet[24..40].copy_from_slice(orig_src);

    // Build ICMPv6 header
    let icmp_start = IPV6_HEADER_LEN;
    packet[icmp_start] = ICMPV6_PACKET_TOO_BIG; // Type 2
    packet[icmp_start + 1] = 0; // Code 0
    // Checksum at [icmp_start + 2..4] - calculated later
    // MTU (4 bytes)
    packet[icmp_start + 4] = 0;
    packet[icmp_start + 5] = 0;
    packet[icmp_start + 6] = (mtu >> 8) as u8;
    packet[icmp_start + 7] = mtu as u8;

    // Copy original packet data as ICMPv6 payload
    packet[icmp_start + 8..].copy_from_slice(icmp_payload);

    // Calculate ICMPv6 checksum (includes pseudo-header)
    let checksum = calculate_icmpv6_checksum(
        &packet[8..24],  // source
        &packet[24..40], // destination
        &packet[icmp_start..],
    );
    packet[icmp_start + 2] = (checksum >> 8) as u8;
    packet[icmp_start + 3] = checksum as u8;

    Some(packet)
}

// Calculate ICMP checksum (same algorithm as IPv4 header checksum)
fn calculate_icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..data.len()).step_by(2) {
        if i == 2 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum += word;
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

// Calculate ICMPv6 checksum with pseudo-header
fn calculate_icmpv6_checksum(src: &[u8], dst: &[u8], icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source address
    for i in (0..16).step_by(2) {
        sum += ((src[i] as u32) << 8) | (src[i + 1] as u32);
    }

    // Pseudo-header: destination address
    for i in (0..16).step_by(2) {
        sum += ((dst[i] as u32) << 8) | (dst[i + 1] as u32);
    }

    // Pseudo-header: ICMPv6 length
    let len = icmp_data.len() as u32;
    sum += len >> 16;
    sum += len & 0xffff;

    // Pseudo-header: Next Header (58 for ICMPv6)
    sum += 58;

    // ICMPv6 data (skip checksum field at offset 2)
    for i in (0..icmp_data.len()).step_by(2) {
        if i == 2 {
            continue;
        }
        let word = if i + 1 < icmp_data.len() {
            ((icmp_data[i] as u32) << 8) | (icmp_data[i + 1] as u32)
        } else {
            (icmp_data[i] as u32) << 8
        };
        sum += word;
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}
