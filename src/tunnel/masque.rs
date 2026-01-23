use crate::tunnel::quic::{QuicConnection, QuicError};
use quiche::h3::NameValue;
use std::time::Duration;
use thiserror::Error;

// Context ID = 0 for IP packets (RFC 9484)
const CONTEXT_ID_ZERO: u8 = 0x00;

#[derive(Error, Debug)]
pub enum MasqueError {
    #[error("QUIC error: {0}")]
    QuicError(#[from] QuicError),
    #[error("HTTP/3 error: {0}")]
    H3Error(#[from] quiche::h3::Error),
    #[error("connection error: {0}")]
    ConnectionError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("connect-ip failed: {0}")]
    ConnectIpFailed(String),
    #[error("timeout")]
    Timeout,
}

pub struct MasqueTunnel {
    pub quic_conn: QuicConnection,
    pub h3_conn: Option<quiche::h3::Connection>,
    pub connect_stream_id: Option<u64>,
    pub established: bool,
}

impl MasqueTunnel {
    pub fn new(quic_conn: QuicConnection) -> Self {
        Self {
            quic_conn,
            h3_conn: None,
            connect_stream_id: None,
            established: false,
        }
    }

    pub fn init_h3(&mut self) -> Result<(), MasqueError> {
        let mut h3_config = quiche::h3::Config::new()?;

        // Note: Do NOT call enable_extended_connect(true) on client side.
        // Per RFC 9220, SETTINGS_ENABLE_CONNECT_PROTOCOL is sent by SERVER to indicate
        // it supports Extended CONNECT. Client should not send this setting.

        // Disable QPACK compression (like Go version's DisableCompression: true)
        h3_config.set_qpack_max_table_capacity(0);
        h3_config.set_qpack_blocked_streams(0);

        // quiche automatically sends SETTINGS_H3_DATAGRAM_00 (0x276) and
        // SETTINGS_H3_DATAGRAM (0x33) when the QUIC connection has datagrams enabled

        let h3_conn = quiche::h3::Connection::with_transport(
            &mut self.quic_conn.conn,
            &h3_config,
        )?;
        self.h3_conn = Some(h3_conn);
        Ok(())
    }

    pub fn send_connect_ip_request(&mut self) -> Result<u64, MasqueError> {
        let h3_conn = self.h3_conn.as_mut()
            .ok_or_else(|| MasqueError::ConnectionError("H3 not initialized".into()))?;

        // Cloudflare uses "cf-connect-ip" instead of standard "connect-ip"
        // Path is "/" not "/.well-known/masque/ip/*/*/" per official client qlog
        let headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
            quiche::h3::Header::new(b":path", b"/"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            quiche::h3::Header::new(b"user-agent", b""),
        ];

        let stream_id = h3_conn.send_request(
            &mut self.quic_conn.conn,
            &headers,
            false,
        )?;

        self.connect_stream_id = Some(stream_id);
        Ok(stream_id)
    }

    pub fn send_datagram(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, MasqueError> {
        let stream_id = self.connect_stream_id
            .ok_or_else(|| MasqueError::ConnectionError("No connect stream".into()))?;

        // Process IP packet (decrement TTL/Hop Limit, recalculate checksum)
        let mut packet = data.to_vec();
        if !process_outgoing_ip_packet(&mut packet)? {
            // Packet should be dropped (TTL too small, etc.)
            return Ok(None);
        }

        // Build HTTP/3 Datagram: [Quarter Stream ID (varint)] [Context ID (varint)] [IP Packet]
        let quarter_stream_id = stream_id / 4;
        let qsid_len = varint_len(quarter_stream_id);

        let mut buf = vec![0u8; qsid_len + 1 + packet.len()];
        let mut offset = encode_varint(quarter_stream_id, &mut buf);
        buf[offset] = CONTEXT_ID_ZERO;
        offset += 1;
        buf[offset..].copy_from_slice(&packet);

        // Check if datagram exceeds maximum writable length
        let max_dgram_len = self.quic_conn.conn.dgram_max_writable_len();
        if let Some(max_len) = max_dgram_len
            && buf.len() > max_len
        {
            log::debug!(
                "Datagram too large: {} bytes > max {} bytes, generating ICMP Packet Too Big",
                buf.len(),
                max_len
            );
            let icmp = compose_icmp_packet_too_big(&packet, MIN_MTU);
            return Ok(icmp);
        }

        match self.quic_conn.conn.dgram_send(&buf) {
            Ok(()) => Ok(None),
            Err(quiche::Error::BufferTooShort) => {
                log::debug!("dgram_send BufferTooShort ({} bytes), generating ICMP", buf.len());
                let icmp = compose_icmp_packet_too_big(&packet, MIN_MTU);
                Ok(icmp)
            }
            Err(e) => {
                log::warn!("dgram_send error: {:?}, buf len: {}", e, buf.len());
                Err(MasqueError::QuicError(QuicError::QuicError(e)))
            }
        }
    }

    /// Process QUIC data that has already been received.
    /// Call this after injecting data via quic_conn.conn.recv()
    pub fn poll_h3(&mut self) {
        if let Some(h3_conn) = self.h3_conn.as_mut() {
            loop {
                match h3_conn.poll(&mut self.quic_conn.conn) {
                    Ok((stream_id, event)) => {
                        log::trace!("H3 event on stream {}: {:?}", stream_id, event);
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        log::warn!("H3 poll error: {:?}", e);
                        break;
                    }
                }
            }
        }
    }

    pub fn recv_datagram(&mut self, buf: &mut [u8]) -> Result<usize, MasqueError> {
        let mut temp_buf = vec![0u8; buf.len() + 10]; // Extra space for headers

        match self.quic_conn.conn.dgram_recv(&mut temp_buf) {
            Ok(len) => {
                // Parse HTTP/3 Datagram: [Quarter Stream ID (varint)] [Context ID (varint)] [IP Packet]
                let (_, qsid_len) = decode_varint(&temp_buf[..len])?;
                let (context_id, ctx_len) = decode_varint(&temp_buf[qsid_len..len])?;

                // Only accept Context ID = 0 (IP packets)
                if context_id != 0 {
                    return Ok(0);
                }

                let header_len = qsid_len + ctx_len;
                let payload_len = len - header_len;

                if payload_len > buf.len() {
                    return Err(MasqueError::ConnectionError("Buffer too small".into()));
                }

                buf[..payload_len].copy_from_slice(&temp_buf[header_len..len]);
                Ok(payload_len)
            }
            Err(quiche::Error::Done) => Ok(0),
            Err(e) => Err(MasqueError::QuicError(QuicError::QuicError(e))),
        }
    }

    pub async fn establish(&mut self, timeout: Duration) -> Result<(), MasqueError> {
        log::debug!("Initializing HTTP/3 connection");
        self.init_h3()?;

        // Step 1: Send our SETTINGS frame
        let sent = self.quic_conn.send_async().await?;
        log::debug!("SETTINGS frame sent ({} bytes)", sent);

        let start = std::time::Instant::now();
        let mut buf = [0u8; 65535];

        // Step 2: Wait for peer's SETTINGS frame before sending CONNECT request
        log::debug!("Waiting for peer SETTINGS...");
        while !self.peer_settings_received() {
            if start.elapsed() > timeout {
                return Err(MasqueError::Timeout);
            }

            self.recv_and_process_async(&mut buf).await?;
            self.poll_h3_events()?;
            self.quic_conn.send_async().await?;

            if let Some(err) = self.quic_conn.conn.peer_error() {
                let reason = String::from_utf8_lossy(err.reason.as_slice());
                log::error!("Connection closed by peer: error={}, reason={}",
                    err.error_code, reason);
                return Err(MasqueError::ConnectionError(
                    format!("peer closed: {} - {}", err.error_code, reason)
                ));
            }

            if self.quic_conn.is_closed() {
                return Err(MasqueError::ConnectionError("connection closed".into()));
            }
        }
        log::debug!("Peer SETTINGS received");

        // Step 3: Send Connect-IP request
        log::debug!("Sending Connect-IP request");
        let stream_id = self.send_connect_ip_request()?;
        log::debug!("Connect-IP request sent on stream {}", stream_id);

        self.quic_conn.send_async().await?;

        // Step 4: Wait for Connect-IP response
        while !self.established {
            if start.elapsed() > timeout {
                return Err(MasqueError::Timeout);
            }

            self.recv_and_process_async(&mut buf).await?;

            if let Some(err) = self.quic_conn.conn.peer_error() {
                let reason = String::from_utf8_lossy(err.reason.as_slice());
                log::error!("Connection closed by peer: error={}, reason={}",
                    err.error_code, reason);
                return Err(MasqueError::ConnectionError(
                    format!("peer closed: {} - {}", err.error_code, reason)
                ));
            }

            self.poll_h3_events()?;
            self.quic_conn.send_async().await?;

            if self.quic_conn.is_closed() {
                return Err(MasqueError::ConnectionError("connection closed".into()));
            }
        }

        log::info!("MASQUE tunnel established");
        Ok(())
    }

    async fn recv_and_process_async(&mut self, buf: &mut [u8]) -> Result<(), MasqueError> {
        match tokio::time::timeout(
            Duration::from_millis(100),
            self.quic_conn.socket.recv_from(buf),
        ).await {
            Ok(Ok((len, from))) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: self.quic_conn.local_addr,
                };
                match self.quic_conn.conn.recv(&mut buf[..len], recv_info) {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("QUIC recv error: {:?}", e);
                        return Err(MasqueError::QuicError(QuicError::QuicError(e)));
                    }
                }
            }
            Ok(Err(e)) => return Err(MasqueError::IoError(e)),
            Err(_) => {} // timeout, continue
        }
        Ok(())
    }

    fn peer_settings_received(&self) -> bool {
        if let Some(h3_conn) = &self.h3_conn {
            h3_conn.peer_settings_raw().is_some()
        } else {
            false
        }
    }

    fn poll_h3_events(&mut self) -> Result<(), MasqueError> {
        let h3_conn = match self.h3_conn.as_mut() {
            Some(c) => c,
            None => return Ok(()),
        };

        loop {
            match h3_conn.poll(&mut self.quic_conn.conn) {
                Ok((stream_id, event)) => {
                    log::debug!("H3 event on stream {}: {:?}", stream_id, event);
                    match event {
                        quiche::h3::Event::Headers { list, .. } => {
                            log::debug!("H3 headers on stream {}: {:?}", stream_id, list);
                            if Some(stream_id) == self.connect_stream_id {
                                for header in &list {
                                    if header.name() == b":status" {
                                        let status = std::str::from_utf8(header.value())
                                            .unwrap_or("unknown");
                                        log::info!("Connect-IP response status: {}", status);
                                        if status == "200" {
                                            self.established = true;
                                            log::info!("Connect-IP request accepted");
                                        } else {
                                            return Err(MasqueError::ConnectIpFailed(
                                                format!("status: {}", status)
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        quiche::h3::Event::Data => {
                            log::debug!("H3 data on stream {}", stream_id);
                        }
                        quiche::h3::Event::Finished => {}
                        quiche::h3::Event::Reset(_) => {}
                        quiche::h3::Event::PriorityUpdate => {}
                        quiche::h3::Event::GoAway => {
                            return Err(MasqueError::ConnectionError("received GOAWAY".into()));
                        }
                    }
                }
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    log::error!("H3 poll error: {:?}", e);
                    return Err(MasqueError::H3Error(e));
                }
            }
        }

        Ok(())
    }
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

fn encode_varint(value: u64, buf: &mut [u8]) -> usize {
    if value < 64 {
        buf[0] = value as u8;
        1
    } else if value < 16384 {
        buf[0] = ((value >> 8) as u8) | 0x40;
        buf[1] = value as u8;
        2
    } else if value < 1073741824 {
        buf[0] = ((value >> 24) as u8) | 0x80;
        buf[1] = (value >> 16) as u8;
        buf[2] = (value >> 8) as u8;
        buf[3] = value as u8;
        4
    } else {
        buf[0] = ((value >> 56) as u8) | 0xc0;
        buf[1] = (value >> 48) as u8;
        buf[2] = (value >> 40) as u8;
        buf[3] = (value >> 32) as u8;
        buf[4] = (value >> 24) as u8;
        buf[5] = (value >> 16) as u8;
        buf[6] = (value >> 8) as u8;
        buf[7] = value as u8;
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
                log::debug!("Dropping packet: TTL too small ({})", ttl);
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
                log::debug!("Dropping packet: Hop Limit too small ({})", hop_limit);
                return Ok(false);
            }
            // Decrement Hop Limit
            packet[7] = hop_limit - 1;
            Ok(true)
        }
        _ => {
            log::debug!("Unknown IP version: {}", version);
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
        &packet[8..24],   // source
        &packet[24..40],  // destination
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
