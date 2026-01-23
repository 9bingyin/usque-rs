use crate::tunnel::quic::{QuicConnection, QuicError};
use quiche::h3::NameValue;
use std::time::Duration;
use thiserror::Error;

pub const CONNECT_URI: &str = "https://cloudflareaccess.com";

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

    pub fn send_datagram(&mut self, data: &[u8]) -> Result<(), MasqueError> {
        let stream_id = self.connect_stream_id
            .ok_or_else(|| MasqueError::ConnectionError("No connect stream".into()))?;

        // Process IP packet (decrement TTL/Hop Limit, recalculate checksum)
        let mut packet = data.to_vec();
        if !process_outgoing_ip_packet(&mut packet)? {
            // Packet should be dropped (TTL too small, etc.)
            return Ok(());
        }

        // Build HTTP/3 Datagram: [Quarter Stream ID (varint)] [Context ID (varint)] [IP Packet]
        let quarter_stream_id = stream_id / 4;
        let qsid_len = varint_len(quarter_stream_id);

        let mut buf = vec![0u8; qsid_len + 1 + packet.len()];
        let mut offset = encode_varint(quarter_stream_id, &mut buf);
        buf[offset] = CONTEXT_ID_ZERO;
        offset += 1;
        buf[offset..].copy_from_slice(&packet);

        self.quic_conn.conn.dgram_send(&buf)
            .map_err(|e| MasqueError::QuicError(QuicError::QuicError(e)))?;
        Ok(())
    }

    /// Process incoming QUIC packets from the socket.
    /// This must be called regularly to receive data from the network.
    pub fn process_quic(&mut self) -> Result<(), MasqueError> {
        let mut buf = [0u8; 65535];

        // Receive from socket and process QUIC
        loop {
            match self.quic_conn.socket.recv(&mut buf) {
                Ok(len) => {
                    let recv_info = quiche::RecvInfo {
                        from: self.quic_conn.peer_addr,
                        to: self.quic_conn.socket.local_addr()?,
                    };
                    if let Err(e) = self.quic_conn.conn.recv(&mut buf[..len], recv_info) {
                        log::warn!("QUIC recv error: {:?}", e);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(MasqueError::IoError(e)),
            }
        }

        // Process H3 events (for datagrams)
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

        Ok(())
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

    pub fn establish(&mut self, timeout: Duration) -> Result<(), MasqueError> {
        log::debug!("Initializing HTTP/3 connection");
        self.init_h3()?;

        // Step 1: Send our SETTINGS frame
        let sent = self.quic_conn.send()?;
        log::debug!("SETTINGS frame sent ({} bytes)", sent);

        let start = std::time::Instant::now();
        let mut buf = [0u8; 65535];

        // Step 2: Wait for peer's SETTINGS frame before sending CONNECT request
        log::debug!("Waiting for peer SETTINGS...");
        while !self.peer_settings_received() {
            if start.elapsed() > timeout {
                return Err(MasqueError::Timeout);
            }

            self.recv_and_process(&mut buf)?;
            self.poll_h3_events()?;
            self.quic_conn.send()?;

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

        self.quic_conn.send()?;

        // Step 4: Wait for Connect-IP response
        while !self.established {
            if start.elapsed() > timeout {
                return Err(MasqueError::Timeout);
            }

            self.recv_and_process(&mut buf)?;

            if let Some(err) = self.quic_conn.conn.peer_error() {
                let reason = String::from_utf8_lossy(err.reason.as_slice());
                log::error!("Connection closed by peer: error={}, reason={}",
                    err.error_code, reason);
                return Err(MasqueError::ConnectionError(
                    format!("peer closed: {} - {}", err.error_code, reason)
                ));
            }

            self.poll_h3_events()?;
            self.quic_conn.send()?;

            if self.quic_conn.is_closed() {
                return Err(MasqueError::ConnectionError("connection closed".into()));
            }
        }

        log::info!("MASQUE tunnel established");
        Ok(())
    }

    fn recv_and_process(&mut self, buf: &mut [u8]) -> Result<(), MasqueError> {
        match self.quic_conn.socket.recv(buf) {
            Ok(len) => {
                let recv_info = quiche::RecvInfo {
                    from: self.quic_conn.peer_addr,
                    to: self.quic_conn.socket.local_addr()?,
                };
                match self.quic_conn.conn.recv(&mut buf[..len], recv_info) {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("QUIC recv error: {:?}", e);
                        return Err(MasqueError::QuicError(QuicError::QuicError(e)));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(MasqueError::IoError(e)),
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
        2 => {
            let v = ((buf[0] & 0x3f) as u64) << 8 | buf[1] as u64;
            v
        }
        4 => {
            let v = ((buf[0] & 0x3f) as u64) << 24
                | (buf[1] as u64) << 16
                | (buf[2] as u64) << 8
                | buf[3] as u64;
            v
        }
        8 => {
            let v = ((buf[0] & 0x3f) as u64) << 56
                | (buf[1] as u64) << 48
                | (buf[2] as u64) << 40
                | (buf[3] as u64) << 32
                | (buf[4] as u64) << 24
                | (buf[5] as u64) << 16
                | (buf[6] as u64) << 8
                | buf[7] as u64;
            v
        }
        _ => unreachable!(),
    };

    Ok((value, len))
}

// IPv4 header length
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

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
