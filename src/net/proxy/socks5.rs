use crate::net::tunnel::manager::ManagerError;
use bytes::Bytes;
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

pub mod resolve;
pub mod server;
pub mod tcp;
pub mod udp;

pub use server::Socks5Server;

static LOCAL_PORT_COUNTER: AtomicU16 = AtomicU16::new(0);

const PORT_RANGE_START: u16 = 49152;
const PORT_RANGE_SIZE: u16 = 16384; // 65536 - 49152 (RFC 6335)
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 1024;
const TCP_READ_BUFFER_SIZE: usize = 64 * 1024;
const UDP_FRAG_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_FRAG_MAX_COUNT: usize = 128;

/// Convert std IpAddr to smoltcp IpAddress, unwrapping IPv4-mapped IPv6
/// (e.g. ::ffff:104.26.12.31) to native IPv4.
fn std_ip_to_smoltcp(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3]))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                let o = v4.octets();
                IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3]))
            } else {
                let s = v6.segments();
                IpAddress::Ipv6(Ipv6Address::new(
                    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                ))
            }
        }
    }
}

// RFC 8305 Happy Eyeballs parameters
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

// RFC 8305 Section 4: Interleave addresses (IPv6, IPv4, IPv6, IPv4, ...)
// In-place sorting to avoid extra allocations
fn interleave_addresses(mut addresses: Vec<IpAddress>) -> Vec<IpAddress> {
    if addresses.len() <= 1 {
        return addresses;
    }

    // Count IPv6 addresses
    let v6_count = addresses
        .iter()
        .filter(|ip| matches!(ip, IpAddress::Ipv6(_)))
        .count();
    let v4_count = addresses.len() - v6_count;

    // If all same type, no interleaving needed
    if v6_count == 0 || v4_count == 0 {
        return addresses;
    }

    // Partition: move all IPv6 to front, IPv4 to back (stable partition)
    addresses.sort_by_key(|ip| matches!(ip, IpAddress::Ipv4(_)));

    // Now addresses = [v6_0, v6_1, ..., v4_0, v4_1, ...]
    // Interleave in-place using a simple algorithm
    let mut result = Vec::with_capacity(addresses.len());
    let mut v6_idx = 0;
    let mut v4_idx = v6_count;

    while v6_idx < v6_count || v4_idx < addresses.len() {
        if v6_idx < v6_count {
            result.push(addresses[v6_idx]);
            v6_idx += 1;
        }
        if v4_idx < addresses.len() {
            result.push(addresses[v4_idx]);
            v4_idx += 1;
        }
    }
    result
}

struct FragBuffer {
    fragments: Vec<Option<Bytes>>,
    highest_seq: u8,
    end_seq: Option<u8>,
    last_update: Instant,
}

impl FragBuffer {
    fn new(now: Instant) -> Self {
        Self {
            fragments: vec![None; UDP_FRAG_MAX_COUNT],
            highest_seq: 0,
            end_seq: None,
            last_update: now,
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_update) > UDP_FRAG_TIMEOUT
    }

    fn reset(&mut self, now: Instant) {
        self.fragments.fill(None);
        self.highest_seq = 0;
        self.end_seq = None;
        self.last_update = now;
    }

    fn insert(&mut self, seq: u8, is_last: bool, data: Bytes, now: Instant) -> Option<Bytes> {
        if seq == 0 || seq as usize >= self.fragments.len() {
            return None;
        }

        if let Some(end_seq) = self.end_seq
            && seq > end_seq
        {
            self.reset(now);
        }

        if seq < self.highest_seq {
            self.reset(now);
        }

        self.last_update = now;
        if self.fragments[seq as usize].is_none() {
            self.fragments[seq as usize] = Some(data);
        }

        if seq > self.highest_seq {
            self.highest_seq = seq;
        }

        if is_last {
            self.end_seq = Some(seq);
        }

        let end_seq = self.end_seq?;
        for idx in 1..=end_seq {
            self.fragments[idx as usize].as_ref()?;
        }

        let total_len: usize = (1..=end_seq)
            .map(|idx| {
                self.fragments[idx as usize]
                    .as_ref()
                    .map(|b| b.len())
                    .unwrap_or(0)
            })
            .sum();
        let mut merged = bytes::BytesMut::with_capacity(total_len);
        for idx in 1..=end_seq {
            if let Some(chunk) = self.fragments[idx as usize].as_ref() {
                merged.extend_from_slice(chunk);
            }
        }
        Some(merged.freeze())
    }
}

fn get_local_port() -> u16 {
    let offset = LOCAL_PORT_COUNTER.fetch_add(1, Ordering::Relaxed) % PORT_RANGE_SIZE;
    PORT_RANGE_START + offset
}

fn max_concurrent_connections() -> usize {
    std::env::var("USQUE_MAX_CONNECTIONS")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .filter(|val| *val > 0)
        .unwrap_or(DEFAULT_MAX_CONCURRENT_CONNECTIONS)
}

#[derive(Error, Debug)]
pub enum Socks5Error {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("timeout")]
    Timeout,
    #[error("channel error: {0}")]
    ChannelError(String),
    #[error("tunnel error: {0}")]
    TunnelError(#[from] ManagerError),
    #[error("socks error: {0}")]
    SocksError(#[from] fast_socks5::SocksError),
    #[error("socks server error: {0}")]
    SocksServerError(#[from] fast_socks5::server::SocksServerError),
}

/// Authentication configuration for SOCKS5 server
#[derive(Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

fn cleanup_fragments(
    frag_buffers: &mut HashMap<fast_socks5::util::target_addr::TargetAddr, FragBuffer>,
) {
    let now = Instant::now();
    frag_buffers.retain(|_, buffer| !buffer.is_expired(now));
}

fn map_manager_error_to_reply(err: &ManagerError) -> fast_socks5::ReplyError {
    match err {
        ManagerError::NotConnected => fast_socks5::ReplyError::GeneralFailure,
        ManagerError::Dns(_) => fast_socks5::ReplyError::HostUnreachable,
        ManagerError::Stack(_) => fast_socks5::ReplyError::GeneralFailure,
        ManagerError::ChannelClosed => fast_socks5::ReplyError::GeneralFailure,
        ManagerError::ResponseChannelClosed => fast_socks5::ReplyError::GeneralFailure,
    }
}

fn map_connect_error_to_reply(err: &Socks5Error) -> fast_socks5::ReplyError {
    match err {
        Socks5Error::Timeout => fast_socks5::ReplyError::ConnectionTimeout,
        Socks5Error::ConnectionFailed(_) => fast_socks5::ReplyError::HostUnreachable,
        Socks5Error::TunnelError(inner) => map_manager_error_to_reply(inner),
        _ => fast_socks5::ReplyError::GeneralFailure,
    }
}

/// Format TargetAddr for logging, converting IPv4-mapped IPv6 to IPv4
fn format_target_addr(target: &fast_socks5::util::target_addr::TargetAddr) -> String {
    use fast_socks5::util::target_addr::TargetAddr;
    match target {
        TargetAddr::Ip(addr) => {
            let ip = match addr.ip() {
                IpAddr::V6(v6) => {
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        IpAddr::V4(v4)
                    } else {
                        IpAddr::V6(v6)
                    }
                }
                ip => ip,
            };
            format!("{}:{}", ip, addr.port())
        }
        TargetAddr::Domain(domain, port) => format!("{}:{}", domain, port),
    }
}

/// Format smoltcp IpAddress for logging (IPv6 uses bracket notation)
fn format_ip_addr(ip: IpAddress) -> String {
    match ip {
        IpAddress::Ipv4(v4) => format!("{}", v4),
        IpAddress::Ipv6(v6) => format!("[{}]", v6),
    }
}
