use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use thiserror::Error;

// Re-export RecordType for use in manager.rs
pub use hickory_proto::rr::RecordType as DnsRecordType;

// DNS constants
const DNS_PORT: u16 = 53;
const DNS_SERVER_V4: Ipv4Address = Ipv4Address::new(1, 1, 1, 1); // Cloudflare DNS

static DNS_TRANSACTION_ID: AtomicU16 = AtomicU16::new(1);
static DNS_LOCAL_PORT: AtomicU16 = AtomicU16::new(50000);

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("query failed: {0}")]
    QueryFailed(String),
    #[error("timeout")]
    Timeout,
    #[error("no records found")]
    NoRecords,
    #[error("invalid response")]
    InvalidResponse,
    #[error("channel error")]
    ChannelError,
    #[error("encode error: {0}")]
    EncodeError(String),
    #[error("decode error: {0}")]
    DecodeError(String),
}

/// Build a DNS query packet using hickory-proto
pub fn build_dns_query(domain: &str, record_type: RecordType) -> Result<(u16, Vec<u8>), DnsError> {
    let transaction_id = DNS_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);

    let name = Name::from_str(domain)
        .map_err(|e| DnsError::EncodeError(format!("invalid domain: {}", e)))?;

    let mut message = Message::new();
    message.set_id(transaction_id);
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);

    let query = Query::query(name, record_type);
    message.add_query(query);

    let bytes = message
        .to_bytes()
        .map_err(|e| DnsError::EncodeError(format!("{}", e)))?;

    Ok((transaction_id, bytes.to_vec()))
}

/// Parse DNS response and extract IP addresses using hickory-proto
pub fn parse_dns_response(data: &[u8], expected_id: u16) -> Result<Vec<IpAddress>, DnsError> {
    let message = Message::from_bytes(data)
        .map_err(|e| DnsError::DecodeError(format!("{}", e)))?;

    // Check transaction ID
    if message.id() != expected_id {
        return Err(DnsError::InvalidResponse);
    }

    // Check if it's a response
    if message.message_type() != MessageType::Response {
        return Err(DnsError::InvalidResponse);
    }

    // Check response code
    if message.response_code() != hickory_proto::op::ResponseCode::NoError {
        return Err(DnsError::QueryFailed(format!(
            "RCODE: {:?}",
            message.response_code()
        )));
    }

    let mut addresses = Vec::new();

    for answer in message.answers() {
        match answer.data() {
            RData::A(a) => {
                let octets = a.0.octets();
                addresses.push(IpAddress::Ipv4(Ipv4Address::new(
                    octets[0], octets[1], octets[2], octets[3],
                )));
            }
            RData::AAAA(aaaa) => {
                let segments = aaaa.0.segments();
                addresses.push(IpAddress::Ipv6(Ipv6Address::new(
                    segments[0], segments[1], segments[2], segments[3],
                    segments[4], segments[5], segments[6], segments[7],
                )));
            }
            // CNAME records are automatically followed by the DNS server
            // Other record types are ignored for IP resolution
            _ => {}
        }
    }

    if addresses.is_empty() {
        Err(DnsError::NoRecords)
    } else {
        Ok(addresses)
    }
}

pub fn get_dns_local_port() -> u16 {
    DNS_LOCAL_PORT.fetch_add(1, Ordering::Relaxed)
}

pub fn dns_server() -> IpAddress {
    IpAddress::Ipv4(DNS_SERVER_V4)
}

pub fn dns_port() -> u16 {
    DNS_PORT
}
