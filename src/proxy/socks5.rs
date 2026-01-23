use crate::tunnel::manager::{SocketChannels, TunnelManager};
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

static LOCAL_PORT_COUNTER: AtomicU16 = AtomicU16::new(40000);

#[derive(Error, Debug)]
pub enum Socks5Error {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("tunnel error: {0}")]
    TunnelError(String),
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("timeout")]
    Timeout,
    #[error("channel error: {0}")]
    ChannelError(String),
}

#[derive(Debug, Clone)]
struct TargetAddress {
    ip: IpAddress,
    port: u16,
}

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;

pub struct Socks5Server {
    bind_addr: SocketAddr,
    manager: Arc<TunnelManager>,
}

impl Socks5Server {
    pub fn new(bind_addr: SocketAddr, manager: Arc<TunnelManager>) -> Self {
        Self { bind_addr, manager }
    }

    pub async fn run(&self) -> Result<(), Socks5Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("SOCKS5 server listening on {}", self.bind_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("New connection from {}", addr);

            let manager = self.manager.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, manager).await {
                    log::error!("Error handling client {}: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    manager: Arc<TunnelManager>,
) -> Result<(), Socks5Error> {
    // Read version and auth methods
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    if buf[0] != SOCKS5_VERSION {
        return Err(Socks5Error::ProtocolError("Invalid SOCKS version".into()));
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // Send auth response (no auth required)
    stream.write_all(&[SOCKS5_VERSION, AUTH_NO_AUTH]).await?;

    // Read connect request
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS5_VERSION || header[1] != CMD_CONNECT {
        return Err(Socks5Error::ProtocolError("Unsupported command".into()));
    }

    let target = read_address(&mut stream, header[3]).await?;
    log::debug!("Connect request to {:?}:{}", target.ip, target.port);

    // Create TCP connection through the manager
    let local_port = LOCAL_PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let channels = manager
        .connect(target.ip, target.port, local_port)
        .await
        .map_err(|e| Socks5Error::ConnectionFailed(e))?;

    // Wait for connection to establish
    let connected = wait_for_connection(&channels, Duration::from_secs(30)).await?;
    if !connected {
        manager.close(channels.handle).await;
        send_error_response(&mut stream, REP_GENERAL_FAILURE).await?;
        return Err(Socks5Error::Timeout);
    }

    // Send success response
    let response = [
        SOCKS5_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4,
        0, 0, 0, 0, 0, 0,
    ];
    stream.write_all(&response).await?;

    // Forward data bidirectionally
    let handle = channels.handle;
    forward_data(stream, channels).await?;

    // Cleanup
    manager.close(handle).await;

    Ok(())
}

async fn read_address(stream: &mut TcpStream, atyp: u8) -> Result<TargetAddress, Socks5Error> {
    match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            Ok(TargetAddress {
                ip: IpAddress::Ipv4(Ipv4Address::new(addr[0], addr[1], addr[2], addr[3])),
                port,
            })
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let _port = u16::from_be_bytes(port);
            let domain_str = String::from_utf8_lossy(&domain);
            Err(Socks5Error::ProtocolError(format!(
                "Domain names not yet supported: {}",
                domain_str
            )))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            Ok(TargetAddress {
                ip: IpAddress::Ipv6(Ipv6Address::new(
                    u16::from_be_bytes([addr[0], addr[1]]),
                    u16::from_be_bytes([addr[2], addr[3]]),
                    u16::from_be_bytes([addr[4], addr[5]]),
                    u16::from_be_bytes([addr[6], addr[7]]),
                    u16::from_be_bytes([addr[8], addr[9]]),
                    u16::from_be_bytes([addr[10], addr[11]]),
                    u16::from_be_bytes([addr[12], addr[13]]),
                    u16::from_be_bytes([addr[14], addr[15]]),
                )),
                port,
            })
        }
        _ => Err(Socks5Error::ProtocolError("Unknown address type".into())),
    }
}

async fn wait_for_connection(
    _channels: &SocketChannels,
    _timeout: Duration,
) -> Result<bool, Socks5Error> {
    // In the new architecture, connection establishment is handled by the manager
    // We just wait a bit for the TCP handshake to complete
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(true)
}

async fn send_error_response(stream: &mut TcpStream, rep: u8) -> Result<(), Socks5Error> {
    let response = [
        SOCKS5_VERSION, rep, 0x00, ATYP_IPV4,
        0, 0, 0, 0, 0, 0,
    ];
    stream.write_all(&response).await?;
    Ok(())
}

async fn forward_data(
    mut stream: TcpStream,
    mut channels: SocketChannels,
) -> Result<(), Socks5Error> {
    let (mut reader, mut writer) = stream.split();
    let mut client_buf = [0u8; 65535];

    loop {
        tokio::select! {
            // Receive data from tunnel, send to client
            result = channels.from_stack.recv() => {
                match result {
                    Some(data) => {
                        if let Err(e) = writer.write_all(&data).await {
                            log::debug!("Error writing to client: {}", e);
                            break;
                        }
                    }
                    None => {
                        log::debug!("Tunnel channel closed");
                        break;
                    }
                }
            }

            // Receive data from client, send to tunnel
            result = reader.read(&mut client_buf) => {
                match result {
                    Ok(0) => {
                        log::debug!("Client closed connection");
                        break;
                    }
                    Ok(n) => {
                        if channels.to_stack.send(client_buf[..n].to_vec()).await.is_err() {
                            log::debug!("Tunnel channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        log::debug!("Error reading from client: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
