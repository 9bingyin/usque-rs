use crate::tunnel::manager::{ManagerCommand, SocketChannels, TunnelManager};
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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
    ip: Option<IpAddress>,
    domain: Option<String>,
    port: u16,
}

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

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

    if header[0] != SOCKS5_VERSION {
        return Err(Socks5Error::ProtocolError("Invalid SOCKS version".into()));
    }

    let cmd = header[1];
    let target = read_address(&mut stream, header[3]).await?;

    match cmd {
        CMD_CONNECT => {
            handle_tcp_connect(stream, manager, target).await
        }
        CMD_UDP_ASSOCIATE => {
            handle_udp_associate(stream, manager).await
        }
        _ => {
            send_error_response(&mut stream, REP_CMD_NOT_SUPPORTED).await?;
            Err(Socks5Error::ProtocolError("Unsupported command".into()))
        }
    }
}

async fn handle_tcp_connect(
    mut stream: TcpStream,
    manager: Arc<TunnelManager>,
    target: TargetAddress,
) -> Result<(), Socks5Error> {
    // Resolve domain name if needed (through tunnel to prevent DNS leak)
    let remote_ip = if let Some(ip) = target.ip {
        log::debug!("Connect request to {:?}:{}", ip, target.port);
        ip
    } else if let Some(ref domain) = target.domain {
        log::debug!("Connect request to {}:{}, resolving DNS through tunnel", domain, target.port);
        match manager.resolve(domain, false).await {
            Ok(ip) => {
                log::debug!("DNS resolved {} -> {:?}", domain, ip);
                ip
            }
            Err(e) => {
                log::error!("DNS resolution failed for {}: {:?}", domain, e);
                send_error_response(&mut stream, REP_GENERAL_FAILURE).await?;
                return Err(Socks5Error::ProtocolError(format!(
                    "DNS resolution failed: {:?}",
                    e
                )));
            }
        }
    } else {
        return Err(Socks5Error::ProtocolError("No address provided".into()));
    };

    // Create TCP connection through the manager
    let local_port = LOCAL_PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let channels = manager
        .connect(remote_ip, target.port, local_port)
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

async fn handle_udp_associate(
    mut stream: TcpStream,
    manager: Arc<TunnelManager>,
) -> Result<(), Socks5Error> {
    // Get local address for UDP relay
    let local_addr = stream.local_addr()?;

    // Bind UDP socket for client communication
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let udp_addr = udp_socket.local_addr()?;

    log::debug!("UDP ASSOCIATE: relay socket bound to {}", udp_addr);

    // Register UDP session with manager
    let local_port = LOCAL_PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    manager.cmd_sender()
        .send(ManagerCommand::UdpRegister {
            local_port,
            response: response_tx,
        })
        .await
        .map_err(|_| Socks5Error::ChannelError("Failed to register UDP session".into()))?;

    let mut from_tunnel = response_rx
        .await
        .map_err(|_| Socks5Error::ChannelError("Failed to get UDP receiver".into()))?;

    // Send success response with UDP relay address
    let response = build_udp_response(local_addr.ip(), udp_addr.port());
    stream.write_all(&response).await?;

    // Forward UDP data bidirectionally
    let cmd_sender = manager.cmd_sender();
    let result = forward_udp_data(
        stream,
        udp_socket,
        &mut from_tunnel,
        cmd_sender,
        local_port,
    ).await;

    // Cleanup: unregister UDP session
    let _ = manager.cmd_sender()
        .send(ManagerCommand::UdpUnregister { local_port })
        .await;

    result
}

fn build_udp_response(ip: std::net::IpAddr, port: u16) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            let port_bytes = port.to_be_bytes();
            vec![
                SOCKS5_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4,
                octets[0], octets[1], octets[2], octets[3],
                port_bytes[0], port_bytes[1],
            ]
        }
        std::net::IpAddr::V6(v6) => {
            let octets = v6.octets();
            let port_bytes = port.to_be_bytes();
            let mut response = vec![SOCKS5_VERSION, REP_SUCCESS, 0x00, ATYP_IPV6];
            response.extend_from_slice(&octets);
            response.extend_from_slice(&port_bytes);
            response
        }
    }
}

async fn forward_udp_data(
    mut tcp_stream: TcpStream,
    udp_socket: UdpSocket,
    from_tunnel: &mut tokio::sync::mpsc::Receiver<(IpAddress, u16, Vec<u8>)>,
    cmd_sender: tokio::sync::mpsc::Sender<ManagerCommand>,
    local_port: u16,
) -> Result<(), Socks5Error> {
    let mut buf = [0u8; 65535];
    let mut tcp_buf = [0u8; 1];
    let mut client_addr: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            // Check if TCP control connection is closed
            result = tcp_stream.read(&mut tcp_buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        log::debug!("UDP ASSOCIATE: TCP control connection closed");
                        break;
                    }
                    Ok(_) => {}
                }
            }

            // Receive UDP from client, forward to tunnel
            result = udp_socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        client_addr = Some(addr);
                        if let Some((remote_ip, remote_port, data)) = parse_udp_request(&buf[..len]) {
                            let _ = cmd_sender.send(ManagerCommand::UdpSend {
                                remote_ip,
                                remote_port,
                                local_port,
                                data,
                            }).await;
                        }
                    }
                    Err(e) => {
                        log::warn!("UDP recv error: {}", e);
                    }
                }
            }

            // Receive UDP from tunnel, forward to client
            Some((remote_ip, remote_port, data)) = from_tunnel.recv() => {
                if let Some(addr) = client_addr {
                    let packet = build_udp_packet(remote_ip, remote_port, &data);
                    let _ = udp_socket.send_to(&packet, addr).await;
                }
            }
        }
    }

    Ok(())
}

fn parse_udp_request(data: &[u8]) -> Option<(IpAddress, u16, Vec<u8>)> {
    if data.len() < 10 {
        return None;
    }

    // RSV (2 bytes) + FRAG (1 byte) + ATYP (1 byte)
    let frag = data[2];
    if frag != 0 {
        log::debug!("UDP fragmentation not supported");
        return None;
    }

    let atyp = data[3];
    let (addr, port, payload_start) = match atyp {
        ATYP_IPV4 => {
            if data.len() < 10 {
                return None;
            }
            let ip = IpAddress::Ipv4(Ipv4Address::new(data[4], data[5], data[6], data[7]));
            let port = u16::from_be_bytes([data[8], data[9]]);
            (ip, port, 10)
        }
        ATYP_DOMAIN => {
            let domain_len = data[4] as usize;
            if data.len() < 7 + domain_len {
                return None;
            }
            // For domain, we would need DNS resolution - skip for now
            log::warn!("UDP domain address not supported yet");
            return None;
        }
        ATYP_IPV6 => {
            if data.len() < 22 {
                return None;
            }
            let ip = IpAddress::Ipv6(Ipv6Address::new(
                u16::from_be_bytes([data[4], data[5]]),
                u16::from_be_bytes([data[6], data[7]]),
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]]),
                u16::from_be_bytes([data[16], data[17]]),
                u16::from_be_bytes([data[18], data[19]]),
            ));
            let port = u16::from_be_bytes([data[20], data[21]]);
            (ip, port, 22)
        }
        _ => return None,
    };

    Some((addr, port, data[payload_start..].to_vec()))
}

fn build_udp_packet(remote_ip: IpAddress, remote_port: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0]; // RSV + FRAG

    match remote_ip {
        IpAddress::Ipv4(v4) => {
            packet.push(ATYP_IPV4);
            packet.extend_from_slice(&v4.octets());
        }
        IpAddress::Ipv6(v6) => {
            packet.push(ATYP_IPV6);
            packet.extend_from_slice(&v6.octets());
        }
    }

    packet.extend_from_slice(&remote_port.to_be_bytes());
    packet.extend_from_slice(data);
    packet
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
                ip: Some(IpAddress::Ipv4(Ipv4Address::new(addr[0], addr[1], addr[2], addr[3]))),
                domain: None,
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
            let port = u16::from_be_bytes(port);
            let domain_str = String::from_utf8_lossy(&domain).to_string();
            Ok(TargetAddress {
                ip: None,
                domain: Some(domain_str),
                port,
            })
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            Ok(TargetAddress {
                ip: Some(IpAddress::Ipv6(Ipv6Address::new(
                    u16::from_be_bytes([addr[0], addr[1]]),
                    u16::from_be_bytes([addr[2], addr[3]]),
                    u16::from_be_bytes([addr[4], addr[5]]),
                    u16::from_be_bytes([addr[6], addr[7]]),
                    u16::from_be_bytes([addr[8], addr[9]]),
                    u16::from_be_bytes([addr[10], addr[11]]),
                    u16::from_be_bytes([addr[12], addr[13]]),
                    u16::from_be_bytes([addr[14], addr[15]]),
                ))),
                domain: None,
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
