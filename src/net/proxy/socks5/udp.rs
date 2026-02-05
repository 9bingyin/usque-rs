use super::{cleanup_fragments, get_local_port, FragBuffer, Socks5Error};
use crate::net::proxy::socks5::resolve;
use crate::net::tunnel::manager::{ManagerCommand, TunnelManager};
use bytes::Bytes;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::{new_udp_header, parse_udp_request};
use fast_socks5::util::target_addr::TargetAddr;
use smoltcp::wire::IpAddress;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::UdpSocket;

pub(crate) async fn handle_udp_associate<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    proto: Socks5ServerProtocol<T, fast_socks5::server::states::CommandRead>,
    manager: Arc<TunnelManager>,
    local_addr: SocketAddr,
) -> Result<(), Socks5Error> {
    // Bind UDP socket for client
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let udp_addr = udp_socket.local_addr()?;
    log::debug!("UDP ASSOCIATE: relay socket bound to {}", udp_addr);

    // Register UDP session with manager
    let local_port = get_local_port();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    manager
        .cmd_sender()
        .send(ManagerCommand::UdpRegister {
            local_port,
            response: response_tx,
        })
        .await
        .map_err(|_| Socks5Error::ChannelError("Failed to register UDP session".into()))?;

    let mut from_tunnel = response_rx
        .await
        .map_err(|_| Socks5Error::ChannelError("Failed to get UDP receiver".into()))??;

    // Send success reply with UDP relay address
    let reply_ip = local_addr.ip();
    let reply_addr = SocketAddr::new(reply_ip, udp_addr.port());
    let mut tcp_stream = proto.reply_success(reply_addr).await?;

    // Forward UDP data
    let result = forward_udp_data(
        &mut tcp_stream,
        udp_socket,
        &mut from_tunnel,
        local_port,
        &manager,
    )
    .await;

    // Cleanup
    if let Err(e) = manager
        .cmd_sender()
        .send(ManagerCommand::UdpUnregister { local_port })
        .await
    {
        log::debug!("Failed to unregister UDP session: {}", e);
    }

    result
}

async fn forward_udp_data<T: AsyncRead + AsyncWrite + Unpin>(
    tcp_stream: &mut T,
    udp_socket: UdpSocket,
    from_tunnel: &mut tokio::sync::mpsc::Receiver<(IpAddress, u16, Bytes)>,
    local_port: u16,
    manager: &TunnelManager,
) -> Result<(), Socks5Error> {
    let mut buf = [0u8; 65535];
    let mut tcp_buf = [0u8; 1];
    let mut client_addr: Option<SocketAddr> = None;
    let mut frag_buffers: HashMap<TargetAddr, FragBuffer> = HashMap::new();

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
                        if let Ok((frag, target, payload)) = parse_udp_request(&buf[..len]).await {
                            cleanup_fragments(&mut frag_buffers);

                            if frag == 0 {
                                frag_buffers.remove(&target);
                                if let Some((remote_ip, remote_port)) = resolve::target_addr_to_ip(&target, manager).await {
                                    let data = Bytes::copy_from_slice(payload);
                                    if let Err(e) = manager.send_udp(remote_ip, remote_port, local_port, data).await {
                                        log::debug!("Failed to send UDP data to tunnel: {}", e);
                                    }
                                }
                                continue;
                            }

                            let is_last = (frag & 0x80) != 0;
                            let seq = frag & 0x7f;
                            if seq == 0 {
                                log::debug!("Invalid UDP fragment sequence 0");
                                continue;
                            }

                            let now = Instant::now();
                            let buffer = frag_buffers
                                .entry(target.clone())
                                .or_insert_with(|| FragBuffer::new(now));

                            if buffer.is_expired(now) {
                                buffer.reset(now);
                            }

                            if let Some(assembled) = buffer.insert(seq, is_last, Bytes::copy_from_slice(payload), now) {
                                frag_buffers.remove(&target);
                                if let Some((remote_ip, remote_port)) = resolve::target_addr_to_ip(&target, manager).await
                                    && let Err(e) = manager.send_udp(remote_ip, remote_port, local_port, assembled).await
                                {
                                    log::debug!("Failed to send UDP data to tunnel: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("UDP recv error: {}", e);
                    }
                }
            }

            // Receive UDP from tunnel, forward to client
            Some((remote_ip, remote_port, data)) = from_tunnel.recv() => {
                if let Some(addr) = client_addr
                    && let Ok(packet) = build_udp_response(remote_ip, remote_port, data.as_ref())
                    && let Err(e) = udp_socket.send_to(&packet, addr).await
                {
                    log::debug!("Failed to send UDP response to client: {}", e);
                }
            }
        }
    }

    Ok(())
}

fn build_udp_response(
    remote_ip: IpAddress,
    remote_port: u16,
    data: &[u8],
) -> Result<Vec<u8>, Socks5Error> {
    let addr = match remote_ip {
        IpAddress::Ipv4(v4) => {
            let bytes: [u8; 4] = [
                v4.octets()[0],
                v4.octets()[1],
                v4.octets()[2],
                v4.octets()[3],
            ];
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(bytes)), remote_port)
        }
        IpAddress::Ipv6(v6) => {
            let bytes = v6.octets();
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(bytes)), remote_port)
        }
    };

    let mut packet = new_udp_header(addr)
        .map_err(|e| Socks5Error::ProtocolError(format!("Failed to build UDP header: {:?}", e)))?;
    packet.extend_from_slice(data);
    Ok(packet)
}
