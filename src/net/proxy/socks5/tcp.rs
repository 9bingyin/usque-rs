use super::{
    format_ip_addr, interleave_addresses, map_connect_error_to_reply, map_manager_error_to_reply,
    CONNECTION_ATTEMPT_DELAY, CONNECT_TIMEOUT, IDLE_TIMEOUT, TCP_READ_BUFFER_SIZE,
};
use super::{Socks5Error, get_local_port};
use crate::net::tunnel::manager::{SocketChannels, TcpSocketState, TunnelManager};
use bytes::BytesMut;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::ReplyError;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpAddress;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

pub(crate) async fn handle_tcp_connect<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, fast_socks5::server::states::CommandRead>,
    manager: Arc<TunnelManager>,
    target: &TargetAddr,
    _client_addr: SocketAddr,
) -> Result<(), Socks5Error> {
    // Resolve addresses and get port
    let (addresses, remote_port) = match target {
        TargetAddr::Ip(addr) => (vec![super::std_ip_to_smoltcp(addr.ip())], addr.port()),
        TargetAddr::Domain(domain, port) => {
            log::debug!("resolving {}", domain);
            let ips = manager.resolve_all(domain).await.map_err(|e| {
                Socks5Error::ProtocolError(format!("DNS resolution failed: {:?}", e))
            })?;
            let sorted = interleave_addresses(ips);
            log::debug!("resolved [{}]", sorted.iter().map(|ip| format_ip_addr(*ip)).collect::<Vec<_>>().join(", "));
            (sorted, *port)
        }
    };

    if addresses.is_empty() {
        if let Err(e) = proto.reply_error(&ReplyError::HostUnreachable).await {
            log::trace!("failed to send error reply: {}", e);
        }
        return Err(Socks5Error::ProtocolError("No addresses resolved".into()));
    }

    // Single address: use simple connection logic
    if addresses.len() == 1 {
        return handle_tcp_connect_single(proto, manager, addresses[0], remote_port).await;
    }

    // Multiple addresses: use Happy Eyeballs connection racing
    handle_tcp_connect_racing(proto, manager, addresses, remote_port).await
}

// Single address connection (no racing needed)
async fn handle_tcp_connect_single<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, fast_socks5::server::states::CommandRead>,
    manager: Arc<TunnelManager>,
    remote_ip: IpAddress,
    remote_port: u16,
) -> Result<(), Socks5Error> {
    let local_port = get_local_port();
    let channels = match manager.connect(remote_ip, remote_port, local_port).await {
        Ok(channels) => channels,
        Err(err) => {
            let reply = map_manager_error_to_reply(&err);
            if let Err(rep_err) = proto.reply_error(&reply).await {
                log::trace!("failed to send error reply: {}", rep_err);
            }
            return Err(Socks5Error::TunnelError(err));
        }
    };

    let handle = channels.handle;
    let ready = match tokio::time::timeout(CONNECT_TIMEOUT, manager.wait_socket_ready(handle)).await
    {
        Ok(state) => state,
        Err(_) => {
            let err = Socks5Error::Timeout;
            let reply = map_connect_error_to_reply(&err);
            if let Err(rep_err) = proto.reply_error(&reply).await {
                log::trace!("failed to send error reply: {}", rep_err);
            }
            manager.close(handle).await;
            return Err(err);
        }
    };

    if ready != TcpSocketState::Established {
        let err = match ready {
            TcpSocketState::Closed => Socks5Error::ConnectionFailed("Connection closed".into()),
            TcpSocketState::Connecting => Socks5Error::Timeout,
            TcpSocketState::Established => unreachable!(),
        };
        let reply = map_connect_error_to_reply(&err);
        if let Err(rep_err) = proto.reply_error(&reply).await {
            log::trace!("failed to send error reply: {}", rep_err);
        }
        manager.close(handle).await;
        return Err(err);
    }

    log::debug!("connected to {}:{}", format_ip_addr(remote_ip), remote_port);
    let reply_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
    let mut stream = proto.reply_success(reply_addr).await?;
    let result = forward_tcp_data(&mut stream, channels).await;
    log::debug!("connection closed");
    manager.close(handle).await;
    result
}

// RFC 8305 Happy Eyeballs: race connections to multiple addresses
// Event-driven: uses wait_socket_ready instead of polling
async fn handle_tcp_connect_racing<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, fast_socks5::server::states::CommandRead>,
    manager: Arc<TunnelManager>,
    addresses: Vec<IpAddress>,
    remote_port: u16,
) -> Result<(), Socks5Error> {
    use tokio::time::timeout;

    log::debug!("racing {} addresses", addresses.len());

    let mut addr_iter = addresses.into_iter().peekable();
    let mut pending: Vec<(SocketHandle, SocketChannels)> = Vec::new();
    let mut last_error: Option<Socks5Error> = None;

    // Start first connection immediately
    if let Some(ip) = addr_iter.next() {
        match start_connection(&manager, ip, remote_port).await {
            Ok(channels) => {
                log::debug!("started connection to {}", format_ip_addr(ip));
                pending.push((channels.handle, channels));
            }
            Err(e) => {
                log::debug!("connection failed to {}: {}", format_ip_addr(ip), e);
                last_error = Some(e);
            }
        }
    }

    // Main racing loop with total timeout
    let result = timeout(CONNECT_TIMEOUT, async {
        race_connections_event_driven(
            &manager,
            &mut pending,
            &mut addr_iter,
            remote_port,
            &mut last_error,
        )
        .await
    })
    .await;

    match result {
        Ok(Ok((winner_handle, winner_channels))) => {
            log::debug!("connected (racing winner)");
            let reply_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
            let mut stream = proto.reply_success(reply_addr).await?;
            let result = forward_tcp_data(&mut stream, winner_channels).await;
            log::debug!("connection closed");
            manager.close(winner_handle).await;
            result
        }
        Ok(Err(e)) => {
            let reply = map_connect_error_to_reply(&e);
            if let Err(rep_err) = proto.reply_error(&reply).await {
                log::trace!("failed to send error reply: {}", rep_err);
            }
            Err(e)
        }
        Err(_) => {
            // Timeout - cleanup pending connections
            for (handle, _) in pending.drain(..) {
                manager.close(handle).await;
            }
            if let Err(e) = proto.reply_error(&ReplyError::ConnectionTimeout).await {
                log::trace!("failed to send error reply: {}", e);
            }
            Err(Socks5Error::Timeout)
        }
    }
}

/// Event-driven connection racing using wait_socket_ready
async fn race_connections_event_driven(
    manager: &Arc<TunnelManager>,
    pending: &mut Vec<(SocketHandle, SocketChannels)>,
    addr_iter: &mut std::iter::Peekable<std::vec::IntoIter<IpAddress>>,
    remote_port: u16,
    last_error: &mut Option<Socks5Error>,
) -> Result<(SocketHandle, SocketChannels), Socks5Error> {
    use tokio::sync::mpsc;
    use tokio::time::sleep;

    // Channel for receiving connection ready notifications
    let (ready_tx, mut ready_rx) = mpsc::channel::<(SocketHandle, TcpSocketState)>(16);

    // Start wait tasks for existing pending connections
    for (handle, _) in pending.iter() {
        let manager = manager.clone();
        let handle = *handle;
        let tx = ready_tx.clone();
        tokio::spawn(async move {
            let state = manager.wait_socket_ready(handle).await;
            if tx.send((handle, state)).await.is_err() {
                log::trace!("connection ready notification dropped");
            }
        });
    }

    // Timer for starting next connection
    let next_attempt = sleep(CONNECTION_ATTEMPT_DELAY);
    tokio::pin!(next_attempt);

    loop {
        // Check if we have any pending connections or addresses to try
        if pending.is_empty() && addr_iter.peek().is_none() {
            return Err(last_error.take().unwrap_or_else(|| {
                Socks5Error::ConnectionFailed("All connection attempts failed".into())
            }));
        }

        let has_more_addresses = addr_iter.peek().is_some();

        tokio::select! {
            biased;

            // Wait for connection ready notification
            Some((handle, state)) = ready_rx.recv() => {
                match state {
                    TcpSocketState::Established => {
                        // Found winner
                        if let Some(idx) = pending.iter().position(|(h, _)| *h == handle) {
                            let (winner_handle, winner_channels) = pending.remove(idx);
                            // Close other pending connections
                            for (h, _) in pending.drain(..) {
                                manager.close(h).await;
                            }
                            return Ok((winner_handle, winner_channels));
                        }
                    }
                    TcpSocketState::Closed => {
                        // Connection failed, remove from pending
                        if let Some(idx) = pending.iter().position(|(h, _)| *h == handle) {
                            let (h, _) = pending.remove(idx);
                            manager.close(h).await;
                            *last_error = Some(Socks5Error::ConnectionFailed("Connection closed".into()));

                            // If no pending connections left, immediately try next address
                            if pending.is_empty() && has_more_addresses {
                                next_attempt.as_mut().reset(tokio::time::Instant::now());
                            }
                        }
                    }
                    TcpSocketState::Connecting => {
                        // Should not happen - wait_socket_ready only returns on state change
                    }
                }
            }

            // Start next connection after delay (RFC 8305: 250ms)
            _ = &mut next_attempt, if has_more_addresses => {
                if let Some(ip) = addr_iter.next() {
                    log::debug!("started connection to {}", format_ip_addr(ip));
                    match start_connection(manager, ip, remote_port).await {
                        Ok(channels) => {
                            let handle = channels.handle;
                            pending.push((handle, channels));
                            // Start wait task for new connection
                            let manager = manager.clone();
                            let tx = ready_tx.clone();
                            tokio::spawn(async move {
                                let state = manager.wait_socket_ready(handle).await;
                                if tx.send((handle, state)).await.is_err() {
                                    log::trace!("connection ready notification dropped");
                                }
                            });
                        }
                        Err(e) => {
                            log::debug!("connection failed to {}: {}", format_ip_addr(ip), e);
                            *last_error = Some(e);
                        }
                    }
                }
                // Reset timer for next attempt
                next_attempt.as_mut().reset(tokio::time::Instant::now() + CONNECTION_ATTEMPT_DELAY);
            }
        }
    }
}

async fn start_connection(
    manager: &TunnelManager,
    remote_ip: IpAddress,
    remote_port: u16,
) -> Result<SocketChannels, Socks5Error> {
    let local_port = get_local_port();
    manager
        .connect(remote_ip, remote_port, local_port)
        .await
        .map_err(Socks5Error::TunnelError)
}

/// Handle SOCKS5 BIND command (RFC 1928)
/// BIND is used for protocols that require the server to accept incoming connections
/// (e.g., FTP active mode). The flow is:
/// 1. Server binds a local port and sends first reply with bind address
/// 2. Server waits for incoming connection from target
/// 3. Server sends second reply when connection is established
/// 4. Data is forwarded bidirectionally
pub(crate) async fn handle_tcp_bind<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, fast_socks5::server::states::CommandRead>,
    _manager: Arc<TunnelManager>,
    local_addr: SocketAddr,
    _target: (IpAddress, u16),
) -> Result<(), Socks5Error> {
    // Bind a local TCP listener
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let bind_addr = listener.local_addr()?;
    log::debug!("TCP BIND listening on {}", bind_addr);

    // First reply: tell client the bind address
    let reply_addr = SocketAddr::new(local_addr.ip(), bind_addr.port());
    let mut client_stream = proto.reply_success(reply_addr).await?;

    // Wait for incoming connection with timeout
    let accept_result = tokio::time::timeout(Duration::from_secs(60), listener.accept()).await;

    let (incoming_stream, peer_addr) = match accept_result {
        Ok(Ok((stream, addr))) => (stream, addr),
        Ok(Err(e)) => {
            log::warn!("TCP BIND accept error: {}", e);
            return Err(Socks5Error::IoError(e));
        }
        Err(_) => {
            log::debug!("TCP BIND timeout");
            return Err(Socks5Error::Timeout);
        }
    };

    log::debug!("BIND accepted from {}", peer_addr);

    // Second reply: tell client the peer address (using same format as first reply)
    // Note: In standard SOCKS5, we should send a second reply here, but fast-socks5
    // doesn't provide a direct way to do this. We'll write the reply manually.
    let second_reply = build_bind_reply(peer_addr);
    client_stream.write_all(&second_reply).await?;

    // Forward data between client and incoming connection
    forward_bind_data(client_stream, incoming_stream).await
}

fn build_bind_reply(addr: SocketAddr) -> Vec<u8> {
    let mut reply = vec![0x05, 0x00, 0x00]; // VER, REP (success), RSV

    match addr {
        SocketAddr::V4(v4) => {
            reply.push(0x01); // ATYP: IPv4
            reply.extend_from_slice(&v4.ip().octets());
            reply.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            reply.push(0x04); // ATYP: IPv6
            reply.extend_from_slice(&v6.ip().octets());
            reply.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    reply
}

async fn forward_bind_data<C, I>(mut client: C, mut incoming: I) -> Result<(), Socks5Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_reader, mut client_writer) = tokio::io::split(&mut client);
    let (mut incoming_reader, mut incoming_writer) = tokio::io::split(&mut incoming);

    let client_to_incoming = async {
        let mut buf = [0u8; 65535];
        loop {
            match client_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if incoming_writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let incoming_to_client = async {
        let mut buf = [0u8; 65535];
        loop {
            match incoming_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if client_writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = client_to_incoming => {}
        _ = incoming_to_client => {}
    }

    Ok(())
}

async fn forward_tcp_data<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    mut channels: SocketChannels,
) -> Result<(), Socks5Error> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut client_buf = BytesMut::with_capacity(TCP_READ_BUFFER_SIZE);
    let mut client_eof = false;
    let mut tunnel_eof = false;

    loop {
        if client_eof && tunnel_eof {
            break;
        }

        let result = tokio::time::timeout(IDLE_TIMEOUT, async {
            tokio::select! {
                result = channels.from_stack.recv(), if !tunnel_eof => {
                    match result {
                        Some(data) => {
                            if let Err(e) = writer.write_all(&data).await {
                                log::trace!("write to client failed: {}", e);
                                return false;
                            }
                            true
                        }
                        None => {
                            log::trace!("tunnel channel closed");
                            // Flush before signaling EOF to client
                            if let Err(e) = writer.flush().await {
                                log::trace!("flush to client failed: {}", e);
                            }
                            if let Err(e) = writer.shutdown().await {
                                log::trace!("shutdown writer failed: {}", e);
                            }
                            tunnel_eof = true;
                            true
                        }
                    }
                }

                result = reader.read_buf(&mut client_buf), if !client_eof => {
                    match result {
                        Ok(0) => {
                            log::trace!("client closed connection");
                            // Drop the sender to signal EOF to tunnel side
                            drop(channels.to_stack.clone());
                            client_eof = true;
                            true
                        }
                        Ok(n) => {
                            let data = client_buf.split_to(n).freeze();
                            if channels.to_stack.send(data).await.is_err() {
                                log::trace!("tunnel channel closed");
                                tunnel_eof = true;
                            }
                            true
                        }
                        Err(e) => {
                            log::trace!("read from client failed: {}", e);
                            false
                        }
                    }
                }
            }
        })
        .await;

        match result {
            Ok(true) => continue,
            Ok(false) => break,
            Err(_) => {
                log::trace!("connection idle timeout");
                break;
            }
        }
    }

    Ok(())
}
