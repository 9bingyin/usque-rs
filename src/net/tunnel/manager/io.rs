impl TunnelManager {
    fn handle_udp_recv(
        tunnel: &mut MasqueTunnel,
        state: &mut RuntimeState,
        data: &mut [u8],
        from: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
    ) -> bool {
        let recv_info = quiche::RecvInfo {
            from,
            to: local_addr,
        };

        if let Err(e) = tunnel.quic_conn.conn.recv(data, recv_info) {
            log::warn!("QUIC recv failed: {:?}", e);
            return false;
        }

        tunnel.poll_h3();

        let mut injected_packet = false;
        loop {
            match tunnel.recv_datagram(state.udp_buffer.as_mut()) {
                Ok(len) if len > 0 => {
                    let mut packet = Self::take_pooled_buffer(&state.buffer_pool, len);
                    packet.extend_from_slice(&state.udp_buffer[..len]);
                    state.perf.inc_rx(len);
                    Self::note_incoming_tcp_handle(state, &packet[..]);
                    state.stack.inject_packet_owned(packet);
                    injected_packet = true;
                }
                _ => break,
            }
        }
        injected_packet
    }

    fn configure_udp_socket_buffers(
        socket: &std::net::UdpSocket,
        recv_size: usize,
        send_size: usize,
    ) {
        let sock = socket2::SockRef::from(socket);

        if let Err(e) = sock.set_recv_buffer_size(recv_size) {
            log::warn!("Failed to set SO_RCVBUF to {}KB: {}", recv_size / 1024, e);
        }
        if let Err(e) = sock.set_send_buffer_size(send_size) {
            log::warn!("Failed to set SO_SNDBUF to {}KB: {}", send_size / 1024, e);
        }

        let actual_recv = sock.recv_buffer_size().unwrap_or(0);
        let actual_send = sock.send_buffer_size().unwrap_or(0);
        log::info!(
            "WG UDP socket buffers: recv={}KB (req {}KB), send={}KB (req {}KB)",
            actual_recv / 1024,
            recv_size / 1024,
            actual_send / 1024,
            send_size / 1024,
        );
    }

    fn take_pooled_buffer(pool: &BufferPool, capacity: usize) -> BytesMut {
        let mut guard = match pool.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(mut buf) = guard.pop() {
            buf.clear();
            if buf.capacity() < capacity {
                buf.reserve(capacity - buf.capacity());
            }
            buf
        } else {
            BytesMut::with_capacity(capacity)
        }
    }

    fn return_pooled_buffer(pool: &BufferPool, mut buf: BytesMut, pool_max_size: usize) {
        buf.clear();
        let mut guard = match pool.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.len() < pool_max_size {
            guard.push(buf);
        }
    }
}
