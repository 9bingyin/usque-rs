impl TunnelManager {
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

    fn return_pooled_buffer(
        pool: &BufferPool,
        mut buf: BytesMut,
        pool_max_size: usize,
        buffer_reuse_max_capacity: usize,
    ) {
        buf.clear();
        if buf.capacity() > buffer_reuse_max_capacity {
            return;
        }
        let mut guard = match pool.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.len() < pool_max_size {
            guard.push(buf);
        }
    }
}
