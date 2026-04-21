impl TunnelManager {
    async fn process_dirty_cycle(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        incoming_task: &mut IncomingTask,
        params: &ConnectionParams,
    ) -> bool {
        Self::drain_socket_event_batch(state, state.tunables.socket_event_batch_budget);
        Self::drain_command_batch(
            state,
            &params.dns_servers,
            params.tcp_buffer_size,
            cmd_rx,
            state.tunables.cmd_batch_budget,
        );
        Self::drain_udp_send_batch(state, udp_rx, state.tunables.udp_batch_budget);

        let handled_incoming = Self::drain_incoming_batch(
            tunnel,
            state,
            &mut incoming_task.incoming_rx,
            state.tunables.udp_batch_read_budget,
        );

        Self::flush_active_tunnel(tunnel, state, handled_incoming).await
    }

    fn drain_socket_event_batch(state: &mut RuntimeState, budget: usize) {
        let mut remaining = budget;
        let mut drained = 0usize;
        while remaining > 0 {
            match state.socket_event_rx.try_recv() {
                Ok(event) => {
                    Self::handle_socket_event(state, event);
                    remaining -= 1;
                    drained += 1;
                }
                Err(_) => break,
            }
        }
        state.perf.inc_socket_event_batch(drained);
    }

    fn drain_command_batch(
        state: &mut RuntimeState,
        dns_servers: &[IpAddress],
        tcp_buffer_size: usize,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        budget: usize,
    ) {
        let mut remaining = budget;
        while remaining > 0 {
            match cmd_rx.try_recv() {
                Ok(cmd) => {
                    Self::handle_command(state, dns_servers, tcp_buffer_size, cmd);
                    remaining -= 1;
                }
                Err(_) => break,
            }
        }
    }

    fn drain_udp_send_batch(
        state: &mut RuntimeState,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        budget: usize,
    ) {
        let mut remaining = budget;
        while remaining > 0 {
            match udp_rx.try_recv() {
                Ok(udp_cmd) => {
                    Self::handle_udp_send(&mut state.stack, &mut state.udp_sessions, udp_cmd);
                    remaining -= 1;
                }
                Err(_) => break,
            }
        }
    }

    fn drain_incoming_batch(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        incoming_rx: &mut mpsc::Receiver<IncomingDatagram>,
        budget: usize,
    ) -> bool {
        let mut remaining = budget;
        let mut handled_incoming = false;
        while remaining > 0 {
            match incoming_rx.try_recv() {
                Ok(incoming) => {
                    handled_incoming |= Self::handle_incoming_datagram(tunnel, state, incoming);
                    remaining -= 1;
                }
                Err(_) => break,
            }
        }
        handled_incoming
    }

    fn handle_socket_event(state: &mut RuntimeState, event: SocketEvent) {
        if let Some(socket_state) = state.sockets.get_mut(&event.handle) {
            socket_state.stream.clear_event(event.kind);
            if matches!(event.kind, SocketEventKind::Closed) {
                socket_state.close_requested = true;
                socket_state.write_shutdown = true;
            }
        }
        state.enqueue_ready_tcp_handle(event.handle);
    }

    fn notify_ready_waiters(
        stack: &mut NetworkStack,
        sockets: &mut HashMap<SocketHandle, SocketState>,
    ) {
        let mut notifications: Vec<(Vec<oneshot::Sender<TcpSocketState>>, TcpSocketState)> =
            Vec::new();

        for (handle, state) in sockets.iter_mut() {
            if state.ready_waiters.is_empty() {
                continue;
            }

            let tcp_state = if !stack.tcp_is_active(*handle) {
                TcpSocketState::Closed
            } else if stack.tcp_may_send(*handle) && stack.tcp_may_recv(*handle) {
                TcpSocketState::Established
            } else {
                TcpSocketState::Connecting
            };

            if tcp_state != TcpSocketState::Connecting {
                let waiters: Vec<_> = state.ready_waiters.drain(..).collect();
                notifications.push((waiters, tcp_state));
            }
        }

        for (waiters, tcp_state) in notifications {
            for waiter in waiters {
                if waiter.send(tcp_state).is_err() {
                    log::trace!("Failed to notify waiter of state change: receiver dropped");
                }
            }
        }
    }

    fn process_dns_responses(
        stack: &mut NetworkStack,
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        dns_cache: &mut Cache<String, DnsCacheValue>,
        dns_sockets: &DnsSockets,
    ) {
        for handle in dns_sockets.handles() {
            while stack.udp_can_recv(handle) {
                let mut buf = [0u8; 4096];
                let (len, _endpoint) = match stack.udp_recv(handle, &mut buf) {
                    Ok(result) => result,
                    Err(e) => {
                        log::debug!("DNS recv failed: {}", e);
                        break;
                    }
                };
                if len == 0 {
                    continue;
                }

                let parsed = match parse_dns_response_with_id(&buf[..len]) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        log::debug!("Failed to parse DNS response: {:?}", e);
                        continue;
                    }
                };

                let (transaction_id, response_result) = parsed;
                let Some(state) = dns_queries.remove(&transaction_id) else {
                    log::trace!("DNS response ignored for unknown id={}", transaction_id);
                    continue;
                };

                if let Some(group) = dns_groups.get_mut(&state.group_id) {
                    match state.query_type {
                        DnsRecordType::A => {
                            group.ipv4_result = Some(response_result);
                        }
                        DnsRecordType::AAAA => {
                            group.ipv6_result = Some(response_result);
                        }
                        _ => {}
                    }
                }

                Self::try_resolve_dns_group(dns_queries, dns_groups, dns_cache, state.group_id);
            }
        }
    }

    fn process_udp_responses(
        stack: &mut NetworkStack,
        udp_sessions: &mut HashMap<u16, UdpSessionState>,
        udp_ports: &[u16],
        udp_buffer: &mut BytesMut,
    ) {
        for &local_port in udp_ports {
            let handle = match udp_sessions.get(&local_port) {
                Some(session) => session.handle,
                None => continue,
            };

            if !stack.udp_can_recv(handle) {
                continue;
            }

            if let Ok((len, endpoint)) = stack.udp_recv(handle, udp_buffer.as_mut())
                && len > 0
            {
                let remote_ip = endpoint.endpoint.addr;
                let remote_port = endpoint.endpoint.port;

                if let Some(session) = udp_sessions.get_mut(&local_port) {
                    session.last_activity = Instant::now();
                    if session
                        .to_client
                        .try_send((remote_ip, remote_port, Bytes::copy_from_slice(&udp_buffer[..len])))
                        .is_err()
                    {
                        log::debug!("UDP session channel full or closed for port {}", local_port);
                    }
                }
            }
        }
    }

    fn poll_stack_common(state: &mut RuntimeState, full_tcp_sweep: bool) -> bool {
        if let Err(e) = state.stack.poll() {
            log::error!("network stack poll failed: {}", e);
            return false;
        }
        state.perf.inc_poll();

        Self::notify_ready_waiters(&mut state.stack, &mut state.sockets);

        Self::process_dns_responses(
            &mut state.stack,
            &mut state.dns_queries,
            &mut state.dns_groups,
            &mut state.dns_cache,
            &state.dns_sockets,
        );

        Self::process_udp_responses(
            &mut state.stack,
            &mut state.udp_sessions,
            &state.udp_ports,
            &mut state.udp_buffer,
        );

        Self::expire_dns_groups(state);
        Self::expire_udp_sessions(state);
        Self::poll_tcp_sockets(state, full_tcp_sweep);

        true
    }

    fn expire_dns_groups(state: &mut RuntimeState) {
        let now = Instant::now();
        let timed_out_groups: Vec<u32> = state
            .dns_groups
            .iter()
            .filter(|(_, group)| now.duration_since(group.created_at) > Duration::from_secs(5))
            .map(|(id, _)| *id)
            .collect();

        for group_id in timed_out_groups {
            let query_ids: Vec<u16> = state
                .dns_queries
                .iter()
                .filter(|(_, s)| s.group_id == group_id)
                .map(|(id, _)| *id)
                .collect();
            for id in query_ids {
                state.dns_queries.remove(&id);
            }
            if let Some(mut group) = state.dns_groups.remove(&group_id) {
                if let Some(response) = group.response.take()
                    && response
                        .send(Err(ManagerError::Dns(DnsError::Timeout)))
                        .is_err()
                {
                    log::trace!("Failed to send DNS timeout response: receiver dropped");
                }
                if let Some(response_all) = group.response_all.take()
                    && response_all
                        .send(Err(ManagerError::Dns(DnsError::Timeout)))
                        .is_err()
                {
                    log::trace!("Failed to send DNS timeout response (all): receiver dropped");
                }
            }
        }
    }

    fn expire_udp_sessions(state: &mut RuntimeState) {
        let now = Instant::now();
        let stale_ports: Vec<u16> = state
            .udp_sessions
            .iter()
            .filter(|(_, session)| {
                now.duration_since(session.last_activity) > state.tunables.udp_session_timeout
            })
            .map(|(port, _)| *port)
            .collect();

        for port in &stale_ports {
            if let Some(session) = state.udp_sessions.remove(port) {
                state.stack.remove_socket(session.handle);
                log::debug!("UDP session expired on port {}", port);
            }
        }

        if !stale_ports.is_empty() {
            state.udp_ports.retain(|p| !stale_ports.contains(p));
        }
    }

    fn poll_tcp_sockets(state: &mut RuntimeState, full_sweep: bool) {
        state.perf.inc_tcp_sweep(full_sweep);
        let mut closed_handles = Vec::new();
        let stack = &mut state.stack;
        let read_buffer = &mut state.read_buffer;
        let write_buffer = &mut state.write_buffer;
        let handles: Vec<SocketHandle> = if full_sweep {
            state.ready_tcp_handles.clear();
            state.ready_tcp_set.clear();
            state.tcp_handles.clone()
        } else {
            let mut handles = Vec::with_capacity(state.ready_tcp_handles.len());
            while let Some(handle) = state.ready_tcp_handles.pop_front() {
                state.ready_tcp_set.remove(&handle);
                handles.push(handle);
            }
            handles
        };

        for handle in handles {
            if !stack.tcp_is_active(handle) {
                closed_handles.push(handle);
                continue;
            }

            if let Some(socket_state) = state.sockets.get_mut(&handle) {
                if socket_state
                    .stream
                    .socket_dropped
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    socket_state.close_requested = true;
                    socket_state.write_shutdown = true;
                }
                if socket_state
                    .stream
                    .write_shutdown
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    socket_state.write_shutdown = true;
                }
                let tcp_chunk_size = state.tunables.tcp_chunk_size;
                Self::flush_pending_to_stack(
                    stack,
                    write_buffer,
                    handle,
                    socket_state,
                    tcp_chunk_size,
                );
                Self::fill_recv_buffer(handle, stack, read_buffer, socket_state, tcp_chunk_size);

                let past_handshake = stack.tcp_is_past_handshake(handle);

                if past_handshake && !stack.tcp_may_recv(handle) {
                    socket_state
                        .stream
                        .read_closed
                        .store(true, std::sync::atomic::Ordering::Release);
                    socket_state.stream.recv_waker.wake();
                }
                if past_handshake && !stack.tcp_may_send(handle) {
                    socket_state
                        .stream
                        .write_closed
                        .store(true, std::sync::atomic::Ordering::Release);
                    socket_state.stream.send_waker.wake();
                }

                if socket_state.close_requested
                    && !socket_state.fin_sent
                    && socket_state.buffered_from_client_bytes() == 0
                    && stack.tcp_may_send(handle)
                {
                    stack.tcp_close(handle);
                    socket_state.fin_sent = true;
                }
            }
        }

        for handle in &closed_handles {
            if let Some(socket_state) = state.sockets.remove(handle) {
                socket_state
                    .stream
                    .socket_closed
                    .store(true, std::sync::atomic::Ordering::Release);
                socket_state
                    .stream
                    .read_closed
                    .store(true, std::sync::atomic::Ordering::Release);
                socket_state
                    .stream
                    .write_closed
                    .store(true, std::sync::atomic::Ordering::Release);
                socket_state.stream.recv_waker.wake();
                socket_state.stream.send_waker.wake();
                for waiter in socket_state.ready_waiters {
                    if waiter.send(TcpSocketState::Closed).is_err() {
                        log::trace!("Failed to notify waiter of connection close: receiver dropped");
                    }
                }
            }
            state.ready_tcp_set.remove(handle);
            stack.remove_socket(*handle);
        }
        if !closed_handles.is_empty() {
            state.tcp_handles.retain(|h| !closed_handles.contains(h));
            state
                .ready_tcp_handles
                .retain(|h| !closed_handles.contains(h));
        }
    }

    fn flush_stack_reads(state: &mut RuntimeState, full_tcp_sweep: bool) -> bool {
        Self::poll_stack_common(state, full_tcp_sweep)
    }

    fn fill_recv_buffer(
        handle: SocketHandle,
        stack: &mut NetworkStack,
        read_buffer: &mut BytesMut,
        state: &mut SocketState,
        tcp_chunk_size: usize,
    ) {
        if state.close_requested || !stack.tcp_may_recv(handle) {
            return;
        }

        while state.stream.recv_buffer.remaining_capacity() > 0 && stack.tcp_may_recv(handle) {
            let read_len = state
                .stream
                .recv_buffer
                .remaining_capacity()
                .min(tcp_chunk_size);
            if read_buffer.len() < read_len {
                read_buffer.resize(read_len, 0);
            }

            match stack.tcp_recv(handle, &mut read_buffer[..read_len]) {
                Ok(0) => break,
                Ok(n) => {
                    let written = state.stream.recv_buffer.enqueue_slice(&read_buffer[..n]);
                    if written > 0 {
                        state.stream.recv_waker.wake();
                    }
                    if written < n {
                        log::debug!(
                            "Receive buffer saturated for socket {:?} ({} bytes buffered)",
                            handle,
                            state.buffered_to_client_bytes()
                        );
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    fn flush_pending_to_stack(
        stack: &mut NetworkStack,
        write_buffer: &mut BytesMut,
        handle: SocketHandle,
        state: &mut SocketState,
        tcp_chunk_size: usize,
    ) {
        while stack.tcp_may_send(handle) {
            if write_buffer.len() < tcp_chunk_size {
                write_buffer.resize(tcp_chunk_size, 0);
            }
            let chunk_len = state
                .stream
                .send_buffer
                .peek_copy(&mut write_buffer[..tcp_chunk_size]);
            if chunk_len == 0 {
                break;
            }

            match stack.tcp_send(handle, &write_buffer[..chunk_len]) {
                Ok(0) => break,
                Ok(sent) => {
                    state.stream.send_buffer.consume(sent);
                    state.stream.send_waker.wake();
                    if sent < chunk_len {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    fn build_perf_snapshot(
        state: &mut RuntimeState,
        tunnel: &ActiveTunnel,
        cmd_queue_len: usize,
        udp_queue_len: usize,
        incoming_queue_len: usize,
    ) -> PerfSnapshot {
        let DeviceStats {
            rx_queue_len,
            tx_queue_len,
            rx_drops,
            tx_drops,
        } = state.stack.take_device_stats();

        let mut pending_from_client_bytes = 0usize;
        let mut pending_to_client_bytes = 0usize;
        for socket_state in state.sockets.values() {
            pending_from_client_bytes += socket_state.buffered_from_client_bytes();
            pending_to_client_bytes += socket_state.buffered_to_client_bytes();
        }

        PerfSnapshot {
            sockets: state.sockets.len(),
            udp_sessions: state.udp_sessions.len(),
            dns_groups: state.dns_groups.len(),
            pending_from_client_bytes,
            pending_to_client_bytes,
            rx_queue_len,
            tx_queue_len,
            rx_drops,
            tx_drops,
            cmd_queue_len,
            udp_queue_len,
            incoming_queue_len,
            ready_tcp_queue_len: state.ready_tcp_handles.len(),
            transport_pending_send_packets: tunnel.transport_pending_send_packets(),
        }
    }
}
