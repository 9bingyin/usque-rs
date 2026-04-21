impl TunnelManager {
    fn classify_incoming_tcp_handle(state: &RuntimeState, packet: &[u8]) -> Option<SocketHandle> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 => {
                let ipv4 = Ipv4Packet::new_checked(packet).ok()?;
                if ipv4.next_header() != IpProtocol::Tcp {
                    return None;
                }
                let tcp = TcpPacket::new_checked(ipv4.payload()).ok()?;
                let key = TcpFlowKey {
                    local_port: tcp.dst_port(),
                    remote_ip: IpAddress::Ipv4(ipv4.src_addr()),
                    remote_port: tcp.src_port(),
                };
                state.tcp_flow_map.get(&key).copied()
            }
            6 => {
                let ipv6 = Ipv6Packet::new_checked(packet).ok()?;
                if ipv6.next_header() != IpProtocol::Tcp {
                    return None;
                }
                let tcp = TcpPacket::new_checked(ipv6.payload()).ok()?;
                let key = TcpFlowKey {
                    local_port: tcp.dst_port(),
                    remote_ip: IpAddress::Ipv6(ipv6.src_addr()),
                    remote_port: tcp.src_port(),
                };
                state.tcp_flow_map.get(&key).copied()
            }
            _ => None,
        }
    }

    fn note_incoming_tcp_handle(state: &mut RuntimeState, packet: &[u8]) {
        if let Some(handle) = Self::classify_incoming_tcp_handle(state, packet) {
            state.mark_ready_tcp_handle(handle, SOCKET_EVENT_READ | SOCKET_EVENT_WRITE);
        }
    }

    async fn process_dirty_cycle(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        incoming_task: &mut IncomingTask,
        params: &ConnectionParams,
    ) -> bool {
        let handled_socket_events =
            Self::drain_socket_event_batch(state, state.tunables.socket_event_batch_budget);
        let handled_commands = Self::drain_command_batch(
            state,
            &params.dns_servers,
            params.tcp_buffer_size,
            cmd_rx,
            state.tunables.cmd_batch_budget,
        );
        let handled_udp_sends =
            Self::drain_udp_send_batch(state, udp_rx, state.tunables.udp_batch_budget);

        let incoming_result = Self::drain_incoming_batch(
            tunnel,
            state,
            &mut incoming_task.incoming_rx,
            state.tunables.udp_batch_read_budget,
        );

        let needs_stack_poll =
            handled_commands || handled_udp_sends || incoming_result.stack_ingress;
        let needs_targeted_tcp_service =
            handled_socket_events || !state.ready_tcp_handles.is_empty();
        let mut needs_stack_egress = false;

        if needs_stack_poll {
            if !Self::flush_stack_reads(state, incoming_result.stack_ingress) {
                return false;
            }
        } else if needs_targeted_tcp_service {
            Self::poll_tcp_sockets(state, false);
            match state.stack.poll_egress() {
                Ok(_state_changed) => {
                    needs_stack_egress = state.stack.has_tx_packets();
                }
                Err(e) => {
                    log::debug!("stack egress poll failed after targeted tcp service: {}", e);
                    return false;
                }
            }
        }

        let needs_transport_drain =
            needs_stack_poll || needs_stack_egress || state.stack.has_tx_packets();

        if needs_transport_drain {
            Self::drain_stack_packets(tunnel, state).await;
        }
        if incoming_result.needs_transport_flush {
            tunnel.mark_transport_flush_pending();
        }
        if tunnel.has_transport_flush_pending() || tunnel.transport_pending_send_packets() > 0 {
            Self::flush_transport_side_effects(tunnel, &mut state.perf).await;
        }

        Self::refresh_runtime_stats(state, tunnel);

        true
    }

    fn drain_socket_event_batch(state: &mut RuntimeState, budget: usize) -> bool {
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
        drained > 0
    }

    fn drain_command_batch(
        state: &mut RuntimeState,
        dns_servers: &[IpAddress],
        tcp_buffer_size: usize,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        budget: usize,
    ) -> bool {
        let mut remaining = budget;
        let mut handled = false;
        while remaining > 0 {
            match cmd_rx.try_recv() {
                Ok(cmd) => {
                    Self::handle_command(state, dns_servers, tcp_buffer_size, cmd);
                    remaining -= 1;
                    handled = true;
                }
                Err(_) => break,
            }
        }
        handled
    }

    fn drain_udp_send_batch(
        state: &mut RuntimeState,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        budget: usize,
    ) -> bool {
        let mut remaining = budget;
        let mut handled = false;
        while remaining > 0 {
            match udp_rx.try_recv() {
                Ok(udp_cmd) => {
                    Self::handle_udp_send(&mut state.stack, &mut state.udp_sessions, udp_cmd);
                    remaining -= 1;
                    handled = true;
                }
                Err(_) => break,
            }
        }
        handled
    }

    fn drain_incoming_batch(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        incoming_rx: &mut mpsc::Receiver<TransportIoEvent>,
        budget: usize,
    ) -> IncomingHandling {
        let mut remaining = budget;
        let mut result = IncomingHandling::default();
        while remaining > 0 {
            match incoming_rx.try_recv() {
                Ok(event) => {
                    let handled = Self::handle_transport_io_event(tunnel, state, event);
                    result.stack_ingress |= handled.stack_ingress;
                    result.needs_transport_flush |= handled.needs_transport_flush;
                    remaining -= 1;
                }
                Err(_) => break,
            }
        }
        result
    }

    fn handle_socket_event(state: &mut RuntimeState, event: SocketEvent) {
        if let Some(socket_state) = state.sockets.get_mut(&event.handle) {
            socket_state.pending_events |= event.kind.bit();
            if matches!(event.kind, SocketEventKind::Closed) {
                socket_state.close_requested = true;
                socket_state.write_shutdown = true;
            }
        }
        state.sync_socket_poll_interest(event.handle);
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
        let outcome = match state.stack.poll_bounded(state.tunables.stack_ingress_budget) {
            Ok(outcome) => outcome,
            Err(e) => {
                log::error!("network stack poll failed: {}", e);
                return false;
            }
        };
        state.perf.inc_poll();

        let should_full_tcp_sweep =
            full_tcp_sweep && outcome.socket_state_changed && state.ready_tcp_handles.is_empty();
        let should_targeted_tcp_sweep = !state.ready_tcp_handles.is_empty();

        if outcome.socket_state_changed {
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
        }

        if should_full_tcp_sweep || should_targeted_tcp_sweep {
            Self::poll_tcp_sockets(state, should_full_tcp_sweep);
        }

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
            let budget = state
                .tunables
                .targeted_tcp_sweep_budget
                .max(1)
                .min(state.ready_tcp_handles.len().max(1));
            let mut handles = Vec::with_capacity(budget);
            while handles.len() < budget {
                let Some(handle) = state.ready_tcp_handles.pop_front() else {
                    break;
                };
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
                let event_mask = if full_sweep {
                    socket_state.pending_events = 0;
                    socket_state.stream.clear_all_events();
                    SOCKET_EVENT_READ | SOCKET_EVENT_WRITE | SOCKET_EVENT_CLOSED
                } else {
                    let event_mask = std::mem::take(&mut socket_state.pending_events);
                    if event_mask & SOCKET_EVENT_READ != 0 {
                        socket_state.stream.clear_read_event();
                    }
                    if event_mask & SOCKET_EVENT_WRITE != 0 {
                        socket_state.stream.clear_write_event();
                    }
                    if event_mask & SOCKET_EVENT_CLOSED != 0 {
                        socket_state.stream.clear_close_event();
                    }
                    event_mask
                };
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
                RuntimeState::sync_socket_poll_interest_counters(
                    socket_state,
                    &mut state.pending_from_client_sockets,
                    &mut state.pending_to_client_sockets,
                    &mut state.close_requested_sockets,
                );
                let tcp_chunk_size = state.tunables.tcp_chunk_size;
                let should_service_write = full_sweep
                    || event_mask & (SOCKET_EVENT_WRITE | SOCKET_EVENT_CLOSED) != 0
                    || socket_state.close_requested
                    || socket_state.write_shutdown;
                let should_service_read = full_sweep || event_mask & SOCKET_EVENT_READ != 0;

                if should_service_write {
                    Self::flush_pending_to_stack(
                        stack,
                        write_buffer,
                        handle,
                        socket_state,
                        tcp_chunk_size,
                    );
                }
                if should_service_read {
                    Self::fill_recv_buffer(handle, stack, read_buffer, socket_state, tcp_chunk_size);
                }
                RuntimeState::sync_socket_poll_interest_counters(
                    socket_state,
                    &mut state.pending_from_client_sockets,
                    &mut state.pending_to_client_sockets,
                    &mut state.close_requested_sockets,
                );

                let past_handshake = stack.tcp_is_past_handshake(handle);
                RuntimeState::sync_socket_connecting_counters(
                    socket_state,
                    !past_handshake,
                    &mut state.connecting_sockets,
                );

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
                let socket_state = RuntimeState::remove_socket_poll_interest_counters(
                    socket_state,
                    &mut state.pending_from_client_sockets,
                    &mut state.pending_to_client_sockets,
                    &mut state.close_requested_sockets,
                    &mut state.connecting_sockets,
                );
                if let Some(flow_key) = socket_state.flow_key {
                    state.tcp_flow_map.remove(&flow_key);
                }
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

        state.runtime_stats.update(
            state.sockets.len(),
            pending_to_client_bytes,
            tunnel.transport_pending_send_packets(),
        );

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
            quic_stats: tunnel.quic_perf_stats(),
        }
    }

    fn refresh_runtime_stats(state: &RuntimeState, tunnel: &ActiveTunnel) {
        let pending_to_client_bytes = state
            .sockets
            .values()
            .map(SocketState::buffered_to_client_bytes)
            .sum();
        state.runtime_stats.update(
            state.sockets.len(),
            pending_to_client_bytes,
            tunnel.transport_pending_send_packets(),
        );
    }
}
