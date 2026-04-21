impl TunnelManager {
    async fn process_dirty_cycle(
        tunnel: &mut ActiveTunnel,
        state: &mut RuntimeState,
        cmd_rx: &mut mpsc::Receiver<ManagerCommand>,
        udp_rx: &mut mpsc::Receiver<UdpSend>,
        incoming_task: &mut IncomingTask,
        params: &ConnectionParams,
    ) -> bool {
        Self::drain_command_batch(
            state,
            &params.dns_servers,
            params.tcp_buffer_size,
            cmd_rx,
            CMD_BATCH_BUDGET,
        );
        Self::drain_udp_send_batch(state, udp_rx, UDP_BATCH_BUDGET);

        let handled_incoming = Self::drain_incoming_batch(
            tunnel,
            state,
            &mut incoming_task.incoming_rx,
            UDP_BATCH_READ_BUDGET,
        );

        if handled_incoming {
            Self::flush_transport_side_effects(tunnel, &mut state.perf).await;
        }

        Self::flush_active_tunnel(tunnel, state).await
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
    ) {
        for &local_port in udp_ports {
            let handle = match udp_sessions.get(&local_port) {
                Some(session) => session.handle,
                None => continue,
            };

            if !stack.udp_can_recv(handle) {
                continue;
            }

            let mut buf = [0u8; 65535];
            if let Ok((len, endpoint)) = stack.udp_recv(handle, &mut buf)
                && len > 0
            {
                let remote_ip = endpoint.endpoint.addr;
                let remote_port = endpoint.endpoint.port;

                if let Some(session) = udp_sessions.get_mut(&local_port) {
                    session.last_activity = Instant::now();
                    if session
                        .to_client
                        .try_send((remote_ip, remote_port, Bytes::copy_from_slice(&buf[..len])))
                        .is_err()
                    {
                        log::debug!("UDP session channel full or closed for port {}", local_port);
                    }
                }
            }
        }
    }

    fn poll_stack_common(state: &mut RuntimeState) -> bool {
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

        Self::process_udp_responses(&mut state.stack, &mut state.udp_sessions, &state.udp_ports);

        Self::expire_dns_groups(state);
        Self::expire_udp_sessions(state);
        Self::poll_tcp_sockets(state);

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
            .filter(|(_, session)| now.duration_since(session.last_activity) > UDP_SESSION_TIMEOUT)
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

    fn poll_tcp_sockets(state: &mut RuntimeState) {
        let mut closed_handles = Vec::new();

        for handle in state.tcp_handles.iter().copied() {
            if !state.stack.tcp_is_active(handle) {
                closed_handles.push(handle);
                continue;
            }

            if let Some(socket_state) = state.sockets.get_mut(&handle) {
                if Self::flush_pending_to_client(socket_state) {
                    socket_state.close_requested = true;
                    socket_state.write_shutdown = true;
                }

                if !socket_state.close_requested
                    && state.stack.tcp_may_recv(handle)
                    && socket_state.pending_to_client_bytes < MAX_PENDING_TO_CLIENT
                {
                    let available =
                        MAX_PENDING_TO_CLIENT.saturating_sub(socket_state.pending_to_client_bytes);
                    let read_len = available.min(MAX_TCP_READ_CHUNK);
                    if read_len > 0 {
                        if state.read_buffer.len() < read_len {
                            state.read_buffer.resize(read_len, 0);
                        }
                        if let Ok(n) = state
                            .stack
                            .tcp_recv(handle, &mut state.read_buffer[..read_len])
                            && n > 0
                        {
                            let data = Bytes::copy_from_slice(&state.read_buffer[..n]);
                            match Self::deliver_to_client(handle, socket_state, data) {
                                Ok(()) | Err(DeliverError::Backpressure) => {}
                                Err(DeliverError::Closed) => {
                                    log::trace!("TCP channel closed for socket {:?}", handle);
                                    socket_state.close_requested = true;
                                    socket_state.write_shutdown = true;
                                }
                            }
                        }
                    }
                }

                Self::flush_pending_to_stack(&mut state.stack, handle, socket_state);

                if !socket_state.write_shutdown
                    && socket_state.pending_from_client_bytes < MAX_PENDING_DATA
                {
                    loop {
                        match socket_state.from_client.try_recv() {
                            Ok(data) => {
                                socket_state.pending_from_client_bytes += data.len();
                                socket_state.pending_from_client.push_back(data);
                                if socket_state.pending_from_client_bytes >= MAX_PENDING_DATA {
                                    log::debug!(
                                        "Pending data exceeded limit for socket {:?} ({} bytes), applying backpressure",
                                        handle,
                                        socket_state.pending_from_client_bytes
                                    );
                                    break;
                                }
                            }
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                socket_state.close_requested = true;
                                socket_state.write_shutdown = true;
                                break;
                            }
                        }
                    }
                }

                Self::flush_pending_to_stack(&mut state.stack, handle, socket_state);

                if socket_state.close_requested
                    && !socket_state.fin_sent
                    && socket_state.pending_from_client_bytes == 0
                    && state.stack.tcp_may_send(handle)
                {
                    state.stack.tcp_close(handle);
                    socket_state.fin_sent = true;
                }
            }
        }

        for handle in &closed_handles {
            if let Some(socket_state) = state.sockets.remove(handle) {
                for waiter in socket_state.ready_waiters {
                    if waiter.send(TcpSocketState::Closed).is_err() {
                        log::trace!("Failed to notify waiter of connection close: receiver dropped");
                    }
                }
            }
            state.stack.remove_socket(*handle);
        }
        if !closed_handles.is_empty() {
            state.tcp_handles.retain(|h| !closed_handles.contains(h));
        }
    }

    fn flush_stack_reads(state: &mut RuntimeState) -> bool {
        Self::poll_stack_common(state)
    }

    fn flush_pending_to_client(state: &mut SocketState) -> bool {
        while let Some(data) = state.pending_to_client.pop_front() {
            let len = data.len();
            match state.to_client.try_send(data) {
                Ok(()) => {
                    state.pending_to_client_bytes =
                        state.pending_to_client_bytes.saturating_sub(len);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                    state.pending_to_client.push_front(data);
                    break;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    state.pending_to_client.clear();
                    state.pending_to_client_bytes = 0;
                    return true;
                }
            }
        }
        false
    }

    fn flush_pending_to_stack(
        stack: &mut NetworkStack,
        handle: SocketHandle,
        state: &mut SocketState,
    ) {
        if !stack.tcp_may_send(handle) {
            return;
        }

        while let Some(data) = state.pending_from_client.pop_front() {
            let len = data.len();
            state.pending_from_client_bytes = state.pending_from_client_bytes.saturating_sub(len);

            match stack.tcp_send(handle, &data) {
                Ok(0) => {
                    state.pending_from_client_bytes += len;
                    state.pending_from_client.push_front(data);
                    break;
                }
                Ok(sent) if sent < len => {
                    let remaining = data.slice(sent..);
                    state.pending_from_client_bytes += remaining.len();
                    state.pending_from_client.push_front(remaining);
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    state.pending_from_client_bytes += len;
                    state.pending_from_client.push_front(data);
                    break;
                }
            }

            if !stack.tcp_may_send(handle) {
                break;
            }
        }
    }

    fn deliver_to_client(
        handle: SocketHandle,
        state: &mut SocketState,
        data: Bytes,
    ) -> Result<(), DeliverError> {
        match state.to_client.try_send(data) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                if state.pending_to_client_bytes + data.len() > MAX_PENDING_TO_CLIENT {
                    log::debug!(
                        "Pending to-client data exceeded limit for socket {:?} ({} bytes), applying backpressure",
                        handle,
                        state.pending_to_client_bytes + data.len()
                    );
                    return Err(DeliverError::Backpressure);
                }
                state.pending_to_client_bytes += data.len();
                state.pending_to_client.push_back(data);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(DeliverError::Closed),
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
            pending_from_client_bytes += socket_state.pending_from_client_bytes;
            pending_to_client_bytes += socket_state.pending_to_client_bytes;
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
            transport_pending_send_packets: tunnel.transport_pending_send_packets(),
        }
    }
}
