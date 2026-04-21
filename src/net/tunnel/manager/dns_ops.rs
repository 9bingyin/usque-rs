impl TunnelManager {
    fn insert_dns_group(
        state: &mut RuntimeState,
        domain: &str,
        prefer_ipv6: bool,
        response: Option<oneshot::Sender<Result<IpAddress, ManagerError>>>,
        response_all: Option<oneshot::Sender<Result<Vec<IpAddress>, ManagerError>>>,
    ) -> u32 {
        use std::sync::atomic::Ordering;

        let group_id = DNS_GROUP_ID.fetch_add(1, Ordering::Relaxed);
        state.dns_groups.insert(
            group_id,
            DnsQueryGroup {
                domain: domain.to_string(),
                response,
                response_all,
                ipv4_result: None,
                ipv6_result: None,
                created_at: Instant::now(),
                prefer_ipv6,
            },
        );
        group_id
    }

    fn record_dns_error(
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        group_id: u32,
        query_type: DnsRecordType,
        err: DnsError,
    ) {
        if let Some(group) = dns_groups.get_mut(&group_id) {
            match query_type {
                DnsRecordType::A => {
                    group.ipv4_result = Some(Err(err));
                }
                DnsRecordType::AAAA => {
                    group.ipv6_result = Some(Err(err));
                }
                _ => {}
            }
        }
    }

    fn fail_dns_group(state: &mut RuntimeState, group_id: u32, err: DnsError) {
        Self::record_dns_error(&mut state.dns_groups, group_id, DnsRecordType::A, err.clone());
        Self::record_dns_error(&mut state.dns_groups, group_id, DnsRecordType::AAAA, err);
        Self::try_resolve_dns_group(
            &mut state.dns_queries,
            &mut state.dns_groups,
            &mut state.dns_cache,
            group_id,
        );
    }

    fn build_unique_dns_query(
        dns_queries: &HashMap<u16, DnsQueryState>,
        domain: &str,
        record_type: DnsRecordType,
    ) -> Result<(u16, Vec<u8>), DnsError> {
        for _ in 0..=u16::MAX {
            let (tx_id, packet) = build_dns_query(domain, record_type)?;
            if !dns_queries.contains_key(&tx_id) {
                return Ok((tx_id, packet));
            }
        }
        Err(DnsError::SocketError("DNS transaction ID exhausted".into()))
    }

    fn dispatch_dns_query(
        state: &mut RuntimeState,
        group_id: u32,
        domain: &str,
        dns_handle: SocketHandle,
        dns_server: IpAddress,
        query_type: DnsRecordType,
        log_label: &str,
    ) {
        match Self::build_unique_dns_query(&state.dns_queries, domain, query_type) {
            Ok((tx_id, packet)) => {
                if state
                    .stack
                    .udp_send(dns_handle, dns_server, dns_port(), &packet)
                    .is_ok()
                {
                    state.dns_queries.insert(tx_id, DnsQueryState { group_id, query_type });
                    log::debug!("DNS query: {} {}", domain, log_label);
                } else {
                    Self::record_dns_error(
                        &mut state.dns_groups,
                        group_id,
                        query_type,
                        DnsError::SocketError(format!("DNS {} send failed", log_label)),
                    );
                    Self::try_resolve_dns_group(
                        &mut state.dns_queries,
                        &mut state.dns_groups,
                        &mut state.dns_cache,
                        group_id,
                    );
                }
            }
            Err(err) => {
                Self::record_dns_error(&mut state.dns_groups, group_id, query_type, err);
                Self::try_resolve_dns_group(
                    &mut state.dns_queries,
                    &mut state.dns_groups,
                    &mut state.dns_cache,
                    group_id,
                );
            }
        }
    }

    fn start_dns_queries_for_group(
        state: &mut RuntimeState,
        group_id: u32,
        domain: &str,
        dns_server: IpAddress,
        dns_handle: SocketHandle,
        resolve_all: bool,
    ) {
        for (query_type, label) in [
            (DnsRecordType::A, "A"),
            (DnsRecordType::AAAA, "AAAA"),
        ] {
            let log_label = if resolve_all {
                match query_type {
                    DnsRecordType::A => "A (all)",
                    DnsRecordType::AAAA => "AAAA (all)",
                    _ => label,
                }
            } else {
                label
            };
            Self::dispatch_dns_query(
                state,
                group_id,
                domain,
                dns_handle,
                dns_server,
                query_type,
                log_label,
            );
        }
    }

    fn start_dns_query(
        state: &mut RuntimeState,
        domain: &str,
        prefer_ipv6: bool,
        response: oneshot::Sender<Result<IpAddress, ManagerError>>,
        dns_servers: &[IpAddress],
    ) {
        let group_id = Self::insert_dns_group(state, domain, prefer_ipv6, Some(response), None);
        let dns_server = Self::select_dns_server(dns_servers, prefer_ipv6);
        let dns_handle = match state
            .dns_sockets
            .ensure_socket(&mut state.stack, dns_server)
        {
            Ok(handle) => handle,
            Err(e) => {
                Self::fail_dns_group(state, group_id, e);
                return;
            }
        };

        Self::start_dns_queries_for_group(state, group_id, domain, dns_server, dns_handle, false);
    }

    fn start_dns_query_all(
        state: &mut RuntimeState,
        domain: &str,
        response: oneshot::Sender<Result<Vec<IpAddress>, ManagerError>>,
        dns_servers: &[IpAddress],
    ) {
        let group_id = Self::insert_dns_group(state, domain, true, None, Some(response));
        let dns_server = Self::select_dns_server(dns_servers, true);
        let dns_handle = match state
            .dns_sockets
            .ensure_socket(&mut state.stack, dns_server)
        {
            Ok(handle) => handle,
            Err(e) => {
                Self::fail_dns_group(state, group_id, e);
                return;
            }
        };

        Self::start_dns_queries_for_group(state, group_id, domain, dns_server, dns_handle, true);
    }

    fn try_resolve_dns_group(
        dns_queries: &mut HashMap<u16, DnsQueryState>,
        dns_groups: &mut HashMap<u32, DnsQueryGroup>,
        dns_cache: &mut Cache<String, DnsCacheValue>,
        group_id: u32,
    ) {
        let group = match dns_groups.get_mut(&group_id) {
            Some(group) => group,
            None => return,
        };

        if group.response.is_some() {
            let result = match group.prefer_ipv6 {
                true => match (&group.ipv6_result, &group.ipv4_result) {
                    (Some(Ok(v6_records)), _) if !v6_records.is_empty() => {
                        log::info!("DNS resolved: {} -> {}", group.domain, format_ip(v6_records[0].address));
                        Some(Ok(v6_records[0].address))
                    }
                    (_, Some(Ok(v4_records))) if !v4_records.is_empty() => {
                        log::info!("DNS resolved: {} -> {}", group.domain, format_ip(v4_records[0].address));
                        Some(Ok(v4_records[0].address))
                    }
                    (Some(_), Some(_)) => {
                        let err = match (&group.ipv6_result, &group.ipv4_result) {
                            (Some(Err(err)), _) if !matches!(err, DnsError::NoRecords) => err.clone(),
                            (_, Some(Err(err))) if !matches!(err, DnsError::NoRecords) => err.clone(),
                            _ => DnsError::NoRecords,
                        };
                        log::warn!("DNS resolution failed: {} -> {:?}", group.domain, err);
                        Some(Err(err))
                    }
                    _ => None,
                },
                false => match (&group.ipv4_result, &group.ipv6_result) {
                    (Some(Ok(v4_records)), _) if !v4_records.is_empty() => {
                        log::info!("DNS resolved: {} -> {}", group.domain, format_ip(v4_records[0].address));
                        Some(Ok(v4_records[0].address))
                    }
                    (_, Some(Ok(v6_records))) if !v6_records.is_empty() => {
                        log::info!("DNS resolved: {} -> {}", group.domain, format_ip(v6_records[0].address));
                        Some(Ok(v6_records[0].address))
                    }
                    (Some(_), Some(_)) => {
                        let err = match (&group.ipv4_result, &group.ipv6_result) {
                            (Some(Err(err)), _) if !matches!(err, DnsError::NoRecords) => err.clone(),
                            (_, Some(Err(err))) if !matches!(err, DnsError::NoRecords) => err.clone(),
                            _ => DnsError::NoRecords,
                        };
                        log::warn!("DNS resolution failed: {} -> {:?}", group.domain, err);
                        Some(Err(err))
                    }
                    _ => None,
                },
            };

            if let Some(result) = result {
                let mapped = result.map_err(ManagerError::Dns);
                if let Some(response) = group.response.take()
                    && response.send(mapped).is_err()
                {
                    log::trace!("Failed to send DNS response: receiver dropped");
                }
            }
        }

        if group.ipv4_result.is_some() && group.ipv6_result.is_some() {
            let mut all_records: Vec<DnsRecord> = Vec::new();
            if let Some(Ok(v4)) = &group.ipv4_result {
                all_records.extend(v4.iter().cloned());
            }
            if let Some(Ok(v6)) = &group.ipv6_result {
                all_records.extend(v6.iter().cloned());
            }
            if !all_records.is_empty() {
                let domain = group.domain.clone();
                dns_cache_insert(dns_cache, domain.clone(), &all_records);
                log::debug!("DNS cache updated: {} ({} records)", domain, all_records.len());
            }

            if let Some(response_all) = group.response_all.take() {
                let all_ips: Vec<IpAddress> = all_records.iter().map(|record| record.address).collect();
                if all_ips.is_empty() {
                    let err = match (&group.ipv4_result, &group.ipv6_result) {
                        (Some(Err(err)), _) if !matches!(err, DnsError::NoRecords) => err.clone(),
                        (_, Some(Err(err))) if !matches!(err, DnsError::NoRecords) => err.clone(),
                        _ => DnsError::NoRecords,
                    };
                    log::warn!("DNS resolution failed: {} -> {:?}", group.domain, err);
                    if response_all.send(Err(ManagerError::Dns(err))).is_err() {
                        log::trace!("DNS response dropped: receiver closed");
                    }
                } else {
                    log::info!(
                        "DNS resolved: {} -> [{}]",
                        group.domain,
                        all_ips.iter().map(|ip| format_ip(*ip)).collect::<Vec<_>>().join(", ")
                    );
                    if response_all.send(Ok(all_ips)).is_err() {
                        log::trace!("DNS response dropped: receiver closed");
                    }
                }
            }

            dns_groups.remove(&group_id);
            dns_queries.retain(|_, state| state.group_id != group_id);
        }
    }

    fn select_dns_server(dns_servers: &[IpAddress], prefer_ipv6: bool) -> IpAddress {
        if dns_servers.is_empty() {
            return IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(1, 1, 1, 1));
        }

        let start = DNS_SERVER_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let len = dns_servers.len();
        for offset in 0..len {
            let idx = (start + offset) % len;
            let server = dns_servers[idx];
            if prefer_ipv6 && matches!(server, IpAddress::Ipv6(_)) {
                return server;
            }
            if !prefer_ipv6 && matches!(server, IpAddress::Ipv4(_)) {
                return server;
            }
        }

        dns_servers[start % len]
    }
}
