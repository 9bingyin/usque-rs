// DNS query state for a single query (A or AAAA)
struct DnsQueryState {
    group_id: u32,
    query_type: DnsRecordType,
}

// Happy Eyeballs: tracks paired A/AAAA queries
struct DnsQueryGroup {
    domain: String,
    response: Option<oneshot::Sender<Result<IpAddress, ManagerError>>>, // Option to allow early response
    response_all: Option<oneshot::Sender<Result<Vec<IpAddress>, ManagerError>>>, // For resolve_all
    ipv4_result: Option<Result<Vec<DnsRecord>, DnsError>>,
    ipv6_result: Option<Result<Vec<DnsRecord>, DnsError>>,
    created_at: Instant,
    prefer_ipv6: bool,
}

// DNS cache value: stores multiple IPs with their expiration times
struct DnsCacheValue {
    records: Vec<(IpAddress, Instant)>, // (ip, expires_at)
}

// DNS cache capacity
const DNS_CACHE_CAPACITY: usize = 1024;

// Helper functions for DNS cache operations
fn dns_cache_get(
    cache: &Cache<String, DnsCacheValue>,
    domain: &str,
    prefer_ipv6: bool,
) -> Option<IpAddress> {
    let value = cache.get(domain)?;
    let now = Instant::now();

    // Count valid records by type without allocation
    let mut v6_count = 0usize;
    let mut v4_count = 0usize;
    for (ip, exp) in &value.records {
        if *exp > now {
            match ip {
                IpAddress::Ipv6(_) => v6_count += 1,
                IpAddress::Ipv4(_) => v4_count += 1,
            }
        }
    }

    let total = v6_count + v4_count;
    if total == 0 {
        return None;
    }

    // Select target type and index for load balancing
    let (target_v6, target_count) = if prefer_ipv6 {
        if v6_count > 0 {
            (true, v6_count)
        } else {
            (false, v4_count)
        }
    } else if v4_count > 0 {
        (false, v4_count)
    } else {
        (true, v6_count)
    };

    let target_idx = rand::rng().random_range(0..target_count);

    // Find the target record
    let mut idx = 0usize;
    for (ip, exp) in &value.records {
        if *exp > now {
            let is_v6 = matches!(ip, IpAddress::Ipv6(_));
            if is_v6 == target_v6 {
                if idx == target_idx {
                    return Some(*ip);
                }
                idx += 1;
            }
        }
    }

    None
}

// Get all valid IP addresses from cache (for Happy Eyeballs connection racing)
fn dns_cache_get_all(cache: &Cache<String, DnsCacheValue>, domain: &str) -> Option<Vec<IpAddress>> {
    let value = cache.get(domain)?;
    let now = Instant::now();

    let valid_ips: Vec<IpAddress> = value
        .records
        .iter()
        .filter(|(_, exp)| *exp > now)
        .map(|(ip, _)| *ip)
        .collect();

    if valid_ips.is_empty() {
        None
    } else {
        Some(valid_ips)
    }
}

fn dns_cache_insert(
    cache: &mut Cache<String, DnsCacheValue>,
    domain: String,
    records: &[DnsRecord],
) {
    let now = Instant::now();
    let entries: Vec<(IpAddress, Instant)> = records
        .iter()
        .map(|r| (r.address, now + Duration::from_secs(r.ttl as u64)))
        .collect();
    cache.insert(domain, DnsCacheValue { records: entries });
}
