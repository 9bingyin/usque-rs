use crate::core::{config::Config, crypto};
use crate::infra::cloudflare::CloudflareClient;
use std::net::SocketAddr;

pub async fn register_device(
    config_path: &str,
    model: &str,
    locale: &str,
    device_name: Option<&str>,
    jwt: Option<&str>,
    _accept_tos: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;

    log::info!("registering new device...");
    if jwt.is_some() {
        log::info!("using ZeroTrust authentication");
    }

    let client = CloudflareClient::new();

    // Step 1: Register with random WG key
    let account = client.register(model, locale, jwt).await?;
    log::info!("account created: {}", account.id);

    let token = account.token.clone().ok_or("No token in response")?;

    // Step 2: Generate ECDSA key pair
    let key_pair = crypto::generate_ec_key_pair()?;
    log::debug!("ECDSA key pair generated");

    // Step 3: Enroll MASQUE key
    let name = device_name.unwrap_or("usque-rs");
    let updated = client
        .enroll_key(&account.id, &token, &key_pair.public_key_der, Some(name))
        .await?;
    log::debug!("MASQUE key enrolled");

    // Step 4: Build and save config
    let endpoint_v4 = updated
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v4.clone());

    let endpoint_v6 = updated
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .and_then(|p| p.endpoint.as_ref())
        .and_then(|e| e.v6.clone());

    let endpoint_pub_key = updated
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .map(|p| p.public_key.clone());

    let ipv4 = updated
        .config
        .interface_config
        .as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v4.clone());

    let ipv6 = updated
        .config
        .interface_config
        .as_ref()
        .and_then(|i| i.addresses.as_ref())
        .and_then(|a| a.v6.clone());

    let license = updated.account.license.clone().unwrap_or_default();

    if endpoint_v4.as_deref().unwrap_or("").is_empty()
        && endpoint_v6.as_deref().unwrap_or("").is_empty()
    {
        return Err("No endpoint info in response".into());
    }

    let endpoint_pub_key = endpoint_pub_key
        .filter(|k| !k.trim().is_empty())
        .ok_or("No endpoint public key in response")?;

    if ipv4.as_deref().unwrap_or("").is_empty() && ipv6.as_deref().unwrap_or("").is_empty() {
        return Err("No interface addresses in response".into());
    }

    let cfg = Config {
        private_key: base64::engine::general_purpose::STANDARD.encode(&key_pair.private_key_der),
        endpoint_v4: endpoint_v4.unwrap_or_default(),
        endpoint_v6: endpoint_v6.unwrap_or_default(),
        endpoint_pub_key,
        license,
        id: updated.id.clone(),
        access_token: token,
        ipv4: ipv4.unwrap_or_default(),
        ipv6: ipv6.unwrap_or_default(),
    };

    cfg.save(config_path)?;
    log::debug!("config saved to {}", config_path);
    log::info!("registration successful");

    Ok(())
}

pub async fn register_wg_device(
    config_path: &str,
    model: &str,
    locale: &str,
    jwt: Option<&str>,
    _accept_tos: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;

    log::info!("registering new WireGuard device...");
    if jwt.is_some() {
        log::info!("using ZeroTrust authentication");
    }

    // Step 1: Generate Curve25519 key pair
    let wg_keys = crypto::generate_wg_key_pair()?;
    log::debug!("WireGuard key pair generated");

    // Step 2: Register with real WG public key
    let client = CloudflareClient::new();
    let account = client
        .register_wg(&wg_keys.public_key_base64, model, locale, jwt)
        .await?;
    log::info!("account created: {}", account.id);

    let token = account.token.clone().ok_or("No token in response")?;

    // Step 3: Extract peer config
    let peer = account
        .config
        .peers
        .as_ref()
        .and_then(|p| p.first())
        .ok_or("No peer info in response")?;

    let peer_public_key = peer.public_key.clone();
    let endpoint_v4 = peer
        .endpoint
        .as_ref()
        .and_then(|e| e.v4.clone())
        .unwrap_or_default();
    let endpoint_v6 = peer.endpoint.as_ref().and_then(|e| e.v6.clone());

    let interface = account
        .config
        .interface_config
        .as_ref()
        .and_then(|i| i.addresses.as_ref())
        .ok_or("No interface addresses in response")?;

    let ipv4 = interface.v4.clone().unwrap_or_default();
    let ipv6 = interface.v6.clone();

    let client_id = account
        .config
        .client_id
        .clone()
        .ok_or("No client_id in response")?;

    if endpoint_v4.is_empty() {
        return Err("No endpoint v4 in response".into());
    }
    if ipv4.is_empty() {
        return Err("No IPv4 address in response".into());
    }

    // Step 4: Build endpoint string (IP:port, default port 2408)
    // Cloudflare API may return port 0; replace with default WG port 2408.
    let endpoint_str = match endpoint_v4.parse::<SocketAddr>() {
        Ok(addr) if addr.port() == 0 => SocketAddr::new(addr.ip(), 2408).to_string(),
        Ok(_) => endpoint_v4.clone(),
        Err(_) => {
            if let Ok(ip) = endpoint_v4.parse::<std::net::IpAddr>() {
                SocketAddr::new(ip, 2408).to_string()
            } else {
                format!("{}:2408", endpoint_v4)
            }
        }
    };

    let endpoint6_str = endpoint_v6.map(|v6| {
        let trimmed = v6.trim_matches(|c| c == '[' || c == ']');
        match trimmed.parse::<SocketAddr>().or_else(|_| v6.parse::<SocketAddr>()) {
            Ok(addr) if addr.port() == 0 => SocketAddr::new(addr.ip(), 2408).to_string(),
            Ok(addr) => addr.to_string(),
            Err(_) => {
                let ip_str = trimmed.split("]:").next().unwrap_or(trimmed);
                if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
                    SocketAddr::new(std::net::IpAddr::V6(ip), 2408).to_string()
                } else {
                    format!("[{}]:2408", ip_str)
                }
            }
        }
    });

    // Step 5: Build and save WG config
    let private_key_b64 = base64::engine::general_purpose::STANDARD.encode(wg_keys.private_key);

    let wg_cfg = crate::core::config::WgConfig {
        device_id: account.id.clone(),
        private_key: private_key_b64,
        token,
        client_id: client_id.clone(),
        account_type: "free".to_string(),
        mtu: 1280,
        peer_public_key,
        endpoint: endpoint_str,
        endpoint6: endpoint6_str,
        keepalive: 30,
        address: format!("{}/32", ipv4),
        address6: ipv6.map(|v6| format!("{}/128", v6)),
        dns: "1.1.1.1".to_string(),
    };

    wg_cfg.save(config_path)?;
    log::debug!("config saved to {}", config_path);
    log::info!("registration successful");

    // Print reserved value for reference
    let client_id_bytes = base64::engine::general_purpose::STANDARD
        .decode(&client_id)
        .unwrap_or_default();
    log::debug!("reserved: {:?} (base64: {})", client_id_bytes, client_id);

    Ok(())
}
