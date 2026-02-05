use crate::core::config::Config;
use crate::core::crypto;
use crate::infra::cloudflare::CloudflareClient;

pub async fn enroll_device(
    config_path: &str,
    device_name: Option<&str>,
    regen_key: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;
    use p256::pkcs8::EncodePublicKey;

    println!("Enrolling device key...");

    // Load existing config
    let cfg = Config::load(config_path)?;
    println!("Config loaded from {}", config_path);

    // Get or regenerate key pair
    let (private_key_der, public_key_der) = if regen_key {
        println!("Regenerating key pair...");
        let key_pair = crypto::generate_ec_key_pair()?;
        (key_pair.private_key_der, key_pair.public_key_der)
    } else {
        let signing_key = cfg.get_signing_key()?;
        let public_key = signing_key.verifying_key();
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| format!("Failed to encode public key: {}", e))?
            .to_vec();
        let private_key_der = cfg.get_private_key_der()?;
        (private_key_der, public_key_der)
    };

    // Call API to re-enroll
    let client = CloudflareClient::new();
    let updated = client
        .enroll_key(&cfg.id, &cfg.access_token, &public_key_der, device_name)
        .await?;
    println!("MASQUE key enrolled");

    // Build updated config
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

    let license = updated
        .account
        .license
        .clone()
        .unwrap_or(cfg.license.clone());

    let endpoint_v4 = endpoint_v4.unwrap_or(cfg.endpoint_v4.clone());
    let endpoint_v6 = endpoint_v6.unwrap_or(cfg.endpoint_v6.clone());
    if endpoint_v4.trim().is_empty() && endpoint_v6.trim().is_empty() {
        return Err("No endpoint info in response or existing config".into());
    }

    let endpoint_pub_key = endpoint_pub_key.unwrap_or(cfg.endpoint_pub_key.clone());
    if endpoint_pub_key.trim().is_empty() {
        return Err("No endpoint public key in response or existing config".into());
    }

    let ipv4 = ipv4.unwrap_or(cfg.ipv4.clone());
    let ipv6 = ipv6.unwrap_or(cfg.ipv6.clone());
    if ipv4.trim().is_empty() && ipv6.trim().is_empty() {
        return Err("No interface addresses in response or existing config".into());
    }

    let new_cfg = Config {
        private_key: base64::engine::general_purpose::STANDARD.encode(&private_key_der),
        endpoint_v4,
        endpoint_v6,
        endpoint_pub_key,
        license,
        id: updated.id.clone(),
        access_token: cfg.access_token.clone(),
        ipv4,
        ipv6,
    };

    new_cfg.save(config_path)?;
    println!("Config saved to {}", config_path);

    Ok(())
}
