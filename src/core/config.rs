use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub private_key: String,
    pub endpoint_v4: String,
    pub endpoint_v6: String,
    pub endpoint_pub_key: String,
    pub license: String,
    pub id: String,
    pub access_token: String,
    #[serde(rename = "ipv4")]
    pub ipv4: String,
    #[serde(rename = "ipv6")]
    pub ipv6: String,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn get_private_key_der(&self) -> Result<Vec<u8>, ConfigError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.private_key)
            .map_err(|e| {
                ConfigError::Parse(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to decode private key: {}", e),
                )))
            })
    }

    pub fn get_endpoint_pub_key_der(&self) -> Result<Vec<u8>, ConfigError> {
        let pem_content = &self.endpoint_pub_key;
        let lines: Vec<&str> = pem_content
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let base64_content = lines.join("");

        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&base64_content)
            .map_err(|e| {
                ConfigError::Parse(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to decode endpoint public key: {}", e),
                )))
            })
    }

    pub fn get_signing_key(&self) -> Result<p256::ecdsa::SigningKey, ConfigError> {
        use p256::SecretKey;
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::DecodePrivateKey;

        let der = self.get_private_key_der()?;

        // Try SEC1 format first (Go version compatibility)
        if let Ok(secret_key) = SecretKey::from_sec1_der(&der) {
            return Ok(SigningKey::from(&secret_key));
        }

        // Fallback to PKCS#8 format
        SigningKey::from_pkcs8_der(&der).map_err(|e| ConfigError::Crypto(e.to_string()))
    }
}

#[derive(Error, Debug)]
pub enum WgConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("missing field: [{section}] {key}")]
    MissingField { section: String, key: String },
    #[error("invalid value: [{section}] {key}: {reason}")]
    InvalidValue {
        section: String,
        key: String,
        reason: String,
    },
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub struct WgConfig {
    // [Account]
    pub device_id: String,
    pub private_key: String,
    pub token: String,
    pub client_id: String,
    pub account_type: String,
    // [Device]
    pub mtu: u16,
    // [Peer]
    pub peer_public_key: String,
    pub endpoint: String,
    pub endpoint6: Option<String>,
    pub keepalive: u16,
    // [Interface]
    pub address: String,
    pub address6: Option<String>,
    pub dns: String,
}

impl WgConfig {
    pub fn load(path: &str) -> Result<Self, WgConfigError> {
        let mut ini = configparser::ini::Ini::new_cs();
        ini.load(path)
            .map_err(|e| WgConfigError::Parse(e.to_string()))?;

        let get = |section: &str, key: &str| -> Result<String, WgConfigError> {
            ini.get(section, key)
                .ok_or_else(|| WgConfigError::MissingField {
                    section: section.to_string(),
                    key: key.to_string(),
                })
        };

        let get_opt = |section: &str, key: &str| -> Option<String> { ini.get(section, key) };

        Ok(Self {
            device_id: get("Account", "Device")?,
            private_key: get("Account", "PrivateKey")?,
            token: get("Account", "Token")?,
            client_id: get("Account", "ClientId")?,
            account_type: get_opt("Account", "Type").unwrap_or_else(|| "free".to_string()),
            mtu: get_opt("Device", "MTU")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1280),
            peer_public_key: get("Peer", "PublicKey")?,
            endpoint: get("Peer", "Endpoint")?,
            endpoint6: get_opt("Peer", "Endpoint6"),
            keepalive: get_opt("Peer", "KeepAlive")
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            address: get("Interface", "Address")?,
            address6: get_opt("Interface", "Address6"),
            dns: get_opt("Interface", "DNS").unwrap_or_else(|| "1.1.1.1".to_string()),
        })
    }

    pub fn save(&self, path: &str) -> Result<(), WgConfigError> {
        let mut ini = configparser::ini::Ini::new_cs();

        ini.set("Account", "Device", Some(self.device_id.clone()));
        ini.set("Account", "PrivateKey", Some(self.private_key.clone()));
        ini.set("Account", "Token", Some(self.token.clone()));
        ini.set("Account", "ClientId", Some(self.client_id.clone()));
        ini.set("Account", "Type", Some(self.account_type.clone()));

        ini.set("Device", "MTU", Some(self.mtu.to_string()));

        ini.set("Peer", "PublicKey", Some(self.peer_public_key.clone()));
        ini.set("Peer", "Endpoint", Some(self.endpoint.clone()));
        if let Some(ref ep6) = self.endpoint6 {
            ini.set("Peer", "Endpoint6", Some(ep6.clone()));
        }
        ini.set("Peer", "KeepAlive", Some(self.keepalive.to_string()));

        ini.set("Interface", "Address", Some(self.address.clone()));
        if let Some(ref addr6) = self.address6 {
            ini.set("Interface", "Address6", Some(addr6.clone()));
        }
        ini.set("Interface", "DNS", Some(self.dns.clone()));

        ini.write(path)
            .map_err(|e| WgConfigError::Parse(e.to_string()))?;
        Ok(())
    }

    pub fn get_private_key_bytes(&self) -> Result<[u8; 32], WgConfigError> {
        let decoded = base64::engine::general_purpose::STANDARD.decode(&self.private_key)?;
        decoded
            .try_into()
            .map_err(|v: Vec<u8>| WgConfigError::InvalidValue {
                section: "Account".to_string(),
                key: "PrivateKey".to_string(),
                reason: format!("expected 32 bytes, got {}", v.len()),
            })
    }

    pub fn get_client_id_bytes(&self) -> Result<[u8; 3], WgConfigError> {
        let decoded = base64::engine::general_purpose::STANDARD.decode(&self.client_id)?;
        decoded
            .try_into()
            .map_err(|v: Vec<u8>| WgConfigError::InvalidValue {
                section: "Account".to_string(),
                key: "ClientId".to_string(),
                reason: format!("expected 3 bytes, got {}", v.len()),
            })
    }

    pub fn get_peer_public_key_bytes(&self) -> Result<[u8; 32], WgConfigError> {
        let decoded = base64::engine::general_purpose::STANDARD.decode(&self.peer_public_key)?;
        decoded
            .try_into()
            .map_err(|v: Vec<u8>| WgConfigError::InvalidValue {
                section: "Peer".to_string(),
                key: "PublicKey".to_string(),
                reason: format!("expected 32 bytes, got {}", v.len()),
            })
    }

    pub fn get_endpoint_addr(&self) -> Result<SocketAddr, WgConfigError> {
        self.endpoint
            .parse()
            .map_err(|e| WgConfigError::InvalidValue {
                section: "Peer".to_string(),
                key: "Endpoint".to_string(),
                reason: format!("{}", e),
            })
    }

    /// Extract the IPv4 address without CIDR suffix.
    pub fn ipv4_address(&self) -> &str {
        self.address.split('/').next().unwrap_or(&self.address)
    }

    /// Extract the IPv6 address without CIDR suffix, if present.
    pub fn ipv6_address(&self) -> Option<&str> {
        self.address6
            .as_deref()
            .map(|a| a.split('/').next().unwrap_or(a))
    }
}
