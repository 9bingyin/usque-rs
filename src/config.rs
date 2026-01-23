use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    CryptoError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            .map_err(|e| ConfigError::ParseError(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to decode private key: {}", e),
            ))))
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
            .map_err(|e| ConfigError::ParseError(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to decode endpoint public key: {}", e),
            ))))
    }

    pub fn get_signing_key(&self) -> Result<p256::ecdsa::SigningKey, ConfigError> {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::DecodePrivateKey;
        use p256::SecretKey;

        let der = self.get_private_key_der()?;

        // Try SEC1 format first (Go version compatibility)
        if let Ok(secret_key) = SecretKey::from_sec1_der(&der) {
            return Ok(SigningKey::from(&secret_key));
        }

        // Fallback to PKCS#8 format
        SigningKey::from_pkcs8_der(&der)
            .map_err(|e| ConfigError::CryptoError(e.to_string()))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            endpoint_v4: String::new(),
            endpoint_v6: String::new(),
            endpoint_pub_key: String::new(),
            license: String::new(),
            id: String::new(),
            access_token: String::new(),
            ipv4: String::new(),
            ipv6: String::new(),
        }
    }
}
