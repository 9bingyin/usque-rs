use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct Registration {
    pub key: String,
    pub install_id: String,
    pub fcm_token: String,
    pub tos: String,
    pub model: String,
    #[serde(rename = "serial_number")]
    pub serial: String,
    pub os_version: String,
    pub key_type: String,
    #[serde(rename = "tunnel_type")]
    pub tun_type: String,
    pub locale: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceUpdate {
    pub key: String,
    pub key_type: String,
    #[serde(rename = "tunnel_type")]
    pub tun_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountData {
    pub id: String,
    pub account: Account,
    pub config: AccountConfig,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    pub license: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountConfig {
    pub peers: Option<Vec<Peer>>,
    #[serde(rename = "interface")]
    pub interface_config: Option<InterfaceConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceConfig {
    pub addresses: Option<Addresses>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Addresses {
    pub v4: Option<String>,
    pub v6: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: Option<Endpoint>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Endpoint {
    pub v4: Option<String>,
    pub v6: Option<String>,
}
