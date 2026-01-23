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
    #[serde(rename = "type")]
    pub account_type: Option<String>,
    pub model: Option<String>,
    pub name: Option<String>,
    pub key: Option<String>,
    pub key_type: Option<String>,
    #[serde(rename = "tunnel_type")]
    pub tun_type: Option<String>,
    pub account: Account,
    pub config: AccountConfig,
    pub warp_enabled: Option<bool>,
    pub waitlist_enabled: Option<bool>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub tos: Option<String>,
    pub place: Option<i32>,
    pub locale: Option<String>,
    pub enabled: Option<bool>,
    pub install_id: Option<String>,
    pub token: Option<String>,
    pub fcm_token: Option<String>,
    #[serde(rename = "serial_number")]
    pub serial: Option<String>,
    pub policy: Option<Policy>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    pub id: String,
    pub account_type: Option<String>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub managed: Option<String>,
    pub organization: Option<String>,
    pub premium_data: Option<i64>,
    pub quota: Option<i64>,
    pub warp_plus: Option<bool>,
    pub referral_count: Option<i32>,
    pub referral_renewal_countdown: Option<i32>,
    pub role: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountConfig {
    pub client_id: Option<String>,
    pub peers: Option<Vec<Peer>>,
    #[serde(rename = "interface")]
    pub interface_config: Option<InterfaceConfig>,
    pub services: Option<Services>,
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
    pub host: Option<String>,
    pub ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Services {
    pub http_proxy: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub tunnel_protocol: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    pub code: Option<i32>,
    pub message: Option<String>,
    pub errors: Option<Vec<ApiErrorDetail>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    pub code: Option<i32>,
    pub message: Option<String>,
}
