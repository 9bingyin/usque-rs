use crate::api::models::*;
use crate::crypto::{generate_random_serial, generate_random_wg_pubkey, time_as_cf_string};
use reqwest::header::{HeaderMap, HeaderValue};
use thiserror::Error;

pub const API_URL: &str = "https://api.cloudflareclient.com";
pub const API_VERSION: &str = "v0a4471";
pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub const CONNECT_URI: &str = "https://cloudflareaccess.com";
pub const DEFAULT_MODEL: &str = "PC";
pub const KEY_TYPE_WG: &str = "curve25519";
pub const TUN_TYPE_WG: &str = "wireguard";
pub const KEY_TYPE_MASQUE: &str = "secp256r1";
pub const TUN_TYPE_MASQUE: &str = "masque";
pub const DEFAULT_LOCALE: &str = "en_US";

#[derive(Error, Debug)]
pub enum ApiClientError {
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("crypto error: {0}")]
    CryptoError(String),
}

pub struct CloudflareClient {
    client: reqwest::Client,
    base_url: String,
}

fn default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("User-Agent", HeaderValue::from_static("WARP for Android"));
    headers.insert(
        "CF-Client-Version",
        HeaderValue::from_static("a-6.35-4471"),
    );
    headers.insert(
        "Content-Type",
        HeaderValue::from_static("application/json; charset=UTF-8"),
    );
    headers.insert("Connection", HeaderValue::from_static("Keep-Alive"));
    headers
}

impl CloudflareClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: format!("{}/{}", API_URL, API_VERSION),
        }
    }

    pub async fn register(
        &self,
        model: &str,
        locale: &str,
        jwt: Option<&str>,
    ) -> Result<AccountData, ApiClientError> {
        let wg_key = generate_random_wg_pubkey()
            .map_err(|e| ApiClientError::CryptoError(e.to_string()))?;
        let serial = generate_random_serial()
            .map_err(|e| ApiClientError::CryptoError(e.to_string()))?;

        let registration = Registration {
            key: wg_key,
            install_id: String::new(),
            fcm_token: String::new(),
            tos: time_as_cf_string(chrono::Local::now()),
            model: model.to_string(),
            serial,
            os_version: String::new(),
            key_type: KEY_TYPE_WG.to_string(),
            tun_type: TUN_TYPE_WG.to_string(),
            locale: locale.to_string(),
        };

        let url = format!("{}/reg", self.base_url);
        let mut req = self.client.post(&url).headers(default_headers());

        if let Some(token) = jwt {
            req = req.header("CF-Access-Jwt-Assertion", token);
        }

        let resp = req.json(&registration).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiClientError::ApiError(format!(
                "registration failed: {} - {}",
                status, body
            )));
        }

        let account_data: AccountData = resp.json().await?;
        Ok(account_data)
    }

    pub async fn enroll_key(
        &self,
        account_id: &str,
        access_token: &str,
        pub_key: &[u8],
        device_name: Option<&str>,
    ) -> Result<AccountData, ApiClientError> {
        use base64::Engine;

        let device_update = DeviceUpdate {
            key: base64::engine::general_purpose::STANDARD.encode(pub_key),
            key_type: KEY_TYPE_MASQUE.to_string(),
            tun_type: TUN_TYPE_MASQUE.to_string(),
            name: device_name.map(|s| s.to_string()),
        };

        let url = format!("{}/reg/{}", self.base_url, account_id);
        let resp = self
            .client
            .patch(&url)
            .headers(default_headers())
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&device_update)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiClientError::ApiError(format!(
                "enroll key failed: {} - {}",
                status, body
            )));
        }

        let account_data: AccountData = resp.json().await?;
        Ok(account_data)
    }
}

impl Default for CloudflareClient {
    fn default() -> Self {
        Self::new()
    }
}
