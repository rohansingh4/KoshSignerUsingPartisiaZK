use anyhow::{Context, Result};
use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub cors_allowed_origins: Vec<String>,
    pub database_url: Option<String>,
    pub log_filter: String,
    pub service_name: String,
    pub keystore_root_dir: Option<PathBuf>,
    pub keystore_master_key: Option<String>,
    pub partisia_node_urls: Vec<String>,
    pub partisia_sender_key: Option<String>,
    pub partisia_sender_address: Option<String>,
    pub partisia_confirm_timeout: Duration,
    pub partisia_poll_interval: Duration,
    pub partisia_max_retries: u32,
    pub sepolia_rpc_url: Option<String>,
    pub sepolia_chain_id: u64,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_addr = env::var("KOSH_BACKEND_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()
            .with_context(|| "invalid KOSH_BACKEND_BIND_ADDR")?;

        let database_url = env::var("KOSH_BACKEND_DATABASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let cors_allowed_origins = env::var("KOSH_CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:5173,http://127.0.0.1:5173".to_string())
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let log_filter =
            env::var("KOSH_BACKEND_LOG").unwrap_or_else(|_| "info,kosh_backend=debug".to_string());
        let service_name =
            env::var("KOSH_BACKEND_SERVICE_NAME").unwrap_or_else(|_| "kosh-backend".to_string());
        let keystore_root_dir = env::var("KOSH_KEYSTORE_ROOT_DIR")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from);
        let keystore_master_key = env::var("KOSH_KEYSTORE_MASTER_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let partisia_node_urls = env::var("PARTISIA_NODE_URLS")
            .or_else(|_| env::var("PARTISIA_NODE_URL"))
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let partisia_sender_key = env::var("PARTISIA_SENDER_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let partisia_sender_address = env::var("PARTISIA_SENDER_ADDRESS")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let partisia_confirm_timeout = Duration::from_millis(
            env::var("PARTISIA_CONFIRM_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30_000),
        );
        let partisia_poll_interval = Duration::from_millis(
            env::var("KOSH_PARTISIA_POLL_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500),
        );
        let partisia_max_retries = env::var("PARTISIA_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7);
        let sepolia_rpc_url = env::var("KOSH_SEPOLIA_RPC_URL")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let sepolia_chain_id = env::var("KOSH_SEPOLIA_CHAIN_ID")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(11155111);
        let webauthn_rp_id =
            env::var("KOSH_WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
        let webauthn_origin = env::var("KOSH_WEBAUTHN_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:5173".to_string());

        Ok(Self {
            bind_addr,
            cors_allowed_origins,
            database_url,
            log_filter,
            service_name,
            keystore_root_dir,
            keystore_master_key,
            partisia_node_urls,
            partisia_sender_key,
            partisia_sender_address,
            partisia_confirm_timeout,
            partisia_poll_interval,
            partisia_max_retries,
            sepolia_rpc_url,
            sepolia_chain_id,
            webauthn_rp_id,
            webauthn_origin,
        })
    }
}
