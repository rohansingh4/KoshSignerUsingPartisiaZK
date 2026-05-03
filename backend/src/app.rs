use crate::{
    api,
    chain_relay::{ChainRelay, ChainRelayConfig},
    config::Config,
    coordinator::BulletinBoard,
    evm_broadcaster::{EvmBroadcaster, EvmBroadcasterConfig},
    jobs::JobManager,
    keystore::KeyStore,
    policy::PolicyStore,
};
use anyhow::{Context, Result};
use axum::Router;
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, sync::RwLock};
use tracing::info;

#[derive(Clone, Debug, Serialize)]
pub struct ActiveRuntimeState {
    pub mode: String,
    pub contract_address: String,
    pub key_id: u32,
    pub sender_address: Option<String>,
    pub evm_address: Option<String>,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub jobs: JobManager,
    pub coordinator: BulletinBoard,
    pub policy: PolicyStore,
    pub keystore: Option<KeyStore>,
    pub chain_relay: ChainRelay,
    pub evm_broadcaster: EvmBroadcaster,
    pub database: Option<PgPool>,
    pub active_runtime: Arc<RwLock<Option<ActiveRuntimeState>>>,
}

pub struct Application {
    config: Arc<Config>,
    state: AppState,
    router: Router,
}

impl Application {
    pub async fn build(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        let database = connect_database(config.database_url.as_deref()).await?;
        let keystore = build_keystore(&config)?;
        let chain_relay = build_chain_relay(&config);
        let evm_broadcaster = build_evm_broadcaster(&config);
        let state = AppState {
            config: Arc::clone(&config),
            jobs: JobManager::new(),
            coordinator: BulletinBoard::new(),
            policy: PolicyStore::new(),
            keystore,
            chain_relay,
            evm_broadcaster,
            database,
            active_runtime: Arc::new(RwLock::new(None)),
        };
        let router = api::routes::router(state.clone());

        Ok(Self {
            config,
            state,
            router,
        })
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .with_context(|| format!("bind {}", self.config.bind_addr))?;

        info!(addr=%self.config.bind_addr, service=%self.state.config.service_name, "kosh backend listening");
        axum::serve(listener, self.router)
            .await
            .context("serve axum")
    }
}

async fn connect_database(database_url: Option<&str>) -> Result<Option<PgPool>> {
    let Some(database_url) = database_url else {
        return Ok(None);
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_lazy(database_url)
        .context("create postgres pool")?;

    Ok(Some(pool))
}

fn build_keystore(config: &Config) -> Result<Option<KeyStore>> {
    let Some(master_key) = config.keystore_master_key.as_deref() else {
        return Ok(None);
    };
    let root = config
        .keystore_root_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(".kosh-backend/keystore"));
    Ok(Some(KeyStore::new(root, master_key)?))
}

fn build_chain_relay(config: &Config) -> ChainRelay {
    ChainRelay::new(ChainRelayConfig {
        node_urls: config.partisia_node_urls.clone(),
        sender_address: config.partisia_sender_address.clone(),
        sender_key: config.partisia_sender_key.clone(),
        confirm_timeout: config.partisia_confirm_timeout,
        poll_interval: config.partisia_poll_interval,
        max_retries: config.partisia_max_retries,
    })
}

fn build_evm_broadcaster(config: &Config) -> EvmBroadcaster {
    EvmBroadcaster::new(EvmBroadcasterConfig {
        rpc_url: config.sepolia_rpc_url.clone(),
        chain_id: config.sepolia_chain_id,
    })
}
