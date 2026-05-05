mod grpc_server;
mod store;

use grpc_server::{
    pb::key_store_server::KeyStoreServer,
    KeyStoreService,
};
use store::KeyStore;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let port      = std::env::var("PORT").unwrap_or_else(|_| "50070".to_string());
    let share_dir = std::env::var("SHARE_FILE_DIR").unwrap_or_else(|_| "./data".to_string());
    let master_key = std::env::var("SHARE_FILE_KEY")
        .unwrap_or_else(|_| "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

    let addr = format!("0.0.0.0:{port}").parse()?;
    let ks   = KeyStore::new(&share_dir, &master_key)?;

    tracing::info!("kosh-keystore listening on {addr} dir={share_dir}");

    Server::builder()
        .add_service(KeyStoreServer::new(KeyStoreService::new(ks)))
        .serve(addr)
        .await?;

    Ok(())
}
