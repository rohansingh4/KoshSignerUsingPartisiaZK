mod action_builders;
mod api;
mod app;
mod chain_relay;
mod config;
mod coordinator;
mod evm_broadcaster;
mod jobs;
mod keystore;
mod observability;
mod orchestrator;
mod party_runtime;
mod passkeys;
mod policy;
mod pqc;
mod threshold_read;

use anyhow::Result;
use app::Application;
use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    observability::init(&config)?;

    let app = Application::build(config).await?;
    app.run().await
}
