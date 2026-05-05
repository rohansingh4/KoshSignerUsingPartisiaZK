use crate::config::Config;
use anyhow::Result;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init(config: &Config) -> Result<()> {
    let filter =
        EnvFilter::try_new(config.log_filter.clone()).or_else(|_| EnvFilter::try_new("info"))?;

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();

    Ok(())
}
