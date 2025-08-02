//! Binary entry-point for the mTLS side-car proxy.

mod config;
mod proxy; 
mod tls;

use anyhow::Result;
use tracing::{error, info};
use tracing_subscriber::{filter::LevelFilter, fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // ── 1. Load CLI flags + YAML config ────────────────────────────────────────
    let (cli, cfg) = config::load_config()?;

    // ── 2. Init structured logging (env -> overrides flag) ─────────────────────
    // e.g. RUST_LOG=debug cargo run
    let log_level = cli
        .log_level
        .parse::<LevelFilter>()
        .unwrap_or(LevelFilter::INFO);

    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.into()))
        .init();

    info!("Configuration loaded from {:?}", cli.config);
    info!("Listen   : {}", cfg.listen);
    info!("Upstream : {}", cfg.upstream);
    info!("CA file  : {}", cfg.tls.ca_file);

    // ── 3. Build and run the proxy ─────────────────────────────────────────────
    let proxy = proxy::Proxy::new(cfg)?;
    if let Err(e) = proxy.run().await {
        error!("Proxy exited with error: {:?}", e);
    }

    Ok(())
}
