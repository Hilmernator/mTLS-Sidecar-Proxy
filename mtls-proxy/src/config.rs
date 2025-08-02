use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use std::fs;


#[derive(Parser, Debug)]
#[command(name = "mpc-mtls", version, about = "mTLS sidecar proxy for MCP")]
pub struct Cli {
    #[arg(long, default_value = "examples/proxy.yaml")]
    pub config: PathBuf,

    #[arg(long, default_value = "info")]
    pub log_level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen: String,
    pub upstream: String,
    pub tls: TlsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub ca_file: String,
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub client_key: String,
}


pub fn load_config() -> Result<(Cli, Config)> {
    let cli = Cli::parse();

    let yaml = fs::read_to_string(&cli.config).with_context(|| format!("Failed to read {}", cli.config.display()))?;

    let cfg: Config = serde_yaml::from_str(&yaml).context("Failed to parse YAML in proxy.yaml")?;
    Ok((cli, cfg))
}