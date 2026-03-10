use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub tls: TlsFileConfig,
    pub telemetry: TelemetryConfig,
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ListenConfig {
    pub http: String,
    pub https: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsFileConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TelemetryConfig {
    pub otlp_endpoint: String,
}

/// A path-prefix sub-route within a virtual host.
/// Matched longest-prefix-first when multiple entries share a prefix.
#[derive(Debug, Deserialize, Clone)]
pub struct PathRoute {
    pub prefix: String,
    pub backend: String,
    /// Strip the matched prefix before forwarding to the backend.
    #[serde(default)]
    pub strip_prefix: bool,
    #[serde(default)]
    pub websocket: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    pub host_prefix: String,
    pub backend: String,
    #[serde(default)]
    pub websocket: bool,
    /// Optional path-based sub-routes (longest prefix wins).
    /// If the request path matches a sub-route, its backend is used instead.
    #[serde(default)]
    pub paths: Vec<PathRoute>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading config from {path}"))?;
        toml::from_str(&raw).with_context(|| "parsing config.toml")
    }
}
