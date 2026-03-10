use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct SshConfig {
    /// Address to bind the SSH listener on, e.g. "0.0.0.0:22" or "[::]:22".
    pub listen: String,
    /// Upstream backend address, e.g. "gitea-ssh.devtools.svc.cluster.local:2222".
    pub backend: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub tls: TlsFileConfig,
    pub telemetry: TelemetryConfig,
    pub routes: Vec<RouteConfig>,
    /// Optional SSH TCP passthrough (port 22 → Gitea SSH).
    pub ssh: Option<SshConfig>,
    /// Optional KNN-based DDoS detection.
    pub ddos: Option<DDoSConfig>,
    /// Optional per-identity rate limiting.
    pub rate_limit: Option<RateLimitConfig>,
    /// Optional per-request scanner detection.
    pub scanner: Option<ScannerConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DDoSConfig {
    pub model_path: String,
    #[serde(default = "default_k")]
    pub k: usize,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_window_capacity")]
    pub window_capacity: usize,
    #[serde(default = "default_min_events")]
    pub min_events: usize,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    #[serde(default = "default_rl_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub bypass_cidrs: Vec<String>,
    #[serde(default = "default_eviction_interval")]
    pub eviction_interval_secs: u64,
    #[serde(default = "default_stale_after")]
    pub stale_after_secs: u64,
    pub authenticated: BucketConfig,
    pub unauthenticated: BucketConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BucketConfig {
    pub burst: u32,
    pub rate: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScannerConfig {
    pub model_path: String,
    #[serde(default = "default_scanner_threshold")]
    pub threshold: f64,
    #[serde(default = "default_scanner_enabled")]
    pub enabled: bool,
    /// How often (seconds) to check the model file for changes. 0 = no hot-reload.
    #[serde(default = "default_scanner_poll_interval")]
    pub poll_interval_secs: u64,
    /// Bot allowlist rules. Verified bots bypass the scanner model.
    #[serde(default)]
    pub allowlist: Vec<BotAllowlistRule>,
    /// TTL (seconds) for verified bot IP cache entries.
    #[serde(default = "default_bot_cache_ttl")]
    pub bot_cache_ttl_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BotAllowlistRule {
    /// Case-insensitive UA prefix to match, e.g. "Googlebot".
    pub ua_prefix: String,
    /// Human-readable label for pipeline logs.
    pub reason: String,
    /// Reverse-DNS hostname suffixes for verification.
    /// e.g. ["googlebot.com", "google.com"]
    #[serde(default)]
    pub dns_suffixes: Vec<String>,
    /// CIDR ranges for instant IP verification.
    /// e.g. ["66.249.64.0/19"]
    #[serde(default)]
    pub cidrs: Vec<String>,
}

fn default_bot_cache_ttl() -> u64 { 86400 } // 24h

fn default_scanner_threshold() -> f64 { 0.5 }
fn default_scanner_enabled() -> bool { true }
fn default_scanner_poll_interval() -> u64 { 30 }

fn default_rl_enabled() -> bool { true }
fn default_eviction_interval() -> u64 { 300 }
fn default_stale_after() -> u64 { 600 }

fn default_k() -> usize { 5 }
fn default_threshold() -> f64 { 0.6 }
fn default_window_secs() -> u64 { 60 }
fn default_window_capacity() -> usize { 1000 }
fn default_min_events() -> usize { 10 }
fn default_enabled() -> bool { true }

#[derive(Debug, Deserialize, Clone)]
pub struct ListenConfig {
    /// HTTP listener address, e.g., "0.0.0.0:80" or "[::]:80".
    pub http: String,
    /// HTTPS listener address, e.g., "0.0.0.0:443" or "[::]:443".
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
    /// Port for the Prometheus metrics scrape endpoint. 0 = disabled.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

fn default_metrics_port() -> u16 { 9090 }

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
    /// URL for auth subrequest (like nginx `auth_request`).
    /// If set, the proxy makes an HTTP request to this URL before forwarding.
    /// A non-2xx response blocks the request with 403.
    #[serde(default)]
    pub auth_request: Option<String>,
    /// Headers to capture from the auth subrequest response and forward upstream.
    #[serde(default)]
    pub auth_capture_headers: Vec<String>,
    /// Prefix to prepend to the upstream path after stripping.
    #[serde(default)]
    pub upstream_path_prefix: Option<String>,
}

/// A URL rewrite rule: requests matching `pattern` are served the file at `target`.
#[derive(Debug, Deserialize, Clone)]
pub struct RewriteRule {
    /// Regex pattern matched against the request path.
    pub pattern: String,
    /// Static file path to serve (relative to `static_root`).
    pub target: String,
}

/// A find/replace rule applied to response bodies.
#[derive(Debug, Deserialize, Clone)]
pub struct BodyRewrite {
    /// String to find in the response body.
    pub find: String,
    /// String to replace it with.
    pub replace: String,
    /// Content-types to apply this rewrite to (e.g. `["text/html"]`).
    #[serde(default)]
    pub types: Vec<String>,
}

/// A response header to add to every response for this route.
#[derive(Debug, Deserialize, Clone)]
pub struct HeaderRule {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    pub host_prefix: String,
    pub backend: String,
    #[serde(default)]
    pub websocket: bool,
    /// When true, plain-HTTP requests for this host are forwarded as-is rather
    /// than being redirected to HTTPS. Defaults to false (redirect enforced).
    #[serde(default)]
    pub disable_secure_redirection: bool,
    /// Optional path-based sub-routes (longest prefix wins).
    /// If the request path matches a sub-route, its backend is used instead.
    #[serde(default)]
    pub paths: Vec<PathRoute>,
    /// Root directory for static file serving. If set, the proxy will try
    /// to serve files from this directory before forwarding to the upstream.
    #[serde(default)]
    pub static_root: Option<String>,
    /// Fallback file for SPA routing (e.g. "index.html").
    #[serde(default)]
    pub fallback: Option<String>,
    /// URL rewrite rules applied before static file lookup.
    #[serde(default)]
    pub rewrites: Vec<RewriteRule>,
    /// Response body find/replace rules (like nginx `sub_filter`).
    #[serde(default)]
    pub body_rewrites: Vec<BodyRewrite>,
    /// Extra response headers added to every response for this route.
    #[serde(default)]
    pub response_headers: Vec<HeaderRule>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading config from {path}"))?;
        toml::from_str(&raw).with_context(|| "parsing config.toml")
    }
}
