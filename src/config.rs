// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
/// Sshconfig.
pub struct SshConfig {
    /// Address to bind the SSH listener on, e.g. "0.0.0.0:22" or "[::]:22".
    pub listen: String,
    /// Upstream backend address, e.g. "gitea-ssh.devtools.svc.cluster.local:2222".
    pub backend: String,
}

#[derive(Debug, Deserialize, Clone)]
/// Config.
pub struct Config {
    /// Listen.
    pub listen: ListenConfig,
    /// Tls.
    pub tls: TlsFileConfig,
    /// Telemetry.
    pub telemetry: TelemetryConfig,
    /// Routes.
    pub routes: Vec<RouteConfig>,
    /// Optional SSH TCP passthrough (port 22 → Gitea SSH).
    pub ssh: Option<SshConfig>,
    /// Optional DDoS detection (ensemble: decision tree + MLP).
    pub ddos: Option<DDoSConfig>,
    /// Optional per-identity rate limiting.
    pub rate_limit: Option<RateLimitConfig>,
    /// Optional per-request scanner detection.
    pub scanner: Option<ScannerConfig>,
    /// Kubernetes resource names and namespaces for watchers.
    #[serde(default)]
    pub kubernetes: KubernetesConfig,
    /// Optional gossip-based cluster for multi-node state sharing.
    pub cluster: Option<ClusterConfig>,
    /// Optional TLS passthrough routes. When present, the proxy peeks at the
    /// TLS ClientHello SNI on the HTTPS port and relays matching connections
    /// directly to the backend without terminating TLS.  Non-matching
    /// connections are forwarded to Pingora's internal TLS listener.
    #[serde(default)]
    pub tls_passthrough: Option<Vec<TlsPassthroughRoute>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsPassthroughRoute {
    /// Subdomain prefix to match against the SNI hostname (same convention
    /// as `RouteConfig::host_prefix`).
    pub host_prefix: String,
    /// Upstream address to relay the raw TLS stream to,
    /// e.g. "buildkitd.build.svc.cluster.local:1234".
    pub backend: String,
}

#[derive(Debug, Deserialize, Clone)]
/// Tlspassthroughroute.
pub struct TlsPassthroughRoute {
    /// Subdomain prefix to match against the SNI hostname (same convention
    /// as `RouteConfig::host_prefix`).
    pub host_prefix: String,
    /// Upstream address to relay the raw TLS stream to,
    /// e.g. "buildkitd.build.svc.cluster.local:1234".
    pub backend: String,
}

#[derive(Debug, Deserialize, Clone)]
/// Kubernetesconfig.
pub struct KubernetesConfig {
    /// Namespace where the proxy's resources live (Secret, ConfigMap, Ingresses).
    #[serde(default = "default_k8s_namespace")]
    pub namespace: String,
    /// Name of the TLS Secret watched for cert hot-reload.
    #[serde(default = "default_tls_secret")]
    pub tls_secret: String,
    /// Name of the ConfigMap watched for config hot-reload.
    #[serde(default = "default_config_configmap")]
    pub config_configmap: String,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            namespace: default_k8s_namespace(),
            tls_secret: default_tls_secret(),
            config_configmap: default_config_configmap(),
        }
    }
}

fn default_k8s_namespace() -> String { "ingress".to_string() }
fn default_tls_secret() -> String { "pingora-tls".to_string() }
fn default_config_configmap() -> String { "pingora-config".to_string() }

#[derive(Debug, Deserialize, Clone)]
/// Ddosconfig.
pub struct DDoSConfig {
    #[serde(default = "default_threshold")]
    /// Threshold.
    pub threshold: f64,
    #[serde(default = "default_window_secs")]
    /// Window secs.
    pub window_secs: u64,
    #[serde(default = "default_window_capacity")]
    /// Window capacity.
    pub window_capacity: usize,
    #[serde(default = "default_min_events")]
    /// Min events.
    pub min_events: usize,
    #[serde(default = "default_enabled")]
    /// Enabled.
    pub enabled: bool,
    /// When true, run the model and log decisions but never block traffic.
    /// Useful for gathering data on model accuracy before enforcing.
    #[serde(default)]
    pub observe_only: bool,
}

#[derive(Debug, Deserialize, Clone)]
/// Ratelimitconfig.
pub struct RateLimitConfig {
    #[serde(default = "default_rl_enabled")]
    /// Enabled.
    pub enabled: bool,
    #[serde(default)]
    /// Bypass cidrs.
    pub bypass_cidrs: Vec<String>,
    #[serde(default = "default_eviction_interval")]
    /// Eviction interval secs.
    pub eviction_interval_secs: u64,
    #[serde(default = "default_stale_after")]
    /// Stale after secs.
    pub stale_after_secs: u64,
    /// Authenticated.
    pub authenticated: BucketConfig,
    /// Unauthenticated.
    pub unauthenticated: BucketConfig,
}

#[derive(Debug, Deserialize, Clone)]
/// Bucketconfig.
pub struct BucketConfig {
    /// Burst.
    pub burst: u32,
    /// Rate.
    pub rate: f64,
}

#[derive(Debug, Deserialize, Clone)]
/// Scannerconfig.
pub struct ScannerConfig {
    #[serde(default = "default_scanner_threshold")]
    /// Threshold.
    pub threshold: f64,
    #[serde(default = "default_scanner_enabled")]
    /// Enabled.
    pub enabled: bool,
    /// Bot allowlist rules. Verified bots bypass the scanner model.
    #[serde(default)]
    pub allowlist: Vec<BotAllowlistRule>,
    /// TTL (seconds) for verified bot IP cache entries.
    #[serde(default = "default_bot_cache_ttl")]
    pub bot_cache_ttl_secs: u64,
    /// When true, run the model and log decisions but never block traffic.
    /// Useful for gathering data on model accuracy before enforcing.
    #[serde(default)]
    pub observe_only: bool,
}

#[derive(Debug, Deserialize, Clone)]
/// Botallowlistrule.
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

fn default_rl_enabled() -> bool { true }
fn default_eviction_interval() -> u64 { 300 }
fn default_stale_after() -> u64 { 600 }

fn default_threshold() -> f64 { 0.6 }
fn default_window_secs() -> u64 { 60 }
fn default_window_capacity() -> usize { 1000 }
fn default_min_events() -> usize { 10 }
fn default_enabled() -> bool { true }

#[derive(Debug, Deserialize, Clone)]
/// Listenconfig.
pub struct ListenConfig {
    /// HTTP listener address, e.g., "0.0.0.0:80" or "[::]:80".
    pub http: String,
    /// HTTPS listener address, e.g., "0.0.0.0:443" or "[::]:443".
    pub https: String,
}

#[derive(Debug, Deserialize, Clone)]
/// Tlsfileconfig.
pub struct TlsFileConfig {
    /// Cert path.
    pub cert_path: String,
    /// Key path.
    pub key_path: String,
}

#[derive(Debug, Deserialize, Clone)]
/// Telemetryconfig.
pub struct TelemetryConfig {
    /// Otlp endpoint.
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
    /// Prefix.
    pub prefix: String,
    /// Backend.
    pub backend: String,
    /// Strip the matched prefix before forwarding to the backend.
    #[serde(default)]
    pub strip_prefix: bool,
    #[serde(default)]
    /// Websocket.
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
    /// Upstream read/write timeout in seconds (default: inherits from parent route, then 60).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// When true, return 403 Forbidden for any request matching this path prefix.
    /// Takes precedence over auth_request and backend forwarding.
    #[serde(default)]
    pub deny: bool,
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
    /// Name.
    pub name: String,
    /// Value.
    pub value: String,
}

/// Per-route HTTP response cache configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    #[serde(default = "default_cache_enabled")]
    /// Enabled.
    pub enabled: bool,
    /// Default TTL in seconds when the upstream response has no Cache-Control header.
    #[serde(default = "default_cache_ttl")]
    pub default_ttl_secs: u64,
    /// Seconds to serve stale content while revalidating in the background.
    #[serde(default)]
    pub stale_while_revalidate_secs: u32,
    /// Max cacheable response body size in bytes (0 = no limit).
    #[serde(default)]
    pub max_file_size: usize,
}

fn default_cache_enabled() -> bool { true }
fn default_cache_ttl() -> u64 { 60 }

#[derive(Debug, Deserialize, Clone)]
/// Routeconfig.
pub struct RouteConfig {
    /// Host prefix.
    pub host_prefix: String,
    /// Backend.
    pub backend: String,
    #[serde(default)]
    /// Websocket.
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
    /// HTTP response cache configuration for this route.
    #[serde(default)]
    pub cache: Option<CacheConfig>,
    /// Upstream read/write timeout in seconds (default: 60).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClusterConfig {
    #[serde(default = "default_cluster_enabled")]
    pub enabled: bool,
    /// Tenant UUID — isolates unrelated deployments.
    pub tenant: String,
    /// UDP port for gossip protocol.
    #[serde(default = "default_gossip_port")]
    pub gossip_port: u16,
    /// Path to persist the node identity key.
    #[serde(default)]
    pub key_path: Option<String>,
    /// Peer discovery configuration.
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    /// Bandwidth broadcast settings.
    #[serde(default)]
    pub bandwidth: Option<BandwidthClusterConfig>,
    /// Model distribution settings.
    #[serde(default)]
    pub models: Option<ModelsConfig>,
}

fn default_cluster_enabled() -> bool { true }
fn default_gossip_port() -> u16 { 11204 }

#[derive(Debug, Deserialize, Clone)]
pub struct DiscoveryConfig {
    /// "k8s" or "bootstrap".
    #[serde(default = "default_discovery_method")]
    pub method: String,
    /// Headless service for k8s DNS discovery.
    #[serde(default)]
    pub headless_service: Option<String>,
    /// Static bootstrap peers ("endpointid@host:port").
    #[serde(default)]
    pub bootstrap_peers: Option<Vec<String>>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            method: default_discovery_method(),
            headless_service: None,
            bootstrap_peers: None,
        }
    }
}

fn default_discovery_method() -> String { "k8s".to_string() }

#[derive(Debug, Deserialize, Clone)]
pub struct BandwidthClusterConfig {
    #[serde(default = "default_broadcast_interval")]
    pub broadcast_interval_secs: u64,
    #[serde(default = "default_stale_peer_timeout")]
    pub stale_peer_timeout_secs: u64,
    /// Sliding window size for aggregate bandwidth rate calculation.
    #[serde(default = "default_meter_window")]
    pub meter_window_secs: u64,
}

fn default_meter_window() -> u64 { 30 }

fn default_broadcast_interval() -> u64 { 1 }
fn default_stale_peer_timeout() -> u64 { 30 }

#[derive(Debug, Deserialize, Clone)]
pub struct ModelsConfig {
    #[serde(default = "default_model_dir")]
    pub model_dir: String,
    #[serde(default = "default_max_model_size")]
    pub max_model_size_bytes: u64,
    #[serde(default = "default_chunk_size")]
    pub chunk_size: u32,
}

fn default_model_dir() -> String { "/models".to_string() }
fn default_max_model_size() -> u64 { 52_428_800 } // 50MB
fn default_chunk_size() -> u32 { 65_536 } // 64KB

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading config from {path}"))?;
        toml::from_str(&raw).with_context(|| "parsing config.toml")
    }
}
