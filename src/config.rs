// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::gateway::GatewayConfig;
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
    #[serde(default)]
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
    /// Gateway API control plane configuration.
    #[serde(default)]
    pub gateway: GatewayConfig,
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

fn default_k8s_namespace() -> String {
    "ingress".to_string()
}
fn default_tls_secret() -> String {
    "pingora-tls".to_string()
}
fn default_config_configmap() -> String {
    "pingora-config".to_string()
}

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

fn default_bot_cache_ttl() -> u64 {
    86400
} // 24h

fn default_scanner_threshold() -> f64 {
    0.5
}
fn default_scanner_enabled() -> bool {
    true
}

fn default_rl_enabled() -> bool {
    true
}
fn default_eviction_interval() -> u64 {
    300
}
fn default_stale_after() -> u64 {
    600
}

fn default_threshold() -> f64 {
    0.6
}
fn default_window_secs() -> u64 {
    60
}
fn default_window_capacity() -> usize {
    1000
}
fn default_min_events() -> usize {
    10
}
fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
/// Listenconfig.
pub struct ListenConfig {
    /// HTTP listener address, e.g., "0.0.0.0:80" or "[::]:80".
    pub http: String,
    /// HTTPS listener address, e.g., "0.0.0.0:443" or "[::]:443".
    pub https: String,
    /// Additional HTTP listener addresses for Gateway API conformance tests
    /// that create Gateways on non-default ports (e.g. 8080, 8082).
    #[serde(default)]
    pub extra_http: Vec<String>,
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

fn default_metrics_port() -> u16 {
    9090
}

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
    /// Full path to replace the request path with (Gateway API ReplaceFullPath).
    #[serde(default)]
    pub path_rewrite_full: Option<String>,
    /// Hostname to replace the Host header with during forwarding.
    #[serde(default)]
    pub hostname_rewrite: Option<String>,
    /// Upstream read/write timeout in seconds (default: inherits from parent route, then 60).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Optional mirror backend addresses for request mirroring (fire-and-forget).
    #[serde(default)]
    pub mirror_backends: Vec<String>,
    /// Optional CORS configuration for this path route.
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// When true, return 403 Forbidden for any request matching this path prefix.
    /// Takes precedence over auth_request and backend forwarding.
    #[serde(default)]
    pub deny: bool,
    /// When true, this Gateway API route was accepted but its backend references
    /// could not be resolved. The proxy returns HTTP 500 for matching requests.
    #[serde(default)]
    pub gateway_api_unprogrammed: bool,
    /// Optional HTTP methods this path route matches. When empty, all methods match.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Optional weighted backends for traffic splitting. When empty, `backend` is used.
    #[serde(default)]
    pub weighted_backends: Vec<WeightedBackendConfig>,
    /// Optional redirect to return instead of forwarding.
    #[serde(default)]
    pub redirect: Option<RedirectRule>,
    /// Optional header-based matches for this path route. All must match (AND).
    #[serde(default)]
    pub header_matches: Vec<HeaderMatchConfig>,
    /// Optional query parameter-based matches for this path route. All must match (AND).
    #[serde(default)]
    pub query_param_matches: Vec<QueryParamMatchConfig>,
    /// Order of the rule within its HTTPRoute; used for Gateway API precedence
    /// tie-breaking when multiple path routes share the same prefix length.
    #[serde(default)]
    pub rule_order: usize,
    /// When true, match the path exactly instead of as a prefix.
    #[serde(default)]
    pub path_match_exact: bool,
    /// Request headers to set (replace) on upstream requests for this path.
    #[serde(default)]
    pub request_headers: Vec<HeaderRule>,
    /// Request headers to add (append) on upstream requests for this path.
    #[serde(default)]
    pub request_headers_add: Vec<HeaderRule>,
    /// Request headers to remove from upstream requests for this path.
    #[serde(default)]
    pub request_headers_remove: Vec<String>,
    /// Response headers to set (replace) for this path.
    #[serde(default)]
    pub response_headers: Vec<HeaderRule>,
    /// Response headers to add (append) for this path.
    #[serde(default)]
    pub response_headers_add: Vec<HeaderRule>,
    /// Response headers to remove for this path.
    #[serde(default)]
    pub response_headers_remove: Vec<String>,
}

/// A weighted backend entry used for traffic splitting.
#[derive(Debug, Deserialize, Clone)]
pub struct WeightedBackendConfig {
    /// Backend address.
    pub backend: String,
    /// Relative weight.
    pub weight: u32,
}

/// A redirect rule returned directly to the client.
#[derive(Debug, Deserialize, Clone)]
pub struct RedirectRule {
    /// HTTP status code (e.g. 301, 302).
    pub status_code: u16,
    /// Target scheme to redirect to.
    pub scheme: Option<String>,
    /// Target hostname.
    pub hostname: Option<String>,
    /// Target port.
    pub port: Option<u16>,
    /// Replacement path. When `path_prefix` is `Some`, this replaces the
    /// matched prefix; otherwise it replaces the entire path.
    pub path: Option<String>,
    /// Matched prefix to replace. `None` means `path` is a full replacement.
    #[serde(default)]
    pub path_prefix: Option<String>,
}

/// CORS configuration for a path route.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CorsConfig {
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age: Option<i32>,
    pub allow_credentials: bool,
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

/// A header match condition for path routes.
#[derive(Debug, Deserialize, Clone)]
pub struct HeaderMatchConfig {
    /// Header name (case-insensitive).
    pub name: String,
    /// Match value.
    pub value: HeaderMatchValueConfig,
}

/// Possible header match values.
#[derive(Debug, Deserialize, Clone)]
pub enum HeaderMatchValueConfig {
    /// Exact string match.
    Exact(String),
    /// Regular expression match.
    Regex(String),
    /// Header must be present (any value).
    Present,
    /// Header must be absent.
    Absent,
}

/// A query parameter match condition for path routes.
#[derive(Debug, Deserialize, Clone)]
pub struct QueryParamMatchConfig {
    /// Query parameter name.
    pub name: String,
    /// Match value.
    pub value: QueryParamMatchValueConfig,
}

/// Possible query parameter match values.
#[derive(Debug, Deserialize, Clone)]
pub enum QueryParamMatchValueConfig {
    /// Exact string match.
    Exact(String),
    /// Regular expression match.
    Regex(String),
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

fn default_cache_enabled() -> bool {
    true
}
fn default_cache_ttl() -> u64 {
    60
}

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
    /// Extra response headers to add (append) to every response.
    #[serde(default)]
    pub response_headers_add: Vec<HeaderRule>,
    /// Response headers to remove from every response.
    #[serde(default)]
    pub response_headers_remove: Vec<String>,
    /// Extra request headers added before forwarding to the upstream.
    #[serde(default)]
    pub request_headers: Vec<HeaderRule>,
    /// Request headers to add (append) before forwarding.
    #[serde(default)]
    pub request_headers_add: Vec<HeaderRule>,
    /// Request headers to remove before forwarding.
    #[serde(default)]
    pub request_headers_remove: Vec<String>,
    /// HTTP response cache configuration for this route.
    #[serde(default)]
    pub cache: Option<CacheConfig>,
    /// Optional CORS configuration for this route.
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Upstream read/write timeout in seconds (default: 60).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Optional Gateway API listener hostname this route belongs to.
    /// Used for listener isolation: when multiple routes match a request,
    /// the one with the most specific listener hostname wins.
    #[serde(default)]
    pub listener_hostname: Option<String>,
    /// When true, this route was created from a Gateway API HTTPRoute.
    /// Missing path matches should return 404 instead of falling through
    /// to a host-level default backend.
    #[serde(default)]
    pub gateway_api: bool,
}

#[derive(Debug, Deserialize, Clone)]
/// Clusterconfig.
pub struct ClusterConfig {
    #[serde(default = "default_cluster_enabled")]
    /// Enabled.
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

fn default_cluster_enabled() -> bool {
    true
}
fn default_gossip_port() -> u16 {
    11204
}

#[derive(Debug, Deserialize, Clone)]
/// Discoveryconfig.
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

fn default_discovery_method() -> String {
    "k8s".to_string()
}

#[derive(Debug, Deserialize, Clone)]
/// Bandwidthclusterconfig.
pub struct BandwidthClusterConfig {
    #[serde(default = "default_broadcast_interval")]
    /// Broadcast interval secs.
    pub broadcast_interval_secs: u64,
    #[serde(default = "default_stale_peer_timeout")]
    /// Stale peer timeout secs.
    pub stale_peer_timeout_secs: u64,
    /// Sliding window size for aggregate bandwidth rate calculation.
    #[serde(default = "default_meter_window")]
    pub meter_window_secs: u64,
}

fn default_meter_window() -> u64 {
    30
}

fn default_broadcast_interval() -> u64 {
    1
}
fn default_stale_peer_timeout() -> u64 {
    30
}

#[derive(Debug, Deserialize, Clone)]
/// Modelsconfig.
pub struct ModelsConfig {
    #[serde(default = "default_model_dir")]
    /// Model dir.
    pub model_dir: String,
    #[serde(default = "default_max_model_size")]
    /// Max model size bytes.
    pub max_model_size_bytes: u64,
    #[serde(default = "default_chunk_size")]
    /// Chunk size.
    pub chunk_size: u32,
}

fn default_model_dir() -> String {
    "/models".to_string()
}
fn default_max_model_size() -> u64 {
    52_428_800
} // 50MB
fn default_chunk_size() -> u32 {
    65_536
} // 64KB

/// Structured error emitted when a deprecated TOML section is detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeprecatedTomlSection {
    /// Name of the deprecated section.
    pub section: &'static str,
    /// Recommended replacement for the deprecated section.
    pub migration_target: &'static str,
}

impl std::fmt::Display for DeprecatedTomlSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "config.toml contains deprecated section `{}`. Migrate to {}.",
            self.section, self.migration_target
        )
    }
}

impl std::error::Error for DeprecatedTomlSection {}

fn reject_deprecated_tables(raw: &str) -> Result<()> {
    let doc: toml::Table = raw
        .parse()
        .with_context(|| "pre-flight TOML parse for deprecated sections")?;
    if doc.contains_key("routes") {
        return Err(anyhow::Error::from(DeprecatedTomlSection {
            section: "[[routes]]",
            migration_target: "Gateway API HTTPRoute CRDs",
        }));
    }
    if doc.contains_key("tls_passthrough") {
        return Err(anyhow::Error::from(DeprecatedTomlSection {
            section: "[[tls_passthrough]]",
            migration_target: "Gateway API TLSRoute CRDs",
        }));
    }
    Ok(())
}

impl Config {
    /// Load and parse `config.toml` from disk, rejecting deprecated sections.
    pub fn load(path: &str) -> Result<Self> {
        let raw =
            fs::read_to_string(path).with_context(|| format!("reading config from {path}"))?;
        reject_deprecated_tables(&raw)?;
        toml::from_str(&raw).with_context(|| "parsing config.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_routes_section() {
        let raw = r#"
listen = "0.0.0.0:8080"
[[routes]]
host_prefix = "example.com"
backend = "10.0.0.1:80"
"#;
        let err = reject_deprecated_tables(raw).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("[[routes]]"),
            "error should name the section: {msg}"
        );
        assert!(
            msg.contains("HTTPRoute"),
            "error should hint migration target: {msg}"
        );
    }

    #[test]
    fn rejects_tls_passthrough_section() {
        let raw = r#"
listen = "0.0.0.0:8080"
[[tls_passthrough]]
host_prefix = "tls.example.com"
backend = "10.0.0.1:443"
"#;
        let err = reject_deprecated_tables(raw).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("[[tls_passthrough]]"),
            "error should name the section: {msg}"
        );
        assert!(
            msg.contains("TLSRoute"),
            "error should hint migration target: {msg}"
        );
    }

    #[test]
    fn accepts_config_without_deprecated_sections() {
        let raw = r#"
listen = "0.0.0.0:8080"
tls = { cert = "/certs/cert.pem", key = "/certs/key.pem" }
# [[routes]]   <-- commented out, must be ignored
"#;
        assert!(reject_deprecated_tables(raw).is_ok());
    }

    #[test]
    fn ignores_commented_deprecated_section() {
        let raw = r#"
listen = "0.0.0.0:8080"
# [[routes]]
# host_prefix = "example.com"
"#;
        assert!(reject_deprecated_tables(raw).is_ok());
    }

    #[test]
    fn deprecated_toml_section_display_and_error_trait() {
        let d = DeprecatedTomlSection {
            section: "[[foo]]",
            migration_target: "Bar",
        };
        let msg = format!("{d}");
        assert!(msg.contains("[[foo]]"));
        assert!(msg.contains("Bar"));
        assert!(std::error::Error::source(&d).is_none());
    }

    #[test]
    fn kubernetes_config_default_uses_expected_values() {
        let k = KubernetesConfig::default();
        assert_eq!(k.namespace, "ingress");
        assert_eq!(k.tls_secret, "pingora-tls");
        assert_eq!(k.config_configmap, "pingora-config");
    }

    #[test]
    fn default_functions_return_expected_values() {
        assert_eq!(default_k8s_namespace(), "ingress");
        assert_eq!(default_tls_secret(), "pingora-tls");
        assert_eq!(default_config_configmap(), "pingora-config");

        assert_eq!(default_bot_cache_ttl(), 86_400);
        assert_eq!(default_scanner_threshold(), 0.5);
        assert!(default_scanner_enabled());
        assert!(default_rl_enabled());
        assert_eq!(default_eviction_interval(), 300);
        assert_eq!(default_stale_after(), 600);

        assert_eq!(default_threshold(), 0.6);
        assert_eq!(default_window_secs(), 60);
        assert_eq!(default_window_capacity(), 1_000);
        assert_eq!(default_min_events(), 10);
        assert!(default_enabled());

        assert_eq!(default_metrics_port(), 9_090);
        assert!(default_cache_enabled());
        assert_eq!(default_cache_ttl(), 60);

        assert!(default_cluster_enabled());
        assert_eq!(default_gossip_port(), 11_204);
        assert_eq!(default_discovery_method(), "k8s");
        assert_eq!(default_meter_window(), 30);
        assert_eq!(default_broadcast_interval(), 1);
        assert_eq!(default_stale_peer_timeout(), 30);
        assert_eq!(default_model_dir(), "/models");
        assert_eq!(default_max_model_size(), 52_428_800);
        assert_eq!(default_chunk_size(), 65_536);
    }

    #[test]
    fn telemetry_default_metrics_port() {
        let raw = r#"
listen = { http = "0.0.0.0:80", https = "0.0.0.0:443" }
tls = { cert_path = "/c/cert.pem", key_path = "/c/key.pem" }
telemetry = { otlp_endpoint = "http://otel:4317" }
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        assert_eq!(cfg.telemetry.metrics_port, 9_090);
        assert_eq!(cfg.telemetry.otlp_endpoint, "http://otel:4317");
    }

    #[test]
    fn config_deserializes_optional_sections_with_defaults() {
        let raw = r#"
listen = { http = "0.0.0.0:80", https = "0.0.0.0:443" }
tls = { cert_path = "/c/cert.pem", key_path = "/c/key.pem" }
telemetry = { otlp_endpoint = "http://otel:4317" }

[scanner]

[ddos]

[rate_limit]
authenticated = { burst = 10, rate = 1.0 }
unauthenticated = { burst = 2, rate = 0.1 }

[cluster]
tenant = "test-tenant"

[cluster.discovery]

[cluster.bandwidth]

[cluster.models]
"#;
        let cfg: Config = toml::from_str(raw).unwrap();

        let scanner = cfg.scanner.as_ref().unwrap();
        assert!(scanner.enabled);
        assert_eq!(scanner.threshold, 0.5);
        assert!(scanner.allowlist.is_empty());
        assert_eq!(scanner.bot_cache_ttl_secs, 86_400);
        assert!(!scanner.observe_only);

        let ddos = cfg.ddos.as_ref().unwrap();
        assert!(ddos.enabled);
        assert_eq!(ddos.threshold, 0.6);
        assert_eq!(ddos.window_secs, 60);
        assert_eq!(ddos.window_capacity, 1_000);
        assert_eq!(ddos.min_events, 10);

        let rl = cfg.rate_limit.as_ref().unwrap();
        assert!(rl.enabled);
        assert!(rl.bypass_cidrs.is_empty());
        assert_eq!(rl.eviction_interval_secs, 300);
        assert_eq!(rl.stale_after_secs, 600);
        assert_eq!(rl.authenticated.burst, 10);

        let cluster = cfg.cluster.as_ref().unwrap();
        assert!(cluster.enabled);
        assert_eq!(cluster.gossip_port, 11_204);
        assert_eq!(cluster.discovery.method, "k8s");
        assert!(cluster.discovery.headless_service.is_none());
        assert!(cluster.discovery.bootstrap_peers.is_none());

        let bw = cluster.bandwidth.as_ref().unwrap();
        assert_eq!(bw.meter_window_secs, 30);
        assert_eq!(bw.broadcast_interval_secs, 1);
        assert_eq!(bw.stale_peer_timeout_secs, 30);

        let models = cluster.models.as_ref().unwrap();
        assert_eq!(models.model_dir, "/models");
        assert_eq!(models.max_model_size_bytes, 52_428_800);
        assert_eq!(models.chunk_size, 65_536);
    }

    #[test]
    fn config_load_reads_valid_file() {
        let path =
            std::env::temp_dir().join(format!("sunbeam-config-valid-{}.toml", std::process::id()));
        let raw = r#"
listen = { http = "0.0.0.0:80", https = "0.0.0.0:443" }
tls = { cert_path = "/c/cert.pem", key_path = "/c/key.pem" }
telemetry = { otlp_endpoint = "http://otel:4317", metrics_port = 9090 }
"#;
        std::fs::write(&path, raw).unwrap();
        let cfg = Config::load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.listen.http, "0.0.0.0:80");
        assert_eq!(cfg.telemetry.metrics_port, 9090);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn config_load_missing_file_reports_reading_error() {
        let err = Config::load("/nonexistent/sunbeam-config-test.toml").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("reading config"), "{msg}");
    }

    #[test]
    fn config_load_invalid_toml_reports_parsing_error() {
        let path =
            std::env::temp_dir().join(format!("sunbeam-config-bad-{}.toml", std::process::id()));
        // Passes the deprecated-section pre-flight parse but fails Config deserialization.
        std::fs::write(&path, "listen = \"0.0.0.0:80\"").unwrap();
        let err = Config::load(path.to_str().unwrap()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("parsing config.toml"), "{msg}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn config_load_rejects_deprecated_routes_file() {
        let path =
            std::env::temp_dir().join(format!("sunbeam-config-depr-{}.toml", std::process::id()));
        let raw = r#"
listen = { http = "0.0.0.0:80", https = "0.0.0.0:443" }
tls = { cert_path = "/c/cert.pem", key_path = "/c/key.pem" }
telemetry = { otlp_endpoint = "http://otel:4317" }
[[routes]]
host_prefix = "foo"
backend = "b"
"#;
        std::fs::write(&path, raw).unwrap();
        let err = Config::load(path.to_str().unwrap()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("[[routes]]"), "{msg}");
        assert!(msg.contains("HTTPRoute"), "{msg}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn config_load_malformed_toml_reports_preflight_error() {
        let path = std::env::temp_dir().join(format!(
            "sunbeam-config-malformed-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, "not toml [[[").unwrap();
        let err = Config::load(path.to_str().unwrap()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("pre-flight TOML parse for deprecated sections"),
            "{msg}"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn discovery_config_default_uses_k8s_method() {
        let d = DiscoveryConfig::default();
        assert_eq!(d.method, "k8s");
        assert!(d.headless_service.is_none());
        assert!(d.bootstrap_peers.is_none());
    }
}
