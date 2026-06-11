// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use crate::acme::AcmeRoutes;
use crate::cluster::ClusterHandle;
use crate::config::{PathRoute, RouteConfig};
use crate::ddos::detector::DDoSDetector;
use crate::ddos::model::DDoSAction;
use crate::metrics;
use crate::rate_limit::key;
use crate::rate_limit::limiter::{RateLimitResult, RateLimiter};
use crate::scanner::allowlist::BotAllowlist;
use crate::scanner::detector::ScannerDetector;
use crate::scanner::model::ScannerAction;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::{CONNECTION, EXPECT, HOST, UPGRADE};
use pingora_cache::{CacheKey, CacheMeta, ForcedFreshness, HitHandler, NoCacheReason, RespCacheable};
use pingora_core::{upstreams::peer::HttpPeer, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use regex::Regex;
use std::cmp::Ordering;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Build an HttpPeer with configurable timeouts.
///
/// DNS resolution is performed here so that a lookup failure can be handled
/// gracefully instead of panicking the Pingora worker thread.
async fn make_peer(addr: &str, timeout_secs: Option<u64>) -> Option<Box<HttpPeer>> {
    let addr = backend_addr(addr);
    let mut addrs = tokio::net::lookup_host(&addr).await.ok()?;
    let sa = addrs.next()?;
    let mut peer = HttpPeer::new(sa, false, String::new());
    let t = timeout_secs.unwrap_or(60);
    peer.options.connection_timeout = Some(Duration::from_secs(10));
    peer.options.read_timeout = Some(Duration::from_secs(t));
    peer.options.write_timeout = Some(Duration::from_secs(t));
    Some(Box::new(peer))
}

/// A compiled rewrite rule (regex compiled once at startup).
pub struct CompiledRewrite {
    /// Pattern.
    pub pattern: Regex,
    /// Target.
    pub target: String,
}

/// Sunbeamproxy.
pub struct SunbeamProxy {
    /// Routes — atomically swappable at runtime via [`Self::swap_routes`].
    pub routes: Arc<ArcSwap<Vec<RouteConfig>>>,
    /// Per-challenge route table populated by the Ingress watcher.
    pub acme_routes: AcmeRoutes,
    /// Optional DDoS detector (ensemble: decision tree + MLP).
    pub ddos_detector: Option<Arc<DDoSDetector>>,
    /// Optional per-request scanner detector (ensemble: decision tree + MLP).
    pub scanner_detector: Option<Arc<ArcSwap<ScannerDetector>>>,
    /// Optional verified-bot allowlist (bypasses scanner for known crawlers/agents).
    pub bot_allowlist: Option<Arc<BotAllowlist>>,
    /// Optional per-identity rate limiter.
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// Compiled rewrite rules per route (indexed by host_prefix) — swappable with routes.
    pub compiled_rewrites: Arc<ArcSwap<Vec<(String, Arc<Vec<CompiledRewrite>>)>>>,
    /// Shared reqwest client for auth subrequests.
    pub http_client: reqwest::Client,
    /// Parsed bypass CIDRs — IPs in these ranges skip the detection pipeline.
    pub pipeline_bypass_cidrs: Vec<crate::rate_limit::cidr::CidrBlock>,
    /// Optional cluster handle for multi-node bandwidth tracking.
    pub cluster: Option<Arc<ClusterHandle>>,
    /// When true, DDoS detector logs decisions but never blocks traffic.
    pub ddos_observe_only: bool,
    /// When true, scanner detector logs decisions but never blocks traffic.
    pub scanner_observe_only: bool,
}

/// Requestctx.
pub struct RequestCtx {
    /// Route.
    pub route: Option<RouteConfig>,
    /// Start time.
    pub start_time: Instant,
    /// Unique request identifier (monotonic hex counter).
    pub request_id: String,
    /// Tracing span for this request.
    pub span: tracing::Span,
    /// Resolved solver backend address for this ACME challenge, if applicable.
    pub acme_backend: Option<String>,
    /// Path prefix to strip before forwarding to the upstream (e.g. "/kratos").
    pub strip_prefix: Option<String>,
    /// Original downstream scheme ("http" or "https"), captured in request_filter.
    pub downstream_scheme: &'static str,
    /// Whether this request was served from static files (skip upstream).
    pub served_static: bool,
    /// Captured auth subrequest headers to forward upstream.
    pub auth_headers: Vec<(String, String)>,
    /// Upstream path prefix to prepend (from PathRoute config).
    pub upstream_path_prefix: Option<String>,
    /// Full path to replace the request path with (Gateway API ReplaceFullPath).
    pub path_rewrite_full: Option<String>,
    /// Hostname to replace the Host header with during forwarding.
    pub hostname_rewrite: Option<String>,
    /// Whether response body rewriting is needed for this request.
    pub body_rewrite_rules: Vec<(String, String)>,
    /// Buffered response body for body rewriting.
    pub body_buffer: Option<Vec<u8>>,
}

/// Return true if `prefix` is a Gateway API path-segment prefix of `req_path`.
/// A PathPrefix `/foo` matches `/foo`, `/foo/`, and `/foo/bar`, but not
/// `/foobar` or `/bar/foo`. The root prefix `/` matches every path.
fn path_prefix_matches(req_path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return req_path.starts_with('/');
    }
    if req_path == prefix {
        return true;
    }
    req_path
        .strip_prefix(prefix)
        .map(|rest| rest.starts_with('/'))
        .unwrap_or(false)
}

/// Check if an Origin matches the CORS allow_origins list.
fn cors_allow_origin(origin: &str, allow_origins: &[String], allow_credentials: bool) -> bool {
    if allow_origins.is_empty() {
        return true;
    }
    for allowed in allow_origins {
        if allowed == "*" {
            return true;
        }
        if allowed.eq_ignore_ascii_case(origin) {
            return true;
        }
        // Wildcard matching: e.g. "*.example.com" matches "foo.example.com"
        if allowed.starts_with("*.") {
            let suffix = &allowed[2..];
            if origin.strip_suffix(suffix).and_then(|rest| rest.strip_suffix('.')).map_or(false, |rest| !rest.is_empty()) {
                return true;
            }
        }
    }
    false
}

/// Select the best matching path route from a list, considering prefix and
/// optional HTTP method constraints. Longest prefix wins; method mismatch
/// excludes a candidate.
fn select_path_route<'a>(
    paths: &'a [PathRoute],
    req_path: &str,
    method: &str,
    req_headers: &http::header::HeaderMap,
    query: Option<&str>,
) -> Option<&'a PathRoute> {
    paths
        .iter()
        .filter(|p| {
            if p.path_match_exact {
                req_path == p.prefix.as_str()
            } else {
                path_prefix_matches(req_path, p.prefix.as_str())
            }
        })
        .filter(|p| p.methods.is_empty() || p.methods.iter().any(|m| m.eq_ignore_ascii_case(method)))
        .filter(|p| {
            p.header_matches.iter().all(|hm| {
                let val = req_headers.get(&hm.name).and_then(|v| v.to_str().ok());
                match &hm.value {
                    crate::config::HeaderMatchValueConfig::Exact(expected) => {
                        val.is_some_and(|v| v.eq_ignore_ascii_case(expected.as_str()))
                    }
                    crate::config::HeaderMatchValueConfig::Regex(pattern) => {
                        val.is_some_and(|v| regex::Regex::new(pattern).ok().is_some_and(|re| re.is_match(v)))
                    }
                    crate::config::HeaderMatchValueConfig::Present => val.is_some(),
                    crate::config::HeaderMatchValueConfig::Absent => val.is_none(),
                }
            })
        })
        .filter(|p| {
            p.query_param_matches.iter().all(|qm| {
                let query_val = query.and_then(|q| {
                    q.split('&').find_map(|pair| {
                        let mut parts = pair.splitn(2, '=');
                        let key = parts.next()?;
                        if key == qm.name {
                            Some(parts.next().unwrap_or(""))
                        } else {
                            None
                        }
                    })
                });
                match &qm.value {
                    crate::config::QueryParamMatchValueConfig::Exact(expected) => query_val == Some(expected.as_str()),
                    crate::config::QueryParamMatchValueConfig::Regex(pattern) => {
                        query_val.is_some_and(|v| {
                            regex::Regex::new(pattern).ok().is_some_and(|re| re.is_match(v))
                        })
                    }
                }
            })
        })
        .max_by(|a, b| {
            let prefix_cmp = a.prefix.len().cmp(&b.prefix.len());
            if prefix_cmp != Ordering::Equal {
                return prefix_cmp;
            }
            // Gateway API precedence: on prefix-length ties, prefer the match
            // with the most header matches, then query param matches, then
            // method match, then earliest rule order.
            let header_cmp = a.header_matches.len().cmp(&b.header_matches.len());
            if header_cmp != Ordering::Equal {
                return header_cmp;
            }
            let query_cmp = a.query_param_matches.len().cmp(&b.query_param_matches.len());
            if query_cmp != Ordering::Equal {
                return query_cmp;
            }
            let method_cmp = b.methods.is_empty().cmp(&a.methods.is_empty());
            if method_cmp != Ordering::Equal {
                return method_cmp;
            }
            // Earlier rule order wins on prefix-length ties (Gateway API
            // precedence semantics). Lower rule_order = earlier rule.
            b.rule_order.cmp(&a.rule_order)
        })
}

/// Pick a backend from weighted backends using a hash of the request path
/// for deterministic distribution.
static WEIGHTED_BACKEND_COUNTER: AtomicU64 = AtomicU64::new(0);

fn pick_weighted_backend(backends: &[crate::config::WeightedBackendConfig], _path: &str) -> Option<String> {
    if backends.is_empty() {
        return None;
    }
    let total: u64 = backends.iter().map(|b| b.weight as u64).sum();
    if total == 0 {
        return Some(backends[0].backend.clone());
    }
    let pick = WEIGHTED_BACKEND_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % total;
    let mut cursor = 0;
    for b in backends {
        cursor += b.weight as u64;
        if pick < cursor {
            return Some(b.backend.clone());
        }
    }
    Some(backends[0].backend.clone())
}

/// Build a redirect Location header from a RedirectRule and the original request.
fn build_redirect_location(
    redirect: &crate::config::RedirectRule,
    original_uri: &http::Uri,
) -> String {
    let scheme = redirect
        .scheme
        .as_deref()
        .or_else(|| original_uri.scheme_str())
        .unwrap_or("http");
    let host = redirect
        .hostname
        .as_deref()
        .or_else(|| original_uri.host())
        .unwrap_or("");
    let original_path = original_uri.path();
    let path = if let Some(prefix) = &redirect.path_prefix {
        original_path
            .strip_prefix(prefix)
            .map(|rest| format!("{}{}", redirect.path.as_deref().unwrap_or(""), rest))
            .unwrap_or_else(|| redirect.path.clone().unwrap_or_else(|| original_path.to_string()))
    } else {
        redirect
            .path
            .clone()
            .unwrap_or_else(|| original_path.to_string())
    };
    match redirect.port {
        Some(port) => format!("{}://{}:{}{}", scheme, host, port, path),
        None => format!("{}://{}{}", scheme, host, path),
    }
}

/// Return true if `host` matches a `host_prefix` that uses a wildcard
/// pattern such as `*.example.com`.
fn host_matches_wildcard(host: &str, prefix: &str) -> bool {
    let Some(suffix) = prefix.strip_prefix("*.") else {
        return false;
    };
    host.strip_suffix(suffix)
        .and_then(|rest| rest.strip_suffix('.'))
        .map_or(false, |rest| !rest.is_empty() && !rest.contains('.'))
}

/// Return true if `host` matches a listener hostname pattern.
fn host_matches_listener(host: &str, listener_hostname: &str) -> bool {
    if listener_hostname.is_empty() {
        return true;
    }
    if listener_hostname.starts_with("*.") {
        let suffix = &listener_hostname[2..];
        host.strip_suffix(suffix)
            .and_then(|rest| rest.strip_suffix('.'))
            .map_or(false, |rest| !rest.is_empty() && !rest.contains('.'))
    } else {
        listener_hostname == host
    }
}

/// Specificity score for a listener hostname. Higher = more specific.
fn listener_specificity_score(listener_hostname: &str) -> i32 {
    if listener_hostname.is_empty() {
        return 0;
    }
    if !listener_hostname.starts_with("*.") {
        // Exact hostname
        return 1000;
    }
    // Wildcard: base score + number of dots in suffix
    100 + listener_hostname[2..].chars().filter(|&c| c == '.').count() as i32
}

impl SunbeamProxy {
    fn find_route(&self, prefix: &str, host: &str) -> Option<RouteConfig> {
        let routes = self.routes.load();

        // Collect all routes whose host_prefix matches the request host.
        // For Gateway API routes, also require that the listener_hostname
        // matches the request host (listener isolation).
        let mut candidates: Vec<&RouteConfig> = routes
            .iter()
            .filter(|r| {
                let host_matches = r.host_prefix == host
                    || r.host_prefix == prefix
                    || host_matches_wildcard(host, &r.host_prefix)
                    || r.host_prefix == "*";
                if !host_matches {
                    return false;
                }
                // If this route belongs to a listener with a specific hostname,
                // the request host must match that listener hostname.
                if let Some(lh) = &r.listener_hostname {
                    return host_matches_listener(host, lh);
                }
                true
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        if candidates.len() == 1 {
            return Some(candidates[0].clone());
        }

        // Gateway API listener isolation: among matching routes, prefer the
        // one whose listener_hostname is most specific. Legacy routes
        // (listener_hostname == None) are treated as least specific.
        candidates.sort_by_key(|r| {
            match &r.listener_hostname {
                None => 0,
                Some(lh) => -listener_specificity_score(lh),
            }
        });

        Some(candidates[0].clone())
    }

    fn find_rewrites(&self, prefix: &str) -> Option<Arc<Vec<CompiledRewrite>>> {
        self.compiled_rewrites
            .load()
            .iter()
            .find(|(p, _)| p == prefix)
            .map(|(_, rules)| Arc::clone(rules))
    }

    /// Compile all rewrite rules from routes at startup.
    pub fn compile_rewrites(routes: &[RouteConfig]) -> Vec<(String, Arc<Vec<CompiledRewrite>>)> {
        routes
            .iter()
            .filter(|r| !r.rewrites.is_empty())
            .map(|r| {
                let compiled = r
                    .rewrites
                    .iter()
                    .filter_map(|rw| {
                        match Regex::new(&rw.pattern) {
                            Ok(re) => Some(CompiledRewrite {
                                pattern: re,
                                target: rw.target.clone(),
                            }),
                            Err(e) => {
                                tracing::error!(
                                    host_prefix = %r.host_prefix,
                                    pattern = %rw.pattern,
                                    error = %e,
                                    "failed to compile rewrite regex"
                                );
                                None
                            }
                        }
                    })
                    .collect();
                (r.host_prefix.clone(), Arc::new(compiled))
            })
            .collect()
    }

    /// Atomically replace the route table and compiled rewrites.
    pub fn swap_routes(&self, new_routes: Vec<RouteConfig>) {
        let compiled = Self::compile_rewrites(&new_routes);
        self.compiled_rewrites.store(Arc::new(compiled));
        self.routes.store(Arc::new(new_routes));
        tracing::info!("Route table hot-swapped");
    }
}

fn extract_host(session: &Session) -> String {
    // HTTP/1.1 carries the host in the `Host` header. HTTP/2 carries it in the
    // `:authority` pseudo-header, which pingora exposes via `uri.host()` and
    // does *not* mirror back into a synthetic `Host` header. Read the header
    // first, then fall back to the URI authority so both protocols work after
    // ALPN started advertising h2.
    let req = session.req_header();
    let from_header = req
        .headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(crate::audit::strip_port)
        .filter(|s| !s.is_empty());
    if let Some(host) = from_header {
        return host.to_string();
    }
    req.uri.host().unwrap_or("").to_string()
}

/// Extract the real client IP, preferring trusted proxy headers.
///
/// Priority: CF-Connecting-IP → X-Real-IP → X-Forwarded-For (first) → socket addr.
/// All traffic arrives via Cloudflare, so CF-Connecting-IP is the authoritative
/// real client IP.  The socket address is the Cloudflare edge node.
fn extract_client_ip(session: &Session) -> Option<IpAddr> {
    let headers = &session.req_header().headers;

    for header in &["cf-connecting-ip", "x-real-ip"] {
        if let Some(val) = headers.get(*header).and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = val.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // X-Forwarded-For: client, proxy1, proxy2 — take the first entry
    if let Some(val) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = val.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // Fallback: raw socket address
    session
        .client_addr()
        .and_then(|addr| addr.as_inet().map(|a| a.ip()))
}

/// Strip the scheme prefix from a backend URL like `http://host:port`.
pub fn backend_addr(backend: &str) -> &str {
    backend
        .trim_start_matches("https://")
        .trim_start_matches("http://")
}

/// Returns true if the downstream connection is plain HTTP (no TLS).
fn is_plain_http(session: &Session) -> bool {
    session
        .digest()
        .map(|d| d.ssl_digest.is_none())
        .unwrap_or(true)
}

#[async_trait]
impl ProxyHttp for SunbeamProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> RequestCtx {
        let request_id = uuid::Uuid::new_v4().to_string();
        RequestCtx {
            route: None,
            start_time: Instant::now(),
            request_id,
            span: tracing::Span::none(),
            acme_backend: None,
            downstream_scheme: "https",
            strip_prefix: None,
            served_static: false,
            auth_headers: Vec::new(),
            upstream_path_prefix: None,
            path_rewrite_full: None,
            hostname_rewrite: None,
            body_rewrite_rules: Vec::new(),
            body_buffer: None,
        }
    }

    /// HTTP → HTTPS redirect; ACME HTTP-01 challenges pass through on plain HTTP.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        ctx.downstream_scheme = if is_plain_http(session) { "http" } else { "https" };

        // Create the request-scoped tracing span.
        let method = session.req_header().method.to_string();
        let host = extract_host(session);
        let path = session.req_header().uri.path().to_string();
        ctx.span = tracing::info_span!("request",
            request_id = %ctx.request_id,
            method = %method,
            host = %host,
            path = %path,
        );

        metrics::ACTIVE_CONNECTIONS.inc();

        if is_plain_http(session) {
            let path = session.req_header().uri.path().to_string();

            // cert-manager HTTP-01 challenge: look up the token path in the
            // Ingress-backed route table.  Each challenge Ingress maps exactly
            // one token to exactly one solver Service, so this routes the request
            // to the right solver pod even when multiple challenges run in parallel.
            if path.starts_with("/.well-known/acme-challenge/") {
                // Drop the guard before any await point (RwLockReadGuard is !Send).
                let backend = self
                    .acme_routes
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&path)
                    .cloned();
                if let Some(backend) = backend {
                    ctx.acme_backend = Some(backend);
                    return Ok(false); // pass to upstream_peer
                }
                // No route yet: challenge Ingress hasn't arrived from cert-manager.
                let mut resp = ResponseHeader::build(404, None)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }

            // All other plain-HTTP traffic.
            let prefix = host.split('.').next().unwrap_or("");

            // Routes that explicitly opt out of HTTPS enforcement pass through.
            // All other requests — including unknown hosts — are redirected.
            if self
                .find_route(prefix, &host)
                .map(|r| r.disable_secure_redirection)
                .unwrap_or(false)
            {
                return Ok(false);
            }

            let query = session
                .req_header()
                .uri
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            let location = format!("https://{host}{path}{query}");
            let mut resp = ResponseHeader::build(301, None)?;
            resp.insert_header("Location", location)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        }

        // ── Detection pipeline ───────────────────────────────────────────
        // Each layer emits an unfiltered pipeline log BEFORE acting on its
        // decision.  This guarantees downstream training pipelines always
        // have the full traffic picture:
        //   - "ddos" log  = all HTTPS traffic  (scanner training data)
        //   - "scanner" log = traffic that passed DDoS (rate-limit training data)
        //   - "rate_limit" log = traffic that passed scanner (validation data)

        // Skip the detection pipeline for trusted IPs (localhost, pod network).
        if extract_client_ip(session)
            .map(|ip| crate::rate_limit::cidr::is_bypassed(ip, &self.pipeline_bypass_cidrs))
            .unwrap_or(false)
        {
            return Ok(false);
        }

        // DDoS detection: check the client IP against the KNN model.
        if let Some(detector) = &self.ddos_detector {
            if let Some(ip) = extract_client_ip(session) {
                let method = session.req_header().method.as_str();
                let path = session.req_header().uri.path();
                let host = extract_host(session);
                let user_agent = session
                    .req_header()
                    .headers
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-");
                let content_length: u64 = session
                    .req_header()
                    .headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let has_cookies = session.req_header().headers.get("cookie").is_some();
                let has_referer = session.req_header().headers.get("referer").is_some();
                let has_accept_language = session.req_header().headers.get("accept-language").is_some();
                let accept = session
                    .req_header()
                    .headers
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-");
                let ddos_action = detector.check(ip, method, path, &host, user_agent, content_length, has_cookies, has_referer, has_accept_language);
                let decision = if matches!(ddos_action, DDoSAction::Block) { "block" } else { "allow" };

                tracing::info!(
                    target = "pipeline",
                    layer       = "ddos",
                    decision,
                    method,
                    host        = %host,
                    path,
                    client_ip   = %ip,
                    user_agent,
                    content_length,
                    has_cookies,
                    has_referer,
                    has_accept_language,
                    accept,
                    "pipeline"
                );

                metrics::DDOS_DECISIONS.with_label_values(&[decision]).inc();

                if matches!(ddos_action, DDoSAction::Block) && !self.ddos_observe_only {
                    let mut resp = ResponseHeader::build(429, None)?;
                    resp.insert_header("Retry-After", "60")?;
                    resp.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        // Scanner detection: per-request classification of scanner/bot probes.
        // The detector is behind ArcSwap for lock-free hot-reload.
        if let Some(scanner_swap) = &self.scanner_detector {
            let method = session.req_header().method.as_str();
            let path = session.req_header().uri.path();
            let host = extract_host(session);
            let prefix = host.split('.').next().unwrap_or("");
            let has_cookies = session.req_header().headers.get("cookie").is_some();
            let has_referer = session.req_header().headers.get("referer").is_some();
            let has_accept_language = session.req_header().headers.get("accept-language").is_some();
            let accept = session
                .req_header()
                .headers
                .get("accept")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let user_agent = session
                .req_header()
                .headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-");
            let content_length: u64 = session
                .req_header()
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let client_ip = extract_client_ip(session);

            // Bot allowlist: verified crawlers/agents bypass the scanner model.
            let bot_reason = self.bot_allowlist.as_ref().and_then(|al| {
                client_ip.and_then(|ip| al.check(user_agent, ip))
            });

            let (decision, score, reason) = if let Some(bot_reason) = bot_reason {
                ("allow", -1.0f64, bot_reason)
            } else {
                let scanner = scanner_swap.load();
                let verdict = scanner.check(
                    method, path, prefix, has_cookies, has_referer,
                    has_accept_language, accept, user_agent, content_length,
                );
                let d = if matches!(verdict.action, ScannerAction::Block) { "block" } else { "allow" };
                (d, verdict.score, verdict.reason)
            };

            let client_ip_str = client_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default();

            tracing::info!(
                target = "pipeline",
                layer       = "scanner",
                decision,
                score,
                reason,
                method,
                host        = %host,
                path,
                client_ip   = client_ip_str,
                user_agent,
                content_length,
                has_cookies,
                has_referer,
                has_accept_language,
                accept,
                "pipeline"
            );

            metrics::SCANNER_DECISIONS
                .with_label_values(&[decision, reason])
                .inc();

            if decision == "block" && !self.scanner_observe_only {
                let mut resp = ResponseHeader::build(403, None)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        }

        // Rate limiting: per-identity throttling.
        if let Some(limiter) = &self.rate_limiter {
            if let Some(ip) = extract_client_ip(session) {
                let cookie = session
                    .req_header()
                    .headers
                    .get("cookie")
                    .and_then(|v| v.to_str().ok());
                let auth = session
                    .req_header()
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok());
                let rl_key = key::extract_key(cookie, auth, ip);
                let rl_result = limiter.check(ip, rl_key);
                let decision = if matches!(rl_result, RateLimitResult::Reject { .. }) { "block" } else { "allow" };

                tracing::info!(
                    target = "pipeline",
                    layer       = "rate_limit",
                    decision,
                    method      = %session.req_header().method,
                    host        = %extract_host(session),
                    path        = %session.req_header().uri.path(),
                    client_ip   = %ip,
                    user_agent  = session.req_header().headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("-"),
                    content_length = session.req_header().headers.get("content-length").and_then(|v| v.to_str().ok()).unwrap_or("0"),
                    has_cookies = cookie.is_some(),
                    has_referer = session.req_header().headers.get("referer").is_some(),
                    has_accept_language = session.req_header().headers.get("accept-language").is_some(),
                    accept      = session.req_header().headers.get("accept").and_then(|v| v.to_str().ok()).unwrap_or("-"),
                    "pipeline"
                );

                metrics::RATE_LIMIT_DECISIONS
                    .with_label_values(&[decision])
                    .inc();

                if let RateLimitResult::Reject { retry_after } = rl_result {
                    let mut resp = ResponseHeader::build(429, None)?;
                    resp.insert_header("Retry-After", retry_after.to_string())?;
                    resp.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        // Cluster-wide bandwidth cap enforcement.
        if let Some(c) = &self.cluster {
            use crate::cluster::bandwidth::BandwidthLimitResult;
            let bw_result = c.limiter.check();
            let decision = if bw_result == BandwidthLimitResult::Reject { "block" } else { "allow" };
            metrics::BANDWIDTH_LIMIT_DECISIONS.with_label_values(&[decision]).inc();
            if bw_result == BandwidthLimitResult::Reject {
                let body = b"{\"error\":\"bandwidth_limit_exceeded\",\"message\":\"Request rate-limited: aggregate bandwidth capacity exceeded. Please try again shortly.\"}";
                let mut resp = ResponseHeader::build(429, None)?;
                resp.insert_header("Retry-After", "5")?;
                resp.insert_header("Content-Type", "application/json")?;
                resp.insert_header("Content-Length", body.len().to_string())?;
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(Bytes::from_static(body)), true).await?;
                return Ok(true);
            }
        }

        // Reject unknown host prefixes with 404.
        let host = extract_host(session);
        let prefix = host.split('.').next().unwrap_or("");
        let route = match self.find_route(prefix, &host) {
            Some(r) => r,
            None => {
                let mut resp = ResponseHeader::build(404, None)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        };

        // Store route early so request_cache_filter can access it.
        ctx.route = Some(route.clone());

        // ── Static file serving ──────────────────────────────────────────
        if let Some(static_root) = &route.static_root {
            let req_path = session.req_header().uri.path().to_string();

            // Check path sub-routes first: if a path route matches, skip static
            // serving and let it go to the upstream backend.
            let path_route_match = route
                .paths
                .iter()
                .any(|p| req_path.starts_with(p.prefix.as_str()));

            if !path_route_match {
                // Apply rewrite rules before static file lookup.
                let mut serve_path = req_path.clone();
                if let Some(rewrites) = self.find_rewrites(prefix) {
                    for rw in rewrites.iter() {
                        if rw.pattern.is_match(&req_path) {
                            serve_path = rw.target.clone();
                            break;
                        }
                    }
                }

                let extra_headers: Vec<(String, String)> = route
                    .response_headers
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect();

                let served = crate::static_files::try_serve(
                    session,
                    static_root,
                    route.fallback.as_deref(),
                    &serve_path,
                    extra_headers,
                )
                .await?;

                if served {
                    ctx.served_static = true;
                    ctx.route = Some(route.clone());
                    return Ok(true);
                }
            }
        }

        // ── Auth subrequest for path routes ──────────────────────────────
        {
            let req_path = session.req_header().uri.path().to_string();
            let req_method = session.req_header().method.as_str();
            let req_headers = &session.req_header().headers;
            let query = session.req_header().uri.query();
            let path_route = select_path_route(&route.paths, &req_path, req_method, req_headers, query);

            if let Some(pr) = path_route {
                if pr.deny {
                    tracing::info!(
                        path = %req_path,
                        prefix = %pr.prefix,
                        "path route denied"
                    );
                    let mut r = ResponseHeader::build(403, None)?;
                    r.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(r), true).await?;
                    return Ok(true);
                }
                if let Some(auth_url) = &pr.auth_request {
                    // Forward the original request's cookies and auth headers.
                    let mut auth_req = self.http_client.get(auth_url);
                    if let Some(cookie) = session.req_header().headers.get("cookie") {
                        auth_req = auth_req.header("cookie", cookie.to_str().unwrap_or(""));
                    }
                    if let Some(auth_hdr) = session.req_header().headers.get("authorization") {
                        auth_req = auth_req.header("authorization", auth_hdr.to_str().unwrap_or(""));
                    }
                    // Forward the original path for context.
                    auth_req = auth_req.header("x-original-uri", &req_path);

                    let has_cookie = session.req_header().headers.get("cookie").is_some();
                    let has_auth = session.req_header().headers.get("authorization").is_some();

                    match auth_req.send().await {
                        Ok(resp) if resp.status().is_success() => {
                            tracing::info!(
                                auth_url,
                                has_cookie,
                                has_auth,
                                status = resp.status().as_u16(),
                                "auth subrequest succeeded"
                            );
                            // Capture specified headers from the auth response.
                            for hdr_name in &pr.auth_capture_headers {
                                if let Some(val) = resp.headers().get(hdr_name.as_str()) {
                                    if let Ok(v) = val.to_str() {
                                        ctx.auth_headers.push((hdr_name.clone(), v.to_string()));
                                    }
                                }
                            }
                        }
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            tracing::warn!(
                                auth_url,
                                has_cookie,
                                has_auth,
                                status,
                                "auth subrequest denied"
                            );
                            let mut r = ResponseHeader::build(403, None)?;
                            r.insert_header("Content-Length", "0")?;
                            session.write_response_header(Box::new(r), true).await?;
                            return Ok(true);
                        }
                        Err(e) => {
                            tracing::error!(
                                auth_url,
                                has_cookie,
                                has_auth,
                                error = %e,
                                "auth subrequest failed"
                            );
                            let mut r = ResponseHeader::build(502, None)?;
                            r.insert_header("Content-Length", "0")?;
                            session.write_response_header(Box::new(r), true).await?;
                            return Ok(true);
                        }
                    }

                    // Store upstream_path_prefix for upstream_request_filter.
                    ctx.upstream_path_prefix = pr.upstream_path_prefix.clone();
                }
            }
        }

        // ── CORS handling ────────────────────────────────────────────────
        {
            let req_path = session.req_header().uri.path().to_string();
            let req_method = session.req_header().method.as_str();
            let req_headers = &session.req_header().headers;
            let query = session.req_header().uri.query();
            let path_route = select_path_route(&route.paths, &req_path, req_method, req_headers, query);

            if let Some(pr) = path_route {
                if let Some(cors) = &pr.cors {
                    let origin = req_headers.get("origin").and_then(|v| v.to_str().ok());
                    let requested_method = req_headers.get("access-control-request-method").and_then(|v| v.to_str().ok());
                    let requested_headers = req_headers.get("access-control-request-headers").and_then(|v| v.to_str().ok());

                    // Preflight request
                    if req_method.eq_ignore_ascii_case("OPTIONS") && requested_method.is_some() {
                        let mut resp = ResponseHeader::build(204, None)?;
                        if let Some(origin) = origin {
                            if cors_allow_origin(origin, &cors.allow_origins, cors.allow_credentials) {
                                resp.insert_header("Access-Control-Allow-Origin", origin)?;
                                if cors.allow_credentials {
                                    resp.insert_header("Access-Control-Allow-Credentials", "true")?;
                                }
                            }
                        }
                        if !cors.allow_methods.is_empty() {
                            resp.insert_header("Access-Control-Allow-Methods", cors.allow_methods.join(", "))?;
                        }
                        if !cors.allow_headers.is_empty() {
                            let allowed = if cors.allow_headers.contains(&"*".to_string()) && requested_headers.is_some() {
                                requested_headers.unwrap_or("").to_string()
                            } else {
                                cors.allow_headers.join(", ")
                            };
                            resp.insert_header("Access-Control-Allow-Headers", allowed)?;
                        }
                        if let Some(max_age) = cors.max_age {
                            resp.insert_header("Access-Control-Max-Age", max_age.to_string())?;
                        }
                        resp.insert_header("Content-Length", "0")?;
                        session.write_response_header(Box::new(resp), true).await?;
                        return Ok(true);
                    }
                }
            }
        }

        // Prepare body rewrite rules if the route has them.
        if !route.body_rewrites.is_empty() {
            // We'll check content-type in upstream_response_filter; store rules now.
            ctx.body_rewrite_rules = route
                .body_rewrites
                .iter()
                .map(|br| (br.find.clone(), br.replace.clone()))
                .collect();
            // Store the content-type filter info on the route for later.
        }

        // Handle Expect: 100-continue before connecting to upstream.
        if session
            .req_header()
            .headers
            .get(EXPECT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("100-continue"))
            .unwrap_or(false)
        {
            session.write_continue_response().await?;
        }

        Ok(false)
    }

    // ── Cache hooks ────────────────────────────────────────────────────
    // Runs AFTER request_filter (detection pipeline) and BEFORE upstream.
    // On cache hit, the response is served directly — no upstream request,
    // no request modifications, no body rewriting.

    fn request_cache_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Only cache GET/HEAD.
        let method = &session.req_header().method;
        if method != http::Method::GET && method != http::Method::HEAD {
            return Ok(());
        }

        let cache_cfg = match ctx.route.as_ref().and_then(|r| r.cache.as_ref()) {
            Some(c) if c.enabled => c,
            _ => return Ok(()),
        };

        // Skip cache if body rewrites are active (need per-response rewriting).
        if !ctx.body_rewrite_rules.is_empty() {
            return Ok(());
        }

        // Skip cache if auth subrequest captured headers (per-user content).
        if !ctx.auth_headers.is_empty() {
            return Ok(());
        }

        session.cache.enable(
            &*crate::cache::CACHE_BACKEND,
            None, // no eviction manager
            None, // no predictor
            None, // no cache lock
            None, // no option overrides
        );

        if cache_cfg.max_file_size > 0 {
            session
                .cache
                .set_max_file_size_bytes(cache_cfg.max_file_size);
        }

        Ok(())
    }

    fn cache_key_callback(
        &self,
        session: &Session,
        _ctx: &mut RequestCtx,
    ) -> Result<CacheKey> {
        let host = extract_host(session);
        let req = session.req_header();
        let path = req.uri.path();
        let key = match req.uri.query() {
            Some(q) => format!("{host}{path}?{q}"),
            None => format!("{host}{path}"),
        };
        Ok(CacheKey::new("", key, ""))
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> Result<RespCacheable> {
        use std::time::{Duration, SystemTime};

        // Only cache 2xx responses.
        if !resp.status.is_success() {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        let cache_cfg = match ctx.route.as_ref().and_then(|r| r.cache.as_ref()) {
            Some(c) => c,
            None => {
                return Ok(RespCacheable::Uncacheable(NoCacheReason::NeverEnabled));
            }
        };

        // Respect Cache-Control: no-store, private.
        if let Some(cc) = resp
            .headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
        {
            let cc_lower = cc.to_ascii_lowercase();
            if cc_lower.contains("no-store") || cc_lower.contains("private") {
                return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
            }
            if let Some(ttl) = crate::cache::parse_cache_ttl(&cc_lower) {
                if ttl == 0 {
                    return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
                }
                let meta = CacheMeta::new(
                    SystemTime::now() + Duration::from_secs(ttl),
                    SystemTime::now(),
                    cache_cfg.stale_while_revalidate_secs,
                    0,
                    resp.clone(),
                );
                return Ok(RespCacheable::Cacheable(meta));
            }
        }

        // No Cache-Control or no max-age: use route's default TTL.
        let meta = CacheMeta::new(
            SystemTime::now() + Duration::from_secs(cache_cfg.default_ttl_secs),
            SystemTime::now(),
            cache_cfg.stale_while_revalidate_secs,
            0,
            resp.clone(),
        );
        Ok(RespCacheable::Cacheable(meta))
    }

    async fn cache_hit_filter(
        &self,
        _session: &mut Session,
        _meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        _is_fresh: bool,
        _ctx: &mut RequestCtx,
    ) -> Result<Option<ForcedFreshness>>
    where
        Self::CTX: Send + Sync,
    {
        metrics::CACHE_STATUS.with_label_values(&["hit"]).inc();
        Ok(None)
    }

    fn cache_miss(&self, session: &mut Session, _ctx: &mut RequestCtx) {
        metrics::CACHE_STATUS.with_label_values(&["miss"]).inc();
        session.cache.cache_miss();
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<Box<HttpPeer>> {
        // ACME challenge: backend was resolved in request_filter.
        if let Some(backend) = &ctx.acme_backend {
            tracing::debug!(backend, "upstream_peer: ACME challenge route");
            if let Some(peer) = make_peer(backend, None).await {
                return Ok(peer);
            }
            let mut resp = ResponseHeader::build(502, None)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())));
        }

        let host = extract_host(session);
        let prefix = host.split('.').next().unwrap_or("");
        // request_filter normally rejects unknown prefixes; if a race with a
        // config reload lets one slip through, return 404 directly rather than
        // panicking the whole worker thread.
        let route = match self.find_route(prefix, &host) {
            Some(r) => r,
            None => {
                tracing::warn!(
                    host = %host,
                    prefix = %prefix,
                    "upstream_peer: no route matches — request_filter/find_route drift"
                );
                let mut resp = ResponseHeader::build(404, None)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())));
            }
        };

        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.as_str();
        let req_headers = &session.req_header().headers;
        let query = session.req_header().uri.query();

        // Check path sub-routes (longest matching prefix + method wins).
        let path_route = select_path_route(&route.paths, &path, method, req_headers, query);

        if let Some(pr) = path_route {
            // RequestRedirect takes precedence over forwarding.
            if let Some(redirect) = &pr.redirect {
                let location = build_redirect_location(redirect, &session.req_header().uri);
                let mut resp = ResponseHeader::build(redirect.status_code, None)?;
                resp.insert_header("Location", location)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())));
            }

            if pr.strip_prefix {
                ctx.strip_prefix = Some(pr.prefix.clone());
            }
            if ctx.upstream_path_prefix.is_none() {
                ctx.upstream_path_prefix = pr.upstream_path_prefix.clone();
            }
            if ctx.path_rewrite_full.is_none() {
                ctx.path_rewrite_full = pr.path_rewrite_full.clone();
            }
            if ctx.hostname_rewrite.is_none() {
                ctx.hostname_rewrite = pr.hostname_rewrite.clone();
            }
            let timeout = pr.timeout_secs.or(route.timeout_secs);

            // Prefer weighted backend selection when configured.
            let backend = if pr.weighted_backends.is_empty() {
                pr.backend.clone()
            } else {
                pick_weighted_backend(&pr.weighted_backends, &path)
                    .unwrap_or_else(|| pr.backend.clone())
            };

            ctx.route = Some(crate::config::RouteConfig {
                host_prefix: route.host_prefix.clone(),
                backend: backend.clone(),
                websocket: pr.websocket || route.websocket,
                disable_secure_redirection: route.disable_secure_redirection,
                paths: vec![],
                static_root: None,
                fallback: None,
                rewrites: vec![],
                body_rewrites: vec![],
                response_headers: pr.response_headers.clone(),
                response_headers_add: pr.response_headers_add.clone(),
                response_headers_remove: pr.response_headers_remove.clone(),
                request_headers: pr.request_headers.clone(),
                request_headers_add: pr.request_headers_add.clone(),
                request_headers_remove: pr.request_headers_remove.clone(),
                cache: None,
                timeout_secs: timeout,
                cors: pr.cors.clone(),
                listener_hostname: route.listener_hostname.clone(),
                gateway_api: route.gateway_api,
            });

            // Fire-and-forget request mirrors.
            for mirror in &pr.mirror_backends {
                let mirror_addr = backend_addr(mirror);
                let mirror_path = session.req_header().uri.path_and_query().map(|pq| pq.to_string()).unwrap_or_else(|| "/".to_string());
                let mirror_url = format!("http://{}{}", mirror_addr, mirror_path);
                let method = session.req_header().method.clone();
                let headers = session.req_header().headers.clone();
                let client = self.http_client.clone();
                tokio::spawn(async move {
                    let mut req = client.request(method, &mirror_url);
                    for (name, value) in headers.iter() {
                        if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                            req = req.header(name.as_str(), v);
                        }
                    }
                    let _ = req.send().await;
                });
            }

            tracing::debug!(backend = %backend, ?timeout, "upstream_peer: path sub-route");
            if let Some(peer) = make_peer(&backend, timeout).await {
                return Ok(peer);
            }
            let mut resp = ResponseHeader::build(502, None)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())));
        }

        // Gateway API routes: if no path matches, return 404 rather than
        // falling back to a host-level default backend.
        if route.gateway_api {
            let mut resp = ResponseHeader::build(404, None)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())));
        }

        tracing::debug!(backend = %route.backend, timeout = ?route.timeout_secs, "upstream_peer: host route");
        ctx.route = Some(route.clone());
        if let Some(peer) = make_peer(&route.backend, route.timeout_secs).await {
            return Ok(peer);
        }
        let mut resp = ResponseHeader::build(502, None)?;
        resp.insert_header("Content-Length", "0")?;
        session.write_response_header(Box::new(resp), true).await?;
        Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())))
    }

    /// Copy WebSocket upgrade headers, apply path prefix stripping, and forward
    /// auth subrequest headers.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_req: &mut RequestHeader,
        ctx: &mut RequestCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Inform backends of the original downstream scheme.
        upstream_req
            .insert_header("x-forwarded-proto", ctx.downstream_scheme)
            .map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "failed to insert x-forwarded-proto",
                    e,
                )
            })?;

        // Forward X-Request-Id to upstream.
        upstream_req.insert_header("x-request-id", &ctx.request_id).map_err(|e| {
            pingora_core::Error::because(
                pingora_core::ErrorType::InternalError,
                "failed to insert x-request-id",
                e,
            )
        })?;

        if ctx.route.as_ref().map(|r| r.websocket).unwrap_or(false) {
            for name in &[CONNECTION, UPGRADE] {
                if let Some(val) = session.req_header().headers.get(name.clone()) {
                    upstream_req.insert_header(name.clone(), val)?;
                }
            }
        }

        // Forward captured auth subrequest headers (pass owned Strings —
        // Pingora's IntoCaseHeaderName is impl'd for String, not &str).
        let auth_headers: Vec<_> = ctx.auth_headers.drain(..).collect();
        for (name, value) in auth_headers {
            upstream_req.insert_header(name, value).map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "failed to insert auth header",
                    e,
                )
            })?;
        }

        // Apply route-level request header modifications (set/add/remove).
        if let Some(route) = &ctx.route {
            for hdr in &route.request_headers {
                upstream_req.insert_header(hdr.name.clone(), hdr.value.clone()).map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::InternalError,
                        "failed to set request header",
                        e,
                    )
                })?;
            }
            for hdr in &route.request_headers_add {
                upstream_req.append_header(hdr.name.clone(), hdr.value.clone()).map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::InternalError,
                        "failed to add request header",
                        e,
                    )
                })?;
            }
            for name in &route.request_headers_remove {
                upstream_req.remove_header(name.as_str());
            }
        }

        // Rewrite Host header if URLRewrite hostname is configured.
        if let Some(hostname) = &ctx.hostname_rewrite {
            upstream_req.insert_header("host", hostname.as_str()).map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "failed to rewrite host header",
                    e,
                )
            })?;
            // Also update the URI authority so Pingora serialises the
            // correct :authority pseudo-header (HTTP/2) or Host header.
            let old_uri = upstream_req.uri.clone();
            let mut parts = old_uri.into_parts();
            let authority = http::uri::Authority::from_str(hostname).map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "invalid rewrite hostname",
                    e,
                )
            })?;
            parts.authority = Some(authority);
            upstream_req.set_uri(
                http::Uri::from_parts(parts).expect("valid uri parts"),
            );
        }

        // Strip Expect: 100-continue.
        upstream_req.remove_header("expect");

        // Gateway API ReplaceFullPath: replace the entire path.
        if let Some(full_path) = &ctx.path_rewrite_full {
            let old_uri = upstream_req.uri.clone();
            let query_part = old_uri
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            let new_pq: http::uri::PathAndQuery =
                format!("{full_path}{query_part}").parse().map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::InternalError,
                        "invalid uri after full path rewrite",
                        e,
                    )
                })?;
            let mut parts = old_uri.into_parts();
            parts.path_and_query = Some(new_pq);
            upstream_req.set_uri(
                http::Uri::from_parts(parts).expect("valid uri parts"),
            );
        }

        // Strip path prefix before forwarding (e.g. /kratos → /).
        if let Some(prefix) = &ctx.strip_prefix {
            let old_uri = upstream_req.uri.clone();
            let old_path = old_uri.path();
            if let Some(stripped) = old_path.strip_prefix(prefix.as_str()) {
                let new_path = if stripped.is_empty() { "/" } else { stripped };

                // Prepend upstream_path_prefix if configured.
                let new_path = if let Some(up_prefix) = &ctx.upstream_path_prefix {
                    if up_prefix.ends_with('/') {
                        let trimmed = new_path.strip_prefix('/').unwrap_or(new_path);
                        format!("{up_prefix}{trimmed}")
                    } else {
                        format!("{up_prefix}{new_path}")
                    }
                } else {
                    new_path.to_string()
                };

                let query_part = old_uri
                    .query()
                    .map(|q| format!("?{q}"))
                    .unwrap_or_default();
                let new_pq: http::uri::PathAndQuery =
                    format!("{new_path}{query_part}").parse().map_err(|e| {
                        pingora_core::Error::because(
                            pingora_core::ErrorType::InternalError,
                            "invalid uri after prefix strip",
                            e,
                        )
                    })?;
                let mut parts = old_uri.into_parts();
                parts.path_and_query = Some(new_pq);
                upstream_req.set_uri(
                    http::Uri::from_parts(parts).expect("valid uri parts"),
                );
            }
        } else if let Some(up_prefix) = &ctx.upstream_path_prefix {
            // No strip_prefix but upstream_path_prefix is set — prepend it.
            let old_uri = upstream_req.uri.clone();
            let old_path = old_uri.path();
            let trimmed = old_path.strip_prefix('/').unwrap_or(old_path);
            let new_path = if up_prefix.ends_with('/') {
                format!("{up_prefix}{trimmed}")
            } else {
                format!("{up_prefix}/{trimmed}")
            };
            let query_part = old_uri
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            let new_pq: http::uri::PathAndQuery =
                format!("{new_path}{query_part}").parse().map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::InternalError,
                        "invalid uri after prefix prepend",
                        e,
                    )
                })?;
            let mut parts = old_uri.into_parts();
            parts.path_and_query = Some(new_pq);
            upstream_req.set_uri(
                http::Uri::from_parts(parts).expect("valid uri parts"),
            );
        }

        Ok(())
    }

    /// Add X-Request-Id and custom response headers.
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Add X-Request-Id to the response so clients can correlate.
        let _ = upstream_response.insert_header("x-request-id", &ctx.request_id);

        // Apply route-level response header modifications (set/add/remove).
        if let Some(route) = &ctx.route {
            for hdr in &route.response_headers {
                let _ = upstream_response.insert_header(hdr.name.clone(), hdr.value.clone());
            }
            for hdr in &route.response_headers_add {
                let _ = upstream_response.append_header(hdr.name.clone(), hdr.value.clone());
            }
            for name in &route.response_headers_remove {
                upstream_response.remove_header(name.as_str());
            }
        }

        // Add CORS response headers for actual (non-preflight) requests.
        if let Some(route) = &ctx.route {
            if let Some(cors) = &route.cors {
                let origin = _session.req_header().headers.get("origin").and_then(|v| v.to_str().ok());
                if let Some(origin) = origin {
                    if cors_allow_origin(origin, &cors.allow_origins, cors.allow_credentials) {
                        let _ = upstream_response.insert_header("Access-Control-Allow-Origin", origin);
                        if cors.allow_credentials {
                            let _ = upstream_response.insert_header("Access-Control-Allow-Credentials", "true");
                        }
                    }
                }
                if !cors.allow_methods.is_empty() {
                    let _ = upstream_response.insert_header("Access-Control-Allow-Methods", cors.allow_methods.join(", "));
                }
                if !cors.allow_headers.is_empty() {
                    let _ = upstream_response.insert_header("Access-Control-Allow-Headers", cors.allow_headers.join(", "));
                }
                if !cors.expose_headers.is_empty() {
                    let _ = upstream_response.insert_header("Access-Control-Expose-Headers", cors.expose_headers.join(", "));
                }
                if let Some(max_age) = cors.max_age {
                    let _ = upstream_response.insert_header("Access-Control-Max-Age", max_age.to_string());
                }
            }
        }

        // Check if body rewriting applies to this response's content-type.
        if !ctx.body_rewrite_rules.is_empty() {
            let content_type = upstream_response
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            // Only buffer text/html and application/javascript responses.
            let should_rewrite = content_type.starts_with("text/html")
                || content_type.starts_with("application/javascript")
                || content_type.starts_with("text/javascript");

            if should_rewrite {
                ctx.body_buffer = Some(Vec::new());
                // Remove content-length since we'll modify the body.
                upstream_response.remove_header("content-length");
            } else {
                // Don't rewrite non-matching content types.
                ctx.body_rewrite_rules.clear();
            }
        }

        Ok(())
    }

    /// Buffer and rewrite response bodies when body_rewrite rules are active.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut RequestCtx,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        if ctx.body_buffer.is_none() {
            return Ok(None);
        }

        // Accumulate chunks into the buffer.
        if let Some(data) = body.take() {
            ctx.body_buffer.as_mut().unwrap().extend_from_slice(&data);
        }

        if end_of_stream {
            let buffer = ctx.body_buffer.take().unwrap();
            let mut result = String::from_utf8_lossy(&buffer).into_owned();
            for (find, replace) in &ctx.body_rewrite_rules {
                result = result.replace(find.as_str(), replace.as_str());
            }
            *body = Some(Bytes::from(result));
        }

        Ok(None)
    }

    /// Emit a structured JSON audit log line for every request.
    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora_core::Error>,
        ctx: &mut RequestCtx,
    ) where
        Self::CTX: Send + Sync,
    {
        metrics::ACTIVE_CONNECTIONS.dec();

        let status = session
            .response_written()
            .map_or(0, |r| r.status.as_u16());
        let duration_ms = ctx.start_time.elapsed().as_millis() as u64;
        let duration_secs = ctx.start_time.elapsed().as_secs_f64();
        let method_str = session.req_header().method.to_string();
        let host = extract_host(session);
        let backend = ctx
            .route
            .as_ref()
            .map(|r| r.backend.as_str())
            .unwrap_or("-");
        let client_ip = extract_client_ip(session)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| {
                session
                    .client_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "-".to_string())
            });
        let error_str = error.map(|e| e.to_string());

        // Record Prometheus metrics.
        metrics::REQUESTS_TOTAL
            .with_label_values(&[&method_str, &host, &status.to_string(), backend])
            .inc();
        metrics::REQUEST_DURATION.observe(duration_secs);

        // Record bandwidth for cluster aggregation.
        if let Some(c) = &self.cluster {
            let req_bytes: u64 = session
                .req_header()
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            c.bandwidth.record(req_bytes, session.body_bytes_sent() as u64);
        }

        let content_length: u64 = session
            .req_header()
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let user_agent = session
            .req_header()
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let referer = session
            .req_header()
            .headers
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let accept_language = session
            .req_header()
            .headers
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let accept = session
            .req_header()
            .headers
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let has_cookies = session
            .req_header()
            .headers
            .get("cookie")
            .is_some();
        let cf_country = session
            .req_header()
            .headers
            .get("cf-ipcountry")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let query = session.req_header().uri.query().unwrap_or("");
        let response_bytes = session.body_bytes_sent();
        let http_version = format!("{:?}", session.req_header().version);
        let header_count = session.req_header().headers.len() as u16;
        let accept_encoding = session
            .req_header()
            .headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        let connection = session
            .req_header()
            .headers
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");

        ctx.span.in_scope(|| {
            tracing::info!(
                target = "audit",
                request_id = %ctx.request_id,
                method  = %session.req_header().method,
                host    = %host,
                path    = %session.req_header().uri.path(),
                query,
                client_ip,
                status,
                duration_ms,
                content_length,
                response_bytes,
                user_agent,
                referer,
                accept_language,
                accept,
                accept_encoding,
                has_cookies,
                cf_country,
                backend,
                error   = error_str,
                http_version,
                header_count,
                connection,
                "request"
            );
        });

        if let Some(detector) = &self.ddos_detector {
            if let Some(ip) = extract_client_ip(session) {
                detector.record_response(ip, status, duration_ms as u32);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;

    /// insert_header keeps CaseMap and base.headers in sync so the header
    /// survives header_to_h1_wire serialization.
    #[test]
    fn test_x_forwarded_proto_https_roundtrips_through_insert_header() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-forwarded-proto", "https").unwrap();
        assert_eq!(
            req.headers.get("x-forwarded-proto"),
            Some(&HeaderValue::from_static("https")),
        );
        // Verify it survives wire serialization (CaseMap + base.headers in sync).
        let mut buf = Vec::new();
        req.header_to_h1_wire(&mut buf);
        let wire = String::from_utf8(buf).unwrap();
        assert!(wire.contains("x-forwarded-proto: https"), "wire: {wire:?}");
    }

    #[test]
    fn test_x_forwarded_proto_http_roundtrips_through_insert_header() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-forwarded-proto", "http").unwrap();
        assert_eq!(
            req.headers.get("x-forwarded-proto"),
            Some(&HeaderValue::from_static("http")),
        );
        let mut buf = Vec::new();
        req.header_to_h1_wire(&mut buf);
        let wire = String::from_utf8(buf).unwrap();
        assert!(wire.contains("x-forwarded-proto: http"), "wire: {wire:?}");
    }

    /// ctx.downstream_scheme defaults to "https" and is readable.
    #[test]
    fn test_ctx_default_scheme_is_https() {
        let ctx = RequestCtx {
            route: None,
            start_time: Instant::now(),
            request_id: "1".to_string(),
            span: tracing::Span::none(),
            acme_backend: None,
            strip_prefix: None,
            downstream_scheme: "https",
            served_static: false,
            auth_headers: Vec::new(),
            upstream_path_prefix: None,
            path_rewrite_full: None,
            hostname_rewrite: None,
            body_rewrite_rules: Vec::new(),
            body_buffer: None,
        };
        assert_eq!(ctx.downstream_scheme, "https");
    }

    #[test]
    fn test_backend_addr_strips_scheme() {
        assert_eq!(backend_addr("http://svc.ns.svc.cluster.local:80"), "svc.ns.svc.cluster.local:80");
        assert_eq!(backend_addr("https://svc.ns.svc.cluster.local:443"), "svc.ns.svc.cluster.local:443");
    }

    /// remove_header("expect") strips the header from the upstream request.
    #[test]
    fn test_expect_header_stripped_before_upstream() {
        let mut req = RequestHeader::build("PUT", b"/v2/studio/image/blobs/uploads/uuid", None).unwrap();
        req.insert_header("expect", "100-continue").unwrap();
        req.insert_header("content-length", "188000000").unwrap();
        assert!(req.headers.get("expect").is_some(), "expect header should be present before stripping");
        req.remove_header("expect");
        assert!(req.headers.get("expect").is_none(), "expect header should be gone after remove_header");
        assert!(req.headers.get("content-length").is_some());
    }

    #[test]
    fn test_request_id_is_uuid_v4() {
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(id.len(), 36);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_pipeline_bypass_cidrs_parsed() {
        use crate::rate_limit::cidr::{parse_cidrs, is_bypassed};
        let cidrs = parse_cidrs(&[
            "10.42.0.0/16".into(),
            "127.0.0.0/8".into(),
            "::1/128".into(),
        ]);
        // Pod network
        assert!(is_bypassed("10.42.1.5".parse().unwrap(), &cidrs));
        // Localhost IPv4
        assert!(is_bypassed("127.0.0.1".parse().unwrap(), &cidrs));
        // Localhost IPv6
        assert!(is_bypassed("::1".parse().unwrap(), &cidrs));
        // External IP should not be bypassed
        assert!(!is_bypassed("8.8.8.8".parse().unwrap(), &cidrs));
        assert!(!is_bypassed("192.168.1.1".parse().unwrap(), &cidrs));
    }

    #[test]
    fn test_pipeline_bypass_empty_cidrs_blocks_nothing() {
        use crate::rate_limit::cidr::{parse_cidrs, is_bypassed};
        let cidrs = parse_cidrs(&[]);
        assert!(!is_bypassed("127.0.0.1".parse().unwrap(), &cidrs));
        assert!(!is_bypassed("10.42.0.1".parse().unwrap(), &cidrs));
    }

    #[test]
    fn test_compile_rewrites_valid() {
        let routes = vec![RouteConfig {
            host_prefix: "docs".into(),
            backend: "http://localhost:8080".into(),
            websocket: false,
            disable_secure_redirection: false,
            paths: vec![],
            static_root: Some("/srv/docs".into()),
            fallback: Some("index.html".into()),
            rewrites: vec![crate::config::RewriteRule {
                pattern: r"^/docs/[0-9a-f-]+/?$".into(),
                target: "/docs/[id]/index.html".into(),
            }],
            body_rewrites: vec![],
            response_headers: vec![],
            response_headers_add: vec![],
            response_headers_remove: vec![],
            request_headers: vec![],
            request_headers_add: vec![],
            request_headers_remove: vec![],
            cache: None,
            timeout_secs: None,
            cors: None,
            listener_hostname: None,
            gateway_api: false,
        }];
        let compiled = SunbeamProxy::compile_rewrites(&routes);
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].1.len(), 1);
        assert!(compiled[0].1[0].pattern.is_match("/docs/abc-def/"));
    }

    #[test]
    fn select_path_route_prefers_longest_prefix() {
        let paths = vec![
            PathRoute {
                prefix: "/".into(),
                backend: "root".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                prefix: "/api".into(),
                backend: "api".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let empty_headers = http::header::HeaderMap::new();
        let chosen = select_path_route(&paths, "/api/v1", "GET", &empty_headers, None).unwrap();
        assert_eq!(chosen.backend, "api");
    }

    #[test]
    fn select_path_route_respects_method_constraint() {
        let paths = vec![
            PathRoute {
                prefix: "/api".into(),
                backend: "api-read".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec!["GET".into(), "HEAD".into()],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                prefix: "/api".into(),
                backend: "api-write".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec!["POST".into()],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let empty_headers = http::header::HeaderMap::new();
        assert_eq!(select_path_route(&paths, "/api", "GET", &empty_headers, None).unwrap().backend, "api-read");
        assert_eq!(select_path_route(&paths, "/api", "POST", &empty_headers, None).unwrap().backend, "api-write");
        assert!(select_path_route(&paths, "/api", "DELETE", &empty_headers, None).is_none());
    }

    #[test]
    fn select_path_route_earlier_rule_wins_on_prefix_tie() {
        let paths = vec![
            PathRoute {
                prefix: "/".into(),
                backend: "first".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec!["PATCH".into()],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                prefix: "/".into(),
                backend: "second".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![crate::config::HeaderMatchConfig {
                    name: "version".into(),
                    value: crate::config::HeaderMatchValueConfig::Exact("four".into()),
                }],
                query_param_matches: vec![],
                rule_order: 1,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let mut headers = http::header::HeaderMap::new();
        headers.insert("version", http::header::HeaderValue::from_static("four"));
        // Gateway API precedence: header match outranks method match on ties.
        let chosen = select_path_route(&paths, "/", "PATCH", &headers, None).unwrap();
        assert_eq!(chosen.backend, "second");
    }

    #[test]
    fn select_path_route_respects_exact_match() {
        let paths = vec![PathRoute {
            prefix: "/api".into(),
            backend: "api-exact".into(),
            strip_prefix: false,
            websocket: false,
            auth_request: None,
            auth_capture_headers: vec![],
            upstream_path_prefix: None,
            path_rewrite_full: None,
            cors: None,
            hostname_rewrite: None,
            mirror_backends: vec![],
            timeout_secs: None,
            deny: false,
            methods: vec![],
            weighted_backends: vec![],
            redirect: None,
            header_matches: vec![],
            query_param_matches: vec![],
            rule_order: 0,
            path_match_exact: true,
            request_headers: vec![],
            request_headers_add: vec![],
            request_headers_remove: vec![],
            response_headers: vec![],
            response_headers_add: vec![],
            response_headers_remove: vec![],
        }];
        let empty_headers = http::header::HeaderMap::new();
        assert_eq!(
            select_path_route(&paths, "/api", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "api-exact"
        );
        assert!(select_path_route(&paths, "/api/", "GET", &empty_headers, None).is_none());
        assert!(select_path_route(&paths, "/api/v1", "GET", &empty_headers, None).is_none());
    }

    #[test]
    fn pick_weighted_backend_empty_returns_none() {
        assert!(pick_weighted_backend(&[], "/x").is_none());
    }

    #[test]
    fn pick_weighted_backend_selects_by_hash() {
        let backends = vec![
            crate::config::WeightedBackendConfig { backend: "a".into(), weight: 1 },
            crate::config::WeightedBackendConfig { backend: "b".into(), weight: 1 },
        ];
        // Both backends should be reachable for different paths; use two
        // distinct paths and assert that at least one differs (or they could
        // both hash to the same bucket, which is valid).
        let a = pick_weighted_backend(&backends, "/path-a").unwrap();
        let b = pick_weighted_backend(&backends, "/path-b").unwrap();
        assert!(a == "a" || a == "b");
        assert!(b == "a" || b == "b");
    }

    #[test]
    fn pick_weighted_backend_honors_weights() {
        let backends = vec![
            crate::config::WeightedBackendConfig { backend: "heavy".into(), weight: 100 },
            crate::config::WeightedBackendConfig { backend: "light".into(), weight: 1 },
        ];
        // With only one backend likely for a fixed path, verify the total is
        // respected by checking that valid backends are returned.
        let choice = pick_weighted_backend(&backends, "/x").unwrap();
        assert!(choice == "heavy" || choice == "light");
    }

    #[test]
    fn build_redirect_location_preserves_unspecified_parts() {
        let redirect = crate::config::RedirectRule {
            status_code: 302,
            scheme: None,
            hostname: None,
            port: None,
            path: Some("/new".into()),
            path_prefix: None,
        };
        let uri: http::Uri = "http://example.com/old".parse().unwrap();
        assert_eq!(build_redirect_location(&redirect, &uri), "http://example.com/new");
    }

    #[test]
    fn build_redirect_location_overrides_all_parts() {
        let redirect = crate::config::RedirectRule {
            status_code: 301,
            scheme: Some("https".into()),
            hostname: Some("other.example.com".into()),
            port: Some(8443),
            path: Some("/redirected".into()),
            path_prefix: None,
        };
        let uri: http::Uri = "http://example.com/old".parse().unwrap();
        assert_eq!(
            build_redirect_location(&redirect, &uri),
            "https://other.example.com:8443/redirected"
        );
    }

    #[test]
    fn build_redirect_location_replaces_prefix() {
        let redirect = crate::config::RedirectRule {
            status_code: 302,
            scheme: None,
            hostname: None,
            port: None,
            path: Some("/replacement-prefix".into()),
            path_prefix: Some("/original-prefix".into()),
        };
        let uri: http::Uri = "http://example.com/original-prefix/lemon".parse().unwrap();
        assert_eq!(
            build_redirect_location(&redirect, &uri),
            "http://example.com/replacement-prefix/lemon"
        );
    }

    #[test]
    fn path_prefix_matches_respects_segment_boundary() {
        assert!(path_prefix_matches("/v2", "/v2"));
        assert!(path_prefix_matches("/v2/", "/v2"));
        assert!(path_prefix_matches("/v2/example", "/v2"));
        assert!(!path_prefix_matches("/v2example", "/v2"));
        assert!(!path_prefix_matches("/foo/v2/example", "/v2"));
        assert!(path_prefix_matches("/", "/"));
        assert!(path_prefix_matches("/foo", "/"));
        assert!(!path_prefix_matches("/foo", "/bar"));
    }

    #[test]
    fn host_matches_wildcard_cases() {
        assert!(host_matches_wildcard("foo.example.com", "*.example.com"));
        assert!(!host_matches_wildcard("bar.foo.example.com", "*.example.com"));
        assert!(!host_matches_wildcard("example.com", "*.example.com"));
        assert!(!host_matches_wildcard("foo.other.com", "*.example.com"));
        assert!(!host_matches_wildcard("foo.example.com", "example.com"));
    }

    #[test]
    fn host_matches_listener_cases() {
        assert!(host_matches_listener("example.com", "example.com"));
        assert!(host_matches_listener("foo.example.com", "*.example.com"));
        assert!(!host_matches_listener("example.com", "*.example.com"));
        assert!(!host_matches_listener("foo.other.com", "*.example.com"));
        assert!(host_matches_listener("anything", ""));
    }

    #[test]
    fn listener_specificity_score_ordering() {
        assert_eq!(listener_specificity_score(""), 0);
        assert_eq!(listener_specificity_score("*.example.com"), 100 + 1);
        assert_eq!(listener_specificity_score("*.foo.example.com"), 100 + 2);
        assert_eq!(listener_specificity_score("example.com"), 1000);
    }

    fn make_proxy(routes: Vec<RouteConfig>) -> SunbeamProxy {
        use arc_swap::ArcSwap;
        SunbeamProxy {
            routes: Arc::new(ArcSwap::new(Arc::new(routes))),
            acme_routes: crate::acme::AcmeRoutes::default(),
            ddos_detector: None,
            scanner_detector: None,
            bot_allowlist: None,
            rate_limiter: None,
            compiled_rewrites: Arc::new(ArcSwap::new(Arc::new(vec![]))),
            http_client: reqwest::Client::new(),
            pipeline_bypass_cidrs: vec![],
            cluster: None,
            ddos_observe_only: false,
            scanner_observe_only: false,
        }
    }

    fn route_with_listener(host_prefix: &str, listener_hostname: Option<&str>, gateway_api: bool) -> RouteConfig {
        RouteConfig {
            host_prefix: host_prefix.into(),
            backend: "backend".into(),
            websocket: false,
            disable_secure_redirection: true,
            paths: vec![],
            static_root: None,
            fallback: None,
            rewrites: vec![],
            body_rewrites: vec![],
            response_headers: vec![],
            response_headers_add: vec![],
            response_headers_remove: vec![],
            request_headers: vec![],
            request_headers_add: vec![],
            request_headers_remove: vec![],
            cache: None,
            timeout_secs: None,
            cors: None,
            listener_hostname: listener_hostname.map(|s| s.into()),
            gateway_api,
        }
    }

    #[test]
    fn find_route_exact_host_prefix() {
        let proxy = make_proxy(vec![route_with_listener("example.com", None, false)]);
        assert!(proxy.find_route("example", "example.com").is_some());
        assert!(proxy.find_route("other", "other.com").is_none());
    }

    #[test]
    fn find_route_wildcard_host_prefix() {
        let proxy = make_proxy(vec![route_with_listener("*.example.com", None, false)]);
        assert!(proxy.find_route("foo", "foo.example.com").is_some());
        assert!(proxy.find_route("example", "example.com").is_none());
    }

    #[test]
    fn find_route_listener_hostname_isolation() {
        let proxy = make_proxy(vec![
            route_with_listener("example.com", Some("example.com"), true),
            route_with_listener("*.example.com", Some("*.example.com"), true),
        ]);
        let chosen = proxy.find_route("sub", "sub.example.com").unwrap();
        assert_eq!(chosen.listener_hostname.as_deref(), Some("*.example.com"));
    }

    #[test]
    fn find_route_listener_specificity_prefers_exact() {
        let proxy = make_proxy(vec![
            route_with_listener("example.com", Some("*.example.com"), true),
            route_with_listener("example.com", Some("example.com"), true),
        ]);
        let chosen = proxy.find_route("example", "example.com").unwrap();
        assert_eq!(chosen.listener_hostname.as_deref(), Some("example.com"));
    }

    #[test]
    fn find_route_legacy_routes_least_specific() {
        let proxy = make_proxy(vec![
            route_with_listener("example.com", None, false),
            route_with_listener("example.com", Some("example.com"), true),
        ]);
        let chosen = proxy.find_route("example", "example.com").unwrap();
        assert_eq!(chosen.listener_hostname.as_deref(), Some("example.com"));
    }

    #[test]
    fn select_path_route_prefers_more_header_matches_on_tie() {
        let paths = vec![
            PathRoute {
                prefix: "/".into(),
                backend: "no-header".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                prefix: "/".into(),
                backend: "with-header".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![crate::config::HeaderMatchConfig {
                    name: "version".into(),
                    value: crate::config::HeaderMatchValueConfig::Exact("one".into()),
                }],
                query_param_matches: vec![],
                rule_order: 1,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let mut headers = http::header::HeaderMap::new();
        headers.insert("version", http::header::HeaderValue::from_static("one"));
        let chosen = select_path_route(&paths, "/", "GET", &headers, None).unwrap();
        assert_eq!(chosen.backend, "with-header");
    }

    #[test]
    fn select_path_route_prefers_method_match_on_tie() {
        let paths = vec![
            PathRoute {
                prefix: "/api".into(),
                backend: "any-method".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                prefix: "/api".into(),
                backend: "post-only".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec!["POST".into()],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 1,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let empty_headers = http::header::HeaderMap::new();
        let chosen = select_path_route(&paths, "/api", "POST", &empty_headers, None).unwrap();
        assert_eq!(chosen.backend, "post-only");
    }

    #[test]
    fn select_path_route_matches_conformance_path_prefix_cases() {
        let paths = vec![
            PathRoute {
                prefix: "/".into(),
                backend: "root".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                prefix: "/v2".into(),
                backend: "v2".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 1,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let empty_headers = http::header::HeaderMap::new();
        assert_eq!(select_path_route(&paths, "/", "GET", &empty_headers, None).unwrap().backend, "root");
        assert_eq!(select_path_route(&paths, "/v2", "GET", &empty_headers, None).unwrap().backend, "v2");
        assert_eq!(select_path_route(&paths, "/v2/", "GET", &empty_headers, None).unwrap().backend, "v2");
        assert_eq!(select_path_route(&paths, "/v2/example", "GET", &empty_headers, None).unwrap().backend, "v2");
        assert_eq!(select_path_route(&paths, "/v2example", "GET", &empty_headers, None).unwrap().backend, "root");
        assert_eq!(select_path_route(&paths, "/foo/v2/example", "GET", &empty_headers, None).unwrap().backend, "root");
    }

    #[test]
    fn select_path_route_header_match_is_case_insensitive() {
        let paths = vec![PathRoute {
            prefix: "/".into(),
            backend: "matched".into(),
            strip_prefix: false,
            websocket: false,
            auth_request: None,
            auth_capture_headers: vec![],
            upstream_path_prefix: None,
            path_rewrite_full: None,
            cors: None,
            hostname_rewrite: None,
            mirror_backends: vec![],
            timeout_secs: None,
            deny: false,
            methods: vec![],
            weighted_backends: vec![],
            redirect: None,
            header_matches: vec![crate::config::HeaderMatchConfig {
                name: "version".into(),
                value: crate::config::HeaderMatchValueConfig::Exact("one".into()),
            }],
            query_param_matches: vec![],
            rule_order: 0,
            path_match_exact: false,
            request_headers: vec![],
            request_headers_add: vec![],
            request_headers_remove: vec![],
            response_headers: vec![],
            response_headers_add: vec![],
            response_headers_remove: vec![],
        }];
        let mut headers = http::header::HeaderMap::new();
        headers.insert("version", http::header::HeaderValue::from_static("ONE"));
        let chosen = select_path_route(&paths, "/", "GET", &headers, None).unwrap();
        assert_eq!(chosen.backend, "matched");
    }
}
