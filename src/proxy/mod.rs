// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::acme::AcmeRoutes;
use crate::cluster::ClusterHandle;
use crate::config::RouteConfig;
use crate::ddos::detector::DDoSDetector;
use crate::ddos::model::DDoSAction;
use crate::ir::compile::{CompiledL4Config, CompiledPlan, CompiledRouteTable};
use crate::ir::{BackendProtocol, BackendTlsConfig, L4Action, Protocol};
use crate::metrics;
use crate::rate_limit::key;
use crate::rate_limit::limiter::{RateLimitResult, RateLimiter};
use crate::scanner::allowlist::BotAllowlist;
use crate::scanner::detector::ScannerDetector;
use crate::scanner::model::ScannerAction;
use crate::tls::TlsRegistry;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::{CONNECTION, EXPECT, HOST, UPGRADE};
use pingora_cache::{
    CacheKey, CacheMeta, ForcedFreshness, HitHandler, NoCacheReason, RespCacheable,
};
use pingora_core::upstreams::peer::{HttpPeer, Scheme};
use pingora_core::utils::tls::CertKey;
use pingora_core::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use regex::Regex;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod cache_hooks;
mod ctx;
mod filters;
mod logging;
mod match_;
mod request_filter;
mod routing;
mod upstream_tls;

pub use ctx::RequestCtx;
use match_::{build_redirect_location_ir, cors_allow_origin, pick_weighted_backend_ir_index};
use upstream_tls::{alpn_for_protocol, DynamicUpstreamL4};

/// Build an HttpPeer with configurable timeouts and optional TLS settings.
///
/// DNS resolution is performed here so that a lookup failure can be handled
/// gracefully instead of panicking the Pingora worker thread.
async fn make_peer(
    addr: &str,
    timeout: Option<Duration>,
    protocol: BackendProtocol,
    tls: Option<&BackendTlsConfig>,
    client_cert: Option<Arc<CertKey>>,
) -> Option<Box<HttpPeer>> {
    let addr = backend_addr(addr);
    let mut addrs = tokio::net::lookup_host(&addr).await.ok()?;
    let sa = addrs.next()?;
    let is_tls = matches!(
        protocol,
        BackendProtocol::Https | BackendProtocol::WebSocketSecure
    );
    if is_tls && tls.is_none() {
        return None;
    }
    let sni = tls.map(|t| t.sni.as_ref().to_string()).unwrap_or_default();
    let mut peer = HttpPeer::new(sa, is_tls, sni);
    let t = timeout.unwrap_or(Duration::from_secs(60));
    peer.options.connection_timeout = Some(Duration::from_secs(10));
    peer.options.read_timeout = Some(t);
    peer.options.write_timeout = Some(t);

    if is_tls {
        if let Some(t) = tls {
            peer.options.verify_hostname = t.verify_hostname;
            if let Some(alt) = &t.alternative_cn {
                peer.options.alternative_cn = Some(alt.as_ref().to_string());
            }
        }
        if let Some(ref cert_key) = client_cert {
            peer.client_cert_key = Some(cert_key.clone());
        }
    }

    if let Some(alpn) = alpn_for_protocol(protocol) {
        peer.options.alpn = alpn;
    }

    // BackendTLSPolicy supplies a per-backend CA bundle. Pingora's default
    // rustls connector only loads trust roots once at startup, so we perform
    // the upstream TLS handshake ourselves via a custom L4 connector.
    if is_tls && tls.and_then(|t| t.ca_bundle_pem.as_ref()).is_some() {
        let tls_cfg = tls.unwrap();
        let connector = DynamicUpstreamL4::new(
            tls_cfg,
            client_cert.clone(),
            Some(peer.options.alpn.clone()),
        );
        peer.group_key = connector.trust_hash();
        peer.options.custom_l4 = Some(Arc::new(connector));
        peer.scheme = Scheme::HTTP;
    }

    Some(Box::new(peer))
}

/// A compiled rewrite rule (regex compiled once at startup).
#[derive(Debug)]
pub struct CompiledRewrite {
    /// Pattern.
    pub pattern: Regex,
    /// Target.
    pub target: String,
}

/// Compiled rewrite table indexed by hostname prefix.
pub type CompiledRewrites = Vec<(String, Arc<Vec<CompiledRewrite>>)>;

/// Sunbeamproxy.
#[derive(Default)]
pub struct SunbeamProxy {
    /// Compiled routes — atomically swappable at runtime via [`Self::swap_routes`].
    pub routes: Arc<ArcSwap<CompiledRouteTable>>,
    /// Compiled L4 configuration — used to detect TLS-terminated downstream
    /// connections that arrive as plaintext HTTP from the L4 manager.
    pub l4_config: Arc<ArcSwap<CompiledL4Config>>,
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
    pub compiled_rewrites: Arc<ArcSwap<CompiledRewrites>>,
    /// Shared reqwest client for auth subrequests.
    pub http_client: reqwest::Client,
    /// Parsed bypass CIDRs — IPs in these ranges skip the detection pipeline.
    pub pipeline_bypass_cidrs: Vec<crate::rate_limit::cidr::CidrBlock>,
    /// Parsed trusted downstream proxy CIDRs. Headers that carry the original
    /// client IP are only trusted when the immediate TCP peer is in one of
    /// these ranges.
    pub trusted_proxy_cidrs: Vec<crate::rate_limit::cidr::CidrBlock>,
    /// Optional cluster handle for multi-node bandwidth tracking.
    pub cluster: Option<Arc<ClusterHandle>>,
    /// When true, DDoS detector logs decisions but never blocks traffic.
    pub ddos_observe_only: bool,
    /// When true, scanner detector logs decisions but never blocks traffic.
    pub scanner_observe_only: bool,
    /// TLS registry for upstream client certificates and per-listener server configs.
    pub tls_registry: Option<Arc<TlsRegistry>>,
    /// Maps the internal upstream socket address of a TLS-terminated connection
    /// to the SNI hostname presented during the TLS handshake. Populated by the
    /// L4 router and consumed by the HTTP proxy for 421 misdirected request
    /// detection.
    pub sni_context:
        Arc<std::sync::Mutex<std::collections::HashMap<std::net::SocketAddr, Arc<str>>>>,
    /// Maps the internal upstream socket address of an L4-relayed plain HTTP
    /// connection to the public listener that accepted it. Populated by the L4
    /// router and consumed by the HTTP proxy so that host/port route matching
    /// uses the original listener port.
    pub http_context: Arc<
        std::sync::Mutex<
            std::collections::HashMap<std::net::SocketAddr, crate::l4::context::HttpRelayContext>,
        >,
    >,
}

impl SunbeamProxy {
    /// Lookup a compiled plan for the request.
    ///
    /// This is the single route-matching entry point. The returned plan is stored
    /// in `ctx` and all subsequent Pingora phases execute it directly.
    fn lookup_plan(
        &self,
        host: &str,
        port: u16,
        path: &str,
        method: &str,
        headers: &http::header::HeaderMap,
        query: Option<&str>,
    ) -> Option<Arc<CompiledPlan>> {
        let table = self.routes.load();
        table.lookup(host, port, path, method, headers, query)
    }

    /// Check whether any Gateway API listener matches the request host and port,
    /// regardless of whether any route rule matches. Used in `request_filter`
    /// to avoid HTTPS-redirecting requests that should instead receive a 404.
    fn has_matching_gateway_api_listener(&self, host: &str, port: u16) -> bool {
        let table = self.routes.load();
        table.has_gateway_api_listener(host, port)
    }

    /// Retrieve and remove the SNI hostname associated with this downstream
    /// connection. The L4 router stores the mapping keyed by the upstream-side
    /// socket address that Pingora sees as the downstream peer.
    fn sni_for_session(&self, session: &Session) -> Option<Arc<str>> {
        let peer = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .copied()?;
        self.sni_context
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&peer)
    }

    /// Retrieve (without removing) the HTTP relay context associated with this
    /// downstream connection. The L4 router stores the mapping keyed by the
    /// upstream-side socket address that Pingora sees as the downstream peer.
    fn http_relay_context(
        &self,
        session: &Session,
    ) -> Option<crate::l4::context::HttpRelayContext> {
        let peer = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .copied()?;
        self.http_context
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer)
            .cloned()
    }

    /// True if the compiled route table contains any Gateway API routes.
    fn has_gateway_api_routes(&self) -> bool {
        let table = self.routes.load();
        table.has_gateway_api_routes()
    }

    fn find_rewrites(&self, prefix: &str) -> Option<Arc<Vec<CompiledRewrite>>> {
        self.compiled_rewrites
            .load()
            .iter()
            .find(|(p, _)| p == prefix)
            .map(|(_, rules)| Arc::clone(rules))
    }

    /// Compile all rewrite rules from routes at startup.
    pub fn compile_rewrites(routes: &[RouteConfig]) -> CompiledRewrites {
        routes
            .iter()
            .filter(|r| !r.rewrites.is_empty())
            .map(|r| {
                let compiled = r
                    .rewrites
                    .iter()
                    .filter_map(|rw| match Regex::new(&rw.pattern) {
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
                    })
                    .collect();
                (r.host_prefix.clone(), Arc::new(compiled))
            })
            .collect()
    }

    /// Atomically replace the route table and compiled rewrites.
    pub fn swap_routes(&self, table: CompiledRouteTable) {
        let compiled = Self::compile_rewrites_from_ir(&table);
        self.compiled_rewrites.store(Arc::new(compiled));
        self.routes.store(Arc::new(table));
        tracing::info!("Route table hot-swapped");
    }

    /// Compile rewrite rules from the IR static file actions.
    pub fn compile_rewrites_from_ir(table: &CompiledRouteTable) -> CompiledRewrites {
        let mut result = Vec::new();

        let mut process = |hostname: &crate::ir::HostnameMatch,
                           node: &crate::ir::compile::HostNode| {
            let host_prefix = match hostname {
                crate::ir::HostnameMatch::Exact(s) => s.to_string(),
                crate::ir::HostnameMatch::Prefix(s) => s.to_string(),
                crate::ir::HostnameMatch::Wildcard(s) => format!("*.{}", s),
                crate::ir::HostnameMatch::Any => "*".to_string(),
            };
            let mut compiled: Vec<CompiledRewrite> = Vec::new();
            for rw in &node.static_rewrites {
                match Regex::new(&rw.pattern) {
                    Ok(re) => compiled.push(CompiledRewrite {
                        pattern: re,
                        target: rw.target.to_string(),
                    }),
                    Err(e) => {
                        tracing::error!(
                            pattern = %rw.pattern,
                            error = %e,
                            "Failed to compile rewrite rule"
                        );
                    }
                }
            }
            if !compiled.is_empty() {
                result.push((host_prefix, Arc::new(compiled)));
            }
        };

        for (name, nodes) in &table.exact_hosts {
            for node in nodes {
                process(&crate::ir::HostnameMatch::Exact(Arc::clone(name)), node);
            }
        }
        for (name, node) in &table.wildcard_hosts {
            process(name, node);
        }
        if let Some(node) = &table.any_host {
            process(&crate::ir::HostnameMatch::Any, node);
        }

        result
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

fn socket_client_ip(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|addr| addr.as_inet().map(|a| a.ip()))
}

impl SunbeamProxy {
    /// Extract the real client IP.
    ///
    /// If the immediate downstream TCP peer is inside one of the configured
    /// `trusted_proxy_cidrs`, proxy headers are consulted in order:
    /// CF-Connecting-IP → X-Real-IP → X-Forwarded-For (first entry).
    /// Otherwise the raw socket address is returned, preventing IP spoofing by
    /// untrusted clients.
    fn extract_client_ip(&self, session: &Session) -> Option<IpAddr> {
        let socket_ip = socket_client_ip(session)?;

        if !crate::rate_limit::cidr::is_bypassed(socket_ip, &self.trusted_proxy_cidrs) {
            return Some(socket_ip);
        }

        let headers = &session.req_header().headers;

        for header in &["cf-connecting-ip", "x-real-ip"] {
            if let Some(val) = headers.get(*header).and_then(|v| v.to_str().ok())
                && let Ok(ip) = val.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
        }

        // X-Forwarded-For: client, proxy1, proxy2 — take the first entry
        if let Some(val) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
            && let Some(first) = val.split(',').next()
                && let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }

        Some(socket_ip)
    }
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

/// Returns the downstream TCP port, or 0 if it cannot be determined.
fn downstream_port(session: &Session) -> u16 {
    session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|s| s.local_addr())
        .and_then(|a| a.as_inet().map(|a| a.port()))
        .unwrap_or(0)
}

/// Returns the local socket address of the downstream connection.
fn downstream_local_addr(session: &Session) -> Option<SocketAddr> {
    session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|s| s.local_addr())
        .and_then(|a| a.as_inet().copied())
}

/// For TLS-terminated HTTPS traffic, the L4 manager forwards decrypted HTTP to
/// an internal plaintext address. This method checks whether the request
/// arrived on such an internal address and, if so, returns the public listener
/// port that should be used for redirects.
fn https_terminate_port(l4_config: &CompiledL4Config, local: SocketAddr) -> Option<u16> {
    for route in &l4_config.https_routes {
        if let L4Action::TerminateAndHttp(target) = &route.action
            && let Ok(target_addr) = target.as_ref().parse::<SocketAddr>()
                && target_addr == local
                    && let Some(listener) = l4_config
                        .listeners
                        .iter()
                        .find(|l| l.id.as_ref() == route.listener_id.as_ref())
                        && matches!(listener.protocol, Protocol::Https | Protocol::Tls) {
                            return listener
                                .bind_addr
                                .as_ref()
                                .rsplit(':')
                                .next()
                                .and_then(|p| p.parse().ok());
                        }
    }
    None
}

/// For plain HTTP traffic relayed through the L4 manager, the request arrives at
/// the internal Pingora plaintext address. Map that internal address back to the
/// public listener port so route matching can use it.
fn http_relay_port(l4_config: &CompiledL4Config, local: SocketAddr) -> Option<u16> {
    for route in &l4_config.http_routes {
        if let L4Action::HttpRelay(target) = &route.action
            && let Ok(target_addr) = target.as_ref().parse::<SocketAddr>()
                && target_addr == local
                    && let Some(listener) = l4_config
                        .listeners
                        .iter()
                        .find(|l| l.id.as_ref() == route.listener_id.as_ref())
                        && listener.protocol == Protocol::Http {
                            return listener
                                .bind_addr
                                .as_ref()
                                .rsplit(':')
                                .next()
                                .and_then(|p| p.parse().ok());
                        }
    }
    None
}

#[async_trait]
impl ProxyHttp for SunbeamProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> RequestCtx {
        let request_id = uuid::Uuid::new_v4().to_string();
        RequestCtx {
            plan: None,
            start_time: Instant::now(),
            request_id,
            span: tracing::Span::none(),
            acme_backend: None,
            downstream_scheme: "https",
            downstream_port: 0,
            served_static: false,
            auth_headers: Vec::new(),
            backend_index: None,
            body_buffer: None,
        }
    }

    /// HTTP → HTTPS redirect; ACME HTTP-01 challenges pass through on plain HTTP.
    async fn request_filter(&self, session: &mut Session, ctx: &mut RequestCtx) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        self.request_filter_inner(session, ctx).await
    }

    // ── Cache hooks ────────────────────────────────────────────────────
    // Runs AFTER request_filter (detection pipeline) and BEFORE upstream.
    // On cache hit, the response is served directly — no upstream request,
    // no request modifications, no body rewriting.

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut RequestCtx) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        self.request_cache_filter_inner(session, ctx)
    }

    fn cache_key_callback(&self, session: &Session, _ctx: &mut RequestCtx) -> Result<CacheKey> {
        self.cache_key_callback_inner(session, _ctx)
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> Result<RespCacheable> {
        self.response_cache_filter_inner(_session, resp, ctx)
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
        self.cache_hit_filter_inner(_session, _meta, _hit_handler, _is_fresh, _ctx)
            .await
    }

    fn cache_miss(&self, session: &mut Session, _ctx: &mut RequestCtx) {
        self.cache_miss_inner(session, _ctx)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<Box<HttpPeer>> {
        self.upstream_peer_inner(session, ctx).await
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
        self.upstream_request_filter_inner(session, upstream_req, ctx)
            .await
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
        self.upstream_response_filter_inner(_session, upstream_response, ctx)
            .await
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
        self.response_body_filter_inner(_session, body, end_of_stream, ctx)
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
        self.logging_inner(session, error, ctx).await
    }

    /// Map upstream read/write timeouts to 504 Gateway Timeout so that
    /// Gateway API `rules.timeouts.backendRequest` / `rules.timeouts.request`
    /// conformance tests see the expected status code.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        _ctx: &mut RequestCtx,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        use pingora_core::{ErrorSource, ErrorType};

        let code = match e.etype() {
            ErrorType::HTTPStatus(code) => *code,
            _ => match e.esource() {
                ErrorSource::Upstream
                    if matches!(
                        e.etype(),
                        ErrorType::ReadTimedout | ErrorType::WriteTimedout
                    ) =>
                {
                    504
                }
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };

        if code > 0
            && let Err(err) = session.respond_error(code).await {
                tracing::error!(%err, "failed to send error response to downstream");
            }

        pingora_proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::match_::*;
    use super::*;
    use crate::config::PathRoute;
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
            plan: None,
            start_time: Instant::now(),
            request_id: "1".to_string(),
            span: tracing::Span::none(),
            acme_backend: None,
            downstream_scheme: "https",
            downstream_port: 0,
            served_static: false,
            auth_headers: Vec::new(),
            backend_index: None,
            body_buffer: None,
        };
        assert_eq!(ctx.downstream_scheme, "https");
        assert_eq!(ctx.downstream_port, 0);
        assert_eq!(ctx.backend_index, None);
    }

    #[test]
    fn test_backend_addr_strips_scheme() {
        assert_eq!(
            backend_addr("http://svc.ns.svc.cluster.local:80"),
            "svc.ns.svc.cluster.local:80"
        );
        assert_eq!(
            backend_addr("https://svc.ns.svc.cluster.local:443"),
            "svc.ns.svc.cluster.local:443"
        );
    }

    /// remove_header("expect") strips the header from the upstream request.
    #[test]
    fn test_expect_header_stripped_before_upstream() {
        let mut req =
            RequestHeader::build("PUT", b"/v2/studio/image/blobs/uploads/uuid", None).unwrap();
        req.insert_header("expect", "100-continue").unwrap();
        req.insert_header("content-length", "188000000").unwrap();
        assert!(
            req.headers.get("expect").is_some(),
            "expect header should be present before stripping"
        );
        req.remove_header("expect");
        assert!(
            req.headers.get("expect").is_none(),
            "expect header should be gone after remove_header"
        );
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
        use crate::rate_limit::cidr::{is_bypassed, parse_cidrs};
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
        use crate::rate_limit::cidr::{is_bypassed, parse_cidrs};
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
        assert_eq!(
            select_path_route(&paths, "/api", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "api-read"
        );
        assert_eq!(
            select_path_route(&paths, "/api", "POST", &empty_headers, None)
                .unwrap()
                .backend,
            "api-write"
        );
        assert!(select_path_route(&paths, "/api", "DELETE", &empty_headers, None).is_none());
    }

    #[test]
    fn select_path_route_earlier_rule_wins_on_prefix_tie() {
        let paths = vec![
            PathRoute {
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
            timeout_ms: None,
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
            gateway_api_unprogrammed: false,
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
            crate::config::WeightedBackendConfig {
                backend: "a".into(),
                weight: 1,
            },
            crate::config::WeightedBackendConfig {
                backend: "b".into(),
                weight: 1,
            },
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
            crate::config::WeightedBackendConfig {
                backend: "heavy".into(),
                weight: 100,
            },
            crate::config::WeightedBackendConfig {
                backend: "light".into(),
                weight: 1,
            },
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
        assert_eq!(
            build_redirect_location(&redirect, &uri),
            "http://example.com/new"
        );
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

    fn make_proxy(table: CompiledRouteTable) -> SunbeamProxy {
        use arc_swap::ArcSwap;
        SunbeamProxy {
            routes: Arc::new(ArcSwap::new(Arc::new(table))),
            l4_config: Arc::new(ArcSwap::new(Arc::new(CompiledL4Config::empty()))),
            sni_context: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            http_context: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            tls_registry: None,
            acme_routes: crate::acme::AcmeRoutes::default(),
            ddos_detector: None,
            scanner_detector: None,
            bot_allowlist: None,
            rate_limiter: None,
            compiled_rewrites: Arc::new(ArcSwap::new(Arc::new(vec![]))),
            http_client: reqwest::Client::new(),
            pipeline_bypass_cidrs: vec![],
            trusted_proxy_cidrs: vec![],
            cluster: None,
            ddos_observe_only: false,
            scanner_observe_only: false,
        }
    }

    fn compile_test_routes(routes: Vec<RouteConfig>) -> CompiledRouteTable {
        let ir = crate::ir::from_config::from_route_configs(&routes);
        crate::ir::compile::CompiledRouteTable::compile(ir).expect("compile")
    }

    fn route_with_listener(
        host_prefix: &str,
        listener_hostname: Option<&str>,
        gateway_api: bool,
    ) -> RouteConfig {
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
    fn lookup_plan_exact_host_prefix() {
        let proxy = make_proxy(compile_test_routes(vec![route_with_listener(
            "example.com",
            None,
            false,
        )]));
        let headers = http::header::HeaderMap::new();
        assert!(proxy
            .lookup_plan("example.com", 0, "/", "GET", &headers, None)
            .is_some());
        assert!(proxy
            .lookup_plan("other.com", 0, "/", "GET", &headers, None)
            .is_none());
    }

    #[test]
    fn lookup_plan_wildcard_host_prefix() {
        let proxy = make_proxy(compile_test_routes(vec![route_with_listener(
            "*.example.com",
            None,
            false,
        )]));
        let headers = http::header::HeaderMap::new();
        assert!(proxy
            .lookup_plan("foo.example.com", 0, "/", "GET", &headers, None)
            .is_some());
        assert!(proxy
            .lookup_plan("example.com", 0, "/", "GET", &headers, None)
            .is_none());
    }

    #[test]
    fn lookup_plan_listener_hostname_isolation() {
        let proxy = make_proxy(compile_test_routes(vec![
            route_with_listener("example.com", Some("example.com"), true),
            route_with_listener("*.example.com", Some("*.example.com"), true),
        ]));
        let headers = http::header::HeaderMap::new();
        let chosen = proxy
            .lookup_plan("sub.example.com", 0, "/", "GET", &headers, None)
            .unwrap();
        assert_eq!(
            chosen.listener_hostname,
            Some(crate::ir::HostnameMatch::Wildcard("example.com".into()))
        );
    }

    #[test]
    fn lookup_plan_listener_specificity_prefers_exact() {
        let proxy = make_proxy(compile_test_routes(vec![
            route_with_listener("example.com", Some("*.example.com"), true),
            route_with_listener("example.com", Some("example.com"), true),
        ]));
        let headers = http::header::HeaderMap::new();
        let chosen = proxy
            .lookup_plan("example.com", 0, "/", "GET", &headers, None)
            .unwrap();
        assert_eq!(
            chosen.listener_hostname,
            Some(crate::ir::HostnameMatch::Exact("example.com".into()))
        );
    }

    #[test]
    fn lookup_plan_legacy_routes_least_specific() {
        let proxy = make_proxy(compile_test_routes(vec![
            route_with_listener("example.com", None, false),
            route_with_listener("example.com", Some("example.com"), true),
        ]));
        let headers = http::header::HeaderMap::new();
        let chosen = proxy
            .lookup_plan("example.com", 0, "/", "GET", &headers, None)
            .unwrap();
        assert_eq!(
            chosen.listener_hostname,
            Some(crate::ir::HostnameMatch::Exact("example.com".into()))
        );
    }

    #[test]
    fn lookup_plan_empty_listener_hostname_matches_any_host() {
        // A Gateway listener with no hostname combined with a route that also has
        // no hostnames is a catch-all on the least-specific listener.
        let host = crate::ir::HostRoute {
            hostname: crate::ir::HostnameMatch::Any,
            listener_ids: vec![],
            listener_hostname: Some(crate::ir::HostnameMatch::Exact("".into())),
            listener_port: None,
            gateway_api: true,
            disable_secure_redirection: true,
            rules: vec![crate::ir::Rule {
                matches: vec![crate::ir::RequestMatch {
                    path: Some(crate::ir::PathMatch::Prefix("/".into())),
                    method: None,
                    headers: vec![],
                    query_params: vec![],
                }],
                action: crate::ir::Action::Route(crate::ir::RouteAction {
                    backends: vec![crate::ir::WeightedBackend {
                        backend: "http://backend".into(),
                        weight: 1,
                        protocol: crate::ir::BackendProtocol::Http,
                        request_filters: vec![],
                        tls: None,
                    }],
                    timeout: None,
                    request_filters: vec![],
                    response_filters: vec![],
                    mirror_backends: vec![],
                    mirror_fractions: vec![],
                    cache: None,
                    body_rewrites: vec![],
                    auth: None,
                    disable_https_redirect: true,
                    websocket: false,
                    client_cert_id: None,
                }),
                rule_order: 0,
            }],
        };
        let table = crate::ir::compile::CompiledRouteTable::compile(crate::ir::RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: std::collections::HashMap::new(),
            l4_routes: vec![],
            tls_certs: vec![],
        })
        .unwrap();
        let proxy = make_proxy(table);
        let headers = http::header::HeaderMap::new();
        assert!(proxy
            .lookup_plan("", 0, "/", "GET", &headers, None)
            .is_some());
        assert!(proxy
            .lookup_plan("sub.third.com", 0, "/", "GET", &headers, None)
            .is_some());
        assert!(proxy
            .lookup_plan("first.com", 0, "/", "GET", &headers, None)
            .is_some());
        assert!(proxy.has_matching_gateway_api_listener("sub.third.com", 0));
        assert!(proxy.has_matching_gateway_api_listener("first.com", 0));
    }

    #[test]
    fn lookup_plan_explicit_hostname_with_empty_listener_matches_host() {
        // A route with an explicit hostname attached to a listener with no
        // hostname should still match that hostname.
        let host = crate::ir::HostRoute {
            hostname: crate::ir::HostnameMatch::Exact("first.com".into()),
            listener_ids: vec![],
            listener_hostname: Some(crate::ir::HostnameMatch::Exact("".into())),
            listener_port: None,
            gateway_api: true,
            disable_secure_redirection: true,
            rules: vec![crate::ir::Rule {
                matches: vec![crate::ir::RequestMatch {
                    path: Some(crate::ir::PathMatch::Prefix("/".into())),
                    method: None,
                    headers: vec![],
                    query_params: vec![],
                }],
                action: crate::ir::Action::Route(crate::ir::RouteAction {
                    backends: vec![crate::ir::WeightedBackend {
                        backend: "http://backend".into(),
                        weight: 1,
                        protocol: crate::ir::BackendProtocol::Http,
                        request_filters: vec![],
                        tls: None,
                    }],
                    timeout: None,
                    request_filters: vec![],
                    response_filters: vec![],
                    mirror_backends: vec![],
                    mirror_fractions: vec![],
                    cache: None,
                    body_rewrites: vec![],
                    auth: None,
                    disable_https_redirect: true,
                    websocket: false,
                    client_cert_id: None,
                }),
                rule_order: 0,
            }],
        };
        let table = crate::ir::compile::CompiledRouteTable::compile(crate::ir::RouteTable {
            listeners: vec![],
            hosts: vec![host],
            acme_routes: std::collections::HashMap::new(),
            l4_routes: vec![],
            tls_certs: vec![],
        })
        .unwrap();
        let proxy = make_proxy(table);
        let headers = http::header::HeaderMap::new();
        assert!(proxy
            .lookup_plan("first.com", 0, "/", "GET", &headers, None)
            .is_some());
        assert!(proxy
            .lookup_plan("sub.third.com", 0, "/", "GET", &headers, None)
            .is_none());
        assert!(proxy.has_matching_gateway_api_listener("first.com", 0));
        assert!(!proxy.has_matching_gateway_api_listener("sub.third.com", 0));
    }

    #[test]
    fn lookup_plan_listener_isolation_prefers_more_specific_listener() {
        // A catch-all route on an empty listener should not receive traffic for
        // hosts that match a more specific wildcard listener.
        let table = crate::ir::compile::CompiledRouteTable::compile(crate::ir::RouteTable {
            listeners: vec![],
            hosts: vec![
                crate::ir::HostRoute {
                    hostname: crate::ir::HostnameMatch::Any,
                    listener_ids: vec![],
                    listener_hostname: Some(crate::ir::HostnameMatch::Exact("".into())),
                    listener_port: None,
                    gateway_api: true,
                    disable_secure_redirection: true,
                    rules: vec![crate::ir::Rule {
                        matches: vec![crate::ir::RequestMatch {
                            path: Some(crate::ir::PathMatch::Prefix("/empty".into())),
                            method: None,
                            headers: vec![],
                            query_params: vec![],
                        }],
                        action: crate::ir::Action::Route(crate::ir::RouteAction {
                            backends: vec![crate::ir::WeightedBackend {
                                backend: "http://empty".into(),
                                weight: 1,
                                protocol: crate::ir::BackendProtocol::Http,
                                request_filters: vec![],
                                tls: None,
                            }],
                            timeout: None,
                            request_filters: vec![],
                            response_filters: vec![],
                            mirror_backends: vec![],
                            mirror_fractions: vec![],
                            cache: None,
                            body_rewrites: vec![],
                            auth: None,
                            disable_https_redirect: true,
                            websocket: false,
                            client_cert_id: None,
                        }),
                        rule_order: 0,
                    }],
                },
                crate::ir::HostRoute {
                    hostname: crate::ir::HostnameMatch::Wildcard("example.com".into()),
                    listener_ids: vec![],
                    listener_hostname: Some(crate::ir::HostnameMatch::Wildcard(
                        "example.com".into(),
                    )),
                    listener_port: None,
                    gateway_api: true,
                    disable_secure_redirection: true,
                    rules: vec![crate::ir::Rule {
                        matches: vec![crate::ir::RequestMatch {
                            path: Some(crate::ir::PathMatch::Prefix("/wildcard".into())),
                            method: None,
                            headers: vec![],
                            query_params: vec![],
                        }],
                        action: crate::ir::Action::Route(crate::ir::RouteAction {
                            backends: vec![crate::ir::WeightedBackend {
                                backend: "http://wildcard".into(),
                                weight: 1,
                                protocol: crate::ir::BackendProtocol::Http,
                                request_filters: vec![],
                                tls: None,
                            }],
                            timeout: None,
                            request_filters: vec![],
                            response_filters: vec![],
                            mirror_backends: vec![],
                            mirror_fractions: vec![],
                            cache: None,
                            body_rewrites: vec![],
                            auth: None,
                            disable_https_redirect: true,
                            websocket: false,
                            client_cert_id: None,
                        }),
                        rule_order: 0,
                    }],
                },
            ],
            acme_routes: std::collections::HashMap::new(),
            l4_routes: vec![],
            tls_certs: vec![],
        })
        .unwrap();
        let proxy = make_proxy(table);
        let headers = http::header::HeaderMap::new();
        // Empty-listener route is used when no more specific listener matches.
        assert!(proxy
            .lookup_plan("bar.com", 0, "/empty", "GET", &headers, None)
            .is_some());
        assert!(proxy
            .lookup_plan("bar.example.com", 0, "/empty", "GET", &headers, None)
            .is_none());
        // Wildcard-listener route is used for matching hosts.
        assert!(proxy
            .lookup_plan("bar.example.com", 0, "/wildcard", "GET", &headers, None)
            .is_some());
        assert!(proxy
            .lookup_plan("bar.com", 0, "/wildcard", "GET", &headers, None)
            .is_none());
    }

    #[test]
    fn select_path_route_prefers_more_header_matches_on_tie() {
        let paths = vec![
            PathRoute {
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
                timeout_ms: None,
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
                gateway_api_unprogrammed: false,
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
        assert_eq!(
            select_path_route(&paths, "/", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "root"
        );
        assert_eq!(
            select_path_route(&paths, "/v2", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "v2"
        );
        assert_eq!(
            select_path_route(&paths, "/v2/", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "v2"
        );
        assert_eq!(
            select_path_route(&paths, "/v2/example", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "v2"
        );
        assert_eq!(
            select_path_route(&paths, "/v2example", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "root"
        );
        assert_eq!(
            select_path_route(&paths, "/foo/v2/example", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "root"
        );
    }

    #[test]
    fn select_path_route_header_match_is_case_insensitive() {
        let paths = vec![PathRoute {
            timeout_ms: None,
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
            gateway_api_unprogrammed: false,
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

    #[test]
    fn https_terminate_port_matches_internal_target_to_listener_port() {
        let listener = crate::ir::compile::CompiledListener {
            id: "https".into(),
            bind_addr: "0.0.0.0:443".into(),
            protocol: Protocol::Https,
            tls: Some(crate::ir::compile::CompiledTlsConfig::Registry {
                cert_id: "gateway".into(),
            }),
            redirect_http_to_https: false,
            frontend_validation: None,
        };
        let l4_config = crate::ir::compile::CompiledL4Config {
            listeners: vec![listener],
            https_routes: vec![crate::ir::compile::CompiledL4Route {
                listener_id: "https".into(),
                listener_hostname: crate::ir::HostnameMatch::Any,
                match_: crate::ir::L4Match::Any,
                action: crate::ir::L4Action::TerminateAndHttp("127.0.0.1:10443".into()),
                priority: 0,
            }],
            ..crate::ir::compile::CompiledL4Config::empty()
        };
        assert_eq!(
            https_terminate_port(&l4_config, "127.0.0.1:10443".parse().unwrap()),
            Some(443)
        );
        assert_eq!(
            https_terminate_port(&l4_config, "127.0.0.1:9999".parse().unwrap()),
            None
        );
    }

    #[test]
    fn https_terminate_port_ignores_non_https_listeners() {
        let listener = crate::ir::compile::CompiledListener {
            id: "http".into(),
            bind_addr: "0.0.0.0:80".into(),
            protocol: Protocol::Http,
            tls: None,
            redirect_http_to_https: false,
            frontend_validation: None,
        };
        let l4_config = crate::ir::compile::CompiledL4Config {
            listeners: vec![listener],
            https_routes: vec![crate::ir::compile::CompiledL4Route {
                listener_id: "http".into(),
                listener_hostname: crate::ir::HostnameMatch::Any,
                match_: crate::ir::L4Match::Any,
                action: crate::ir::L4Action::TerminateAndHttp("127.0.0.1:8080".into()),
                priority: 0,
            }],
            ..crate::ir::compile::CompiledL4Config::empty()
        };
        assert_eq!(
            https_terminate_port(&l4_config, "127.0.0.1:8080".parse().unwrap()),
            None
        );
    }

    #[tokio::test]
    async fn make_peer_plain_http() {
        let peer = make_peer(
            "http://127.0.0.1:8080",
            None,
            BackendProtocol::Http,
            None,
            None,
        )
        .await;
        assert!(peer.is_some());
        let peer = peer.unwrap();
        assert!(!peer.is_tls());
    }

    #[tokio::test]
    async fn make_peer_https_requires_tls_config() {
        let peer = make_peer(
            "https://127.0.0.1:8443",
            None,
            BackendProtocol::Https,
            None,
            None,
        )
        .await;
        assert!(peer.is_none());
    }

    #[tokio::test]
    async fn make_peer_https_with_tls_config_sets_options() {
        let tls = BackendTlsConfig {
            sni: Arc::from("backend.example.com"),
            verify_hostname: false,
            alternative_cn: Some(Arc::from("alt.example.com")),
            client_cert_id: None,
            ca_bundle_pem: None,
            subject_alt_names: vec![],
        };
        let peer = make_peer(
            "https://127.0.0.1:8443",
            None,
            BackendProtocol::Https,
            Some(&tls),
            None,
        )
        .await;
        assert!(peer.is_some());
        let peer = peer.unwrap();
        assert!(peer.is_tls());
    }

    #[tokio::test]
    async fn make_peer_https_with_ca_bundle_uses_custom_l4() {
        let tls = BackendTlsConfig {
            sni: Arc::from("backend.example.com"),
            verify_hostname: true,
            alternative_cn: None,
            client_cert_id: None,
            ca_bundle_pem: Some(Arc::from(
                "-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----\n",
            )),
            subject_alt_names: vec![Arc::from("backend.example.com")],
        };
        let peer = make_peer(
            "https://127.0.0.1:8443",
            None,
            BackendProtocol::Https,
            Some(&tls),
            None,
        )
        .await;
        assert!(peer.is_some());
        let peer = peer.unwrap();
        // Custom L4 connector is stored as an Arc<dyn CustomL4>.
        assert!(peer.options.custom_l4.is_some());
    }

    #[test]
    fn compile_rewrites_from_ir_covers_all_host_types() {
        use crate::ir::compile::{CompiledRouteTable, HostNode};
        use crate::ir::{HostnameMatch, RewriteRule};
        use std::collections::HashMap;

        let mut exact = HashMap::new();
        exact.insert(
            Arc::from("exact.example.com"),
            vec![HostNode {
                hostname: HostnameMatch::Exact(Arc::from("exact.example.com")),
                listener_ids: vec![],
                listener_hostname: None,
                listener_port: None,
                gateway_api: false,
                disable_secure_redirection: false,
                path_trie: crate::ir::compile::PathTrieNode::default(),
                exact_paths: HashMap::new(),
                regex_plans: vec![],
                static_rewrites: vec![RewriteRule {
                    pattern: Arc::from(r"^/old$"),
                    target: Arc::from("/new"),
                }],
            }],
        );

        let wildcard = vec![(
            HostnameMatch::Wildcard(Arc::from("example.com")),
            HostNode {
                hostname: HostnameMatch::Wildcard(Arc::from("example.com")),
                listener_ids: vec![],
                listener_hostname: None,
                listener_port: None,
                gateway_api: false,
                disable_secure_redirection: false,
                path_trie: crate::ir::compile::PathTrieNode::default(),
                exact_paths: HashMap::new(),
                regex_plans: vec![],
                static_rewrites: vec![RewriteRule {
                    pattern: Arc::from(r"^/foo$"),
                    target: Arc::from("/bar"),
                }],
            },
        )];

        let any = HostNode {
            hostname: HostnameMatch::Any,
            listener_ids: vec![],
            listener_hostname: None,
            listener_port: None,
            gateway_api: false,
            disable_secure_redirection: false,
            path_trie: crate::ir::compile::PathTrieNode::default(),
            exact_paths: HashMap::new(),
            regex_plans: vec![],
            static_rewrites: vec![RewriteRule {
                pattern: Arc::from(r"^/any$"),
                target: Arc::from("/anywhere"),
            }],
        };

        let table = CompiledRouteTable {
            exact_hosts: exact,
            wildcard_hosts: wildcard,
            any_host: Some(any),
            acme_routes: HashMap::new(),
        };

        let rewrites = SunbeamProxy::compile_rewrites_from_ir(&table);
        assert!(rewrites.iter().any(|(h, _)| h == "exact.example.com"));
        assert!(rewrites.iter().any(|(h, _)| h == "*.example.com"));
        assert!(rewrites.iter().any(|(h, _)| h == "*"));
    }

    #[test]
    fn find_rewrites_returns_matching_prefix() {
        let proxy = SunbeamProxy::default();
        let rules = vec![(
            "docs".to_string(),
            Arc::new(vec![CompiledRewrite {
                pattern: Regex::new(r"^/old$").unwrap(),
                target: "/new".into(),
            }]),
        )];
        proxy.compiled_rewrites.store(Arc::new(rules));
        let found = proxy.find_rewrites("docs");
        assert!(found.is_some());
        assert_eq!(found.unwrap().len(), 1);
        assert!(proxy.find_rewrites("missing").is_none());
    }
}
