// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use crate::acme::AcmeRoutes;
use crate::cluster::ClusterHandle;
use crate::config::RouteConfig;
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
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

/// A compiled rewrite rule (regex compiled once at startup).
pub struct CompiledRewrite {
    pub pattern: Regex,
    pub target: String,
}

pub struct SunbeamProxy {
    pub routes: Vec<RouteConfig>,
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
    /// Compiled rewrite rules per route (indexed by host_prefix).
    pub compiled_rewrites: Vec<(String, Vec<CompiledRewrite>)>,
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

pub struct RequestCtx {
    pub route: Option<RouteConfig>,
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
    /// Whether response body rewriting is needed for this request.
    pub body_rewrite_rules: Vec<(String, String)>,
    /// Buffered response body for body rewriting.
    pub body_buffer: Option<Vec<u8>>,
}

impl SunbeamProxy {
    fn find_route(&self, prefix: &str) -> Option<&RouteConfig> {
        self.routes.iter().find(|r| r.host_prefix == prefix)
    }

    fn find_rewrites(&self, prefix: &str) -> Option<&[CompiledRewrite]> {
        self.compiled_rewrites
            .iter()
            .find(|(p, _)| p == prefix)
            .map(|(_, rules)| rules.as_slice())
    }

    /// Compile all rewrite rules from routes at startup.
    pub fn compile_rewrites(routes: &[RouteConfig]) -> Vec<(String, Vec<CompiledRewrite>)> {
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
                (r.host_prefix.clone(), compiled)
            })
            .collect()
    }
}

fn extract_host(session: &Session) -> String {
    session
        .req_header()
        .headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
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
                .find_route(prefix)
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
        let route = match self.find_route(prefix) {
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
                    for rw in rewrites {
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
            let path_route = route
                .paths
                .iter()
                .filter(|p| req_path.starts_with(p.prefix.as_str()))
                .max_by_key(|p| p.prefix.len());

            if let Some(pr) = path_route {
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

                    match auth_req.send().await {
                        Ok(resp) if resp.status().is_success() => {
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
                            tracing::info!(
                                auth_url,
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
        let req = session.req_header();
        let host = req
            .headers
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
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
            return Ok(Box::new(HttpPeer::new(
                backend_addr(backend),
                false,
                String::new(),
            )));
        }

        let host = extract_host(session);
        let prefix = host.split('.').next().unwrap_or("");
        let route = self
            .find_route(prefix)
            .expect("route already validated in request_filter");

        let path = session.req_header().uri.path().to_string();

        // Check path sub-routes (longest matching prefix wins).
        let path_route = route
            .paths
            .iter()
            .filter(|p| path.starts_with(p.prefix.as_str()))
            .max_by_key(|p| p.prefix.len());

        if let Some(pr) = path_route {
            if pr.strip_prefix {
                ctx.strip_prefix = Some(pr.prefix.clone());
            }
            if ctx.upstream_path_prefix.is_none() {
                ctx.upstream_path_prefix = pr.upstream_path_prefix.clone();
            }
            ctx.route = Some(crate::config::RouteConfig {
                host_prefix: route.host_prefix.clone(),
                backend: pr.backend.clone(),
                websocket: pr.websocket || route.websocket,
                disable_secure_redirection: route.disable_secure_redirection,
                paths: vec![],
                static_root: None,
                fallback: None,
                rewrites: vec![],
                body_rewrites: vec![],
                response_headers: vec![],
                cache: None,
            });
            return Ok(Box::new(HttpPeer::new(
                backend_addr(&pr.backend),
                false,
                String::new(),
            )));
        }

        ctx.route = Some(route.clone());
        Ok(Box::new(HttpPeer::new(
            backend_addr(&route.backend),
            false,
            String::new(),
        )))
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

        // Strip Expect: 100-continue.
        upstream_req.remove_header("expect");

        // Strip path prefix before forwarding (e.g. /kratos → /).
        if let Some(prefix) = &ctx.strip_prefix {
            let old_uri = upstream_req.uri.clone();
            let old_path = old_uri.path();
            if let Some(stripped) = old_path.strip_prefix(prefix.as_str()) {
                let new_path = if stripped.is_empty() { "/" } else { stripped };

                // Prepend upstream_path_prefix if configured.
                let new_path = if let Some(up_prefix) = &ctx.upstream_path_prefix {
                    let trimmed = new_path.strip_prefix('/').unwrap_or(new_path);
                    format!("{up_prefix}{trimmed}")
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
            let new_path = format!("{up_prefix}{trimmed}");
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

        // Add route-level response headers (owned Strings for Pingora's IntoCaseHeaderName).
        if let Some(route) = &ctx.route {
            for hdr in &route.response_headers {
                let _ = upstream_response.insert_header(hdr.name.clone(), hdr.value.clone());
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
            cache: None,
        }];
        let compiled = SunbeamProxy::compile_rewrites(&routes);
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].1.len(), 1);
        assert!(compiled[0].1[0].pattern.is_match("/docs/abc-def/"));
    }
}
