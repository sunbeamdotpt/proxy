use crate::acme::AcmeRoutes;
use crate::config::RouteConfig;
use crate::ddos::detector::DDoSDetector;
use crate::ddos::model::DDoSAction;
use crate::rate_limit::key;
use crate::rate_limit::limiter::{RateLimitResult, RateLimiter};
use crate::scanner::allowlist::BotAllowlist;
use crate::scanner::detector::ScannerDetector;
use crate::scanner::model::ScannerAction;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::header::{CONNECTION, EXPECT, HOST, UPGRADE};
use pingora_core::{upstreams::peer::HttpPeer, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

pub struct SunbeamProxy {
    pub routes: Vec<RouteConfig>,
    /// Per-challenge route table populated by the Ingress watcher.
    /// Maps `/.well-known/acme-challenge/<token>` → solver service address.
    pub acme_routes: AcmeRoutes,
    /// Optional KNN-based DDoS detector.
    pub ddos_detector: Option<Arc<DDoSDetector>>,
    /// Optional per-request scanner detector (hot-reloadable via ArcSwap).
    pub scanner_detector: Option<Arc<ArcSwap<ScannerDetector>>>,
    /// Optional verified-bot allowlist (bypasses scanner for known crawlers/agents).
    pub bot_allowlist: Option<Arc<BotAllowlist>>,
    /// Optional per-identity rate limiter.
    pub rate_limiter: Option<Arc<RateLimiter>>,
}

pub struct RequestCtx {
    pub route: Option<RouteConfig>,
    pub start_time: Instant,
    /// Resolved solver backend address for this ACME challenge, if applicable.
    pub acme_backend: Option<String>,
    /// Path prefix to strip before forwarding to the upstream (e.g. "/kratos").
    pub strip_prefix: Option<String>,
    /// Original downstream scheme ("http" or "https"), captured in request_filter.
    pub downstream_scheme: &'static str,
}

impl SunbeamProxy {
    fn find_route(&self, prefix: &str) -> Option<&RouteConfig> {
        self.routes.iter().find(|r| r.host_prefix == prefix)
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
fn backend_addr(backend: &str) -> &str {
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
        RequestCtx {
            route: None,
            start_time: Instant::now(),
            acme_backend: None,
            downstream_scheme: "https",
            strip_prefix: None,
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
            let host = extract_host(session);
            let prefix = host.split('.').next().unwrap_or("");

            // Routes that explicitly opt out of HTTPS enforcement pass through.
            // All other requests — including unknown hosts — are redirected.
            // This is as close to an L4 redirect as HTTP allows: the upstream is
            // never contacted; the 301 is written directly to the downstream socket.
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

                if matches!(ddos_action, DDoSAction::Block) {
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
            // CIDR rules are instant; DNS-verified IPs are cached after
            // background reverse+forward lookup.
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

            if decision == "block" {
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
                    has_cookies = cookie.is_some(),
                    "pipeline"
                );

                if let RateLimitResult::Reject { retry_after } = rl_result {
                    let mut resp = ResponseHeader::build(429, None)?;
                    resp.insert_header("Retry-After", retry_after.to_string())?;
                    resp.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        // Reject unknown host prefixes with 404.
        let host = extract_host(session);
        let prefix = host.split('.').next().unwrap_or("");
        if self.find_route(prefix).is_none() {
            let mut resp = ResponseHeader::build(404, None)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        }

        // Handle Expect: 100-continue before connecting to upstream.
        //
        // Docker's OCI distribution protocol sends Expect: 100-continue for
        // large layer blob uploads (typically > 5 MB).  Without this, Pingora
        // forwards the header to the upstream (e.g. Gitea), the upstream
        // responds with 100 Continue, and Pingora must then proxy that
        // informational response back to the client.  Pingora's handling of
        // upstream informational responses is unreliable and can cause the
        // upload to fail with a spurious 400 for the client.
        //
        // By responding with 100 Continue here — before upstream_peer is
        // even called — we unblock the client immediately.  The Expect header
        // is stripped in upstream_request_filter so the upstream never sends
        // its own 100 Continue.
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
            ctx.route = Some(crate::config::RouteConfig {
                host_prefix: route.host_prefix.clone(),
                backend: pr.backend.clone(),
                websocket: pr.websocket || route.websocket,
                disable_secure_redirection: route.disable_secure_redirection,
                paths: vec![],
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

    /// Copy WebSocket upgrade headers and apply path prefix stripping.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_req: &mut RequestHeader,
        ctx: &mut RequestCtx,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Inform backends of the original downstream scheme so they can construct
        // correct absolute URLs (e.g. OIDC redirect_uri, CSRF checks).
        // Must use insert_header (not headers.insert) so that both base.headers
        // and the CaseMap are updated together — header_to_h1_wire zips them
        // and silently drops headers only present in base.headers.
        upstream_req
            .insert_header("x-forwarded-proto", ctx.downstream_scheme)
            .map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "failed to insert x-forwarded-proto",
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

        // Strip Expect: 100-continue — the proxy already sent 100 Continue to
        // the downstream client in request_filter, so we must not forward the
        // header to the upstream.  If the upstream also sees Expect it will
        // send its own 100 Continue, which Pingora cannot reliably proxy back
        // (it has already been consumed) and which can corrupt the response.
        upstream_req.remove_header("expect");

        // Strip path prefix before forwarding (e.g. /kratos → /).
        if let Some(prefix) = &ctx.strip_prefix {
            let old_uri = upstream_req.uri.clone();
            let old_path = old_uri.path();
            if let Some(stripped) = old_path.strip_prefix(prefix.as_str()) {
                let new_path = if stripped.is_empty() { "/" } else { stripped };
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
        }

        Ok(())
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
        let status = session
            .response_written()
            .map_or(0, |r| r.status.as_u16());
        let duration_ms = ctx.start_time.elapsed().as_millis() as u64;
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

        tracing::info!(
            target = "audit",
            method  = %session.req_header().method,
            host    = %extract_host(session),
            path    = %session.req_header().uri.path(),
            query,
            client_ip,
            status,
            duration_ms,
            content_length,
            user_agent,
            referer,
            accept_language,
            accept,
            has_cookies,
            cf_country,
            backend,
            error   = error_str,
            "request"
        );

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
            acme_backend: None,
            strip_prefix: None,
            downstream_scheme: "https",
        };
        assert_eq!(ctx.downstream_scheme, "https");
    }

    #[test]
    fn test_backend_addr_strips_scheme() {
        assert_eq!(backend_addr("http://svc.ns.svc.cluster.local:80"), "svc.ns.svc.cluster.local:80");
        assert_eq!(backend_addr("https://svc.ns.svc.cluster.local:443"), "svc.ns.svc.cluster.local:443");
    }

    /// remove_header("expect") strips the header from the upstream request.
    /// This is tested independently of the async proxy logic because
    /// upstream_request_filter requires a live session.
    #[test]
    fn test_expect_header_stripped_before_upstream() {
        let mut req = RequestHeader::build("PUT", b"/v2/studio/image/blobs/uploads/uuid", None).unwrap();
        req.insert_header("expect", "100-continue").unwrap();
        req.insert_header("content-length", "188000000").unwrap();
        assert!(req.headers.get("expect").is_some(), "expect header should be present before stripping");
        req.remove_header("expect");
        assert!(req.headers.get("expect").is_none(), "expect header should be gone after remove_header");
        // Content-Length must survive the strip.
        assert!(req.headers.get("content-length").is_some());
    }
}
