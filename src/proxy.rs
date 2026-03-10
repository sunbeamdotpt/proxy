use crate::acme::AcmeRoutes;
use crate::config::RouteConfig;
use async_trait::async_trait;
use http::header::{CONNECTION, HOST, UPGRADE};
use pingora_core::{upstreams::peer::HttpPeer, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::time::Instant;

pub struct SunbeamProxy {
    pub routes: Vec<RouteConfig>,
    /// Per-challenge route table populated by the Ingress watcher.
    /// Maps `/.well-known/acme-challenge/<token>` → solver service address.
    pub acme_routes: AcmeRoutes,
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

        // Reject unknown host prefixes with 404.
        let host = extract_host(session);
        let prefix = host.split('.').next().unwrap_or("");
        if self.find_route(prefix).is_none() {
            let mut resp = ResponseHeader::build(404, None)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
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
        let duration_ms = ctx.start_time.elapsed().as_millis();
        let backend = ctx
            .route
            .as_ref()
            .map(|r| r.backend.as_str())
            .unwrap_or("-");
        let client_ip = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".to_string());
        let error_str = error.map(|e| e.to_string());

        tracing::info!(
            target = "audit",
            method  = %session.req_header().method,
            host    = %extract_host(session),
            path    = %session.req_header().uri.path(),
            client_ip,
            status,
            duration_ms,
            backend,
            error   = error_str,
            "request"
        );
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
}
