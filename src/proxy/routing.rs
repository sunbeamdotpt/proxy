// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SunbeamProxy {
    pub(crate) async fn upstream_peer_inner(
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

        // request_filter always stores the plan; if it's missing, something drifted.
        let plan = match ctx.plan.as_ref() {
            Some(p) => p,
            None => {
                tracing::warn!("upstream_peer: no plan in context — request_filter drift");
                let mut resp = ResponseHeader::build(404, None)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())));
            }
        };

        // Execute the upstream action selected by the compiler.
        if let Some(ref upstream) = plan.upstream {
            let (backend, backend_idx) = if upstream.backends.is_empty() {
                (String::new(), None)
            } else if upstream.backends.len() == 1 {
                ctx.backend_index = Some(0);
                (upstream.backends[0].backend.to_string(), Some(0))
            } else {
                let idx = pick_weighted_backend_ir_index(&upstream.backends).unwrap_or(0);
                ctx.backend_index = Some(idx);
                (upstream.backends[idx].backend.to_string(), Some(idx))
            };
            let _ = backend_idx;

            // Fire-and-forget mirrors.
            for mirror in &upstream.mirror {
                let mirror_addr = backend_addr(mirror);
                let mirror_path = session
                    .req_header()
                    .uri
                    .path_and_query()
                    .map(|pq| pq.to_string())
                    .unwrap_or_else(|| "/".to_string());
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

            let timeout_secs = upstream.timeout.map(|d| d.as_secs());
            tracing::debug!(backend = %backend, ?upstream.timeout, "upstream_peer: route plan");
            if !backend.is_empty() {
                if let Some(peer) = make_peer(&backend, timeout_secs).await {
                    return Ok(peer);
                }
            }
            let mut resp = ResponseHeader::build(502, None)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())));
        }

        // No upstream action in the plan. Gateway API routes return 500.
        if plan.gateway_api {
            let mut resp = ResponseHeader::build(500, None)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())));
        }

        // Legacy fallback — should not happen because from_config creates a
        // catch-all rule, but handle it defensively.
        let mut resp = ResponseHeader::build(404, None)?;
        resp.insert_header("Content-Length", "0")?;
        session.write_response_header(Box::new(resp), true).await?;
        Ok(Box::new(HttpPeer::new("127.0.0.1:1", false, String::new())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_core::protocols::l4::stream::Stream;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_ctx_with_plan(plan: Arc<CompiledPlan>) -> RequestCtx {
        RequestCtx {
            plan: Some(plan),
            start_time: Instant::now(),
            request_id: "test".to_string(),
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

    fn plan_with_upstream(backends: Vec<&str>, mirror: Vec<&str>) -> Arc<CompiledPlan> {
        let backends: Vec<crate::ir::WeightedBackend> = backends
            .into_iter()
            .map(|b| crate::ir::WeightedBackend {
                backend: b.into(),
                weight: 1,
                request_filters: vec![],
            })
            .collect();
        let backend_request_mutations = backends.iter().map(|_| vec![]).collect();
        Arc::new(CompiledPlan {
            precedence: 0,
            rule_order: 0,
            gateway_api: false,
            disable_secure_redirection: false,
            listener_hostname: None,
            matches: crate::ir::RequestMatch::default(),
            request_stages: vec![],
            upstream: Some(crate::ir::compile::UpstreamAction {
                backends,
                timeout: Some(Duration::from_secs(5)),
                mirror: mirror.into_iter().map(|m| m.into()).collect(),
                backend_request_mutations,
            }),
            upstream_request_mutations: vec![],
            response_mutations: vec![],
            body_rewrites: vec![],
            cache: None,
            websocket: false,
        })
    }

    fn gateway_plan_without_upstream() -> Arc<CompiledPlan> {
        Arc::new(CompiledPlan {
            precedence: 0,
            rule_order: 0,
            gateway_api: true,
            disable_secure_redirection: false,
            listener_hostname: None,
            matches: crate::ir::RequestMatch::default(),
            request_stages: vec![],
            upstream: None,
            upstream_request_mutations: vec![],
            response_mutations: vec![],
            body_rewrites: vec![],
            cache: None,
            websocket: false,
        })
    }

    fn legacy_plan_without_upstream() -> Arc<CompiledPlan> {
        Arc::new(CompiledPlan {
            precedence: 0,
            rule_order: 0,
            gateway_api: false,
            disable_secure_redirection: false,
            listener_hostname: None,
            matches: crate::ir::RequestMatch::default(),
            request_stages: vec![],
            upstream: None,
            upstream_request_mutations: vec![],
            response_mutations: vec![],
            body_rewrites: vec![],
            cache: None,
            websocket: false,
        })
    }

    async fn make_session_pair(
        method: &str,
        path: &str,
        host: &str,
    ) -> (Session, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let request = format!("{} {} HTTP/1.1\r\nHost: {}\r\n\r\n", method, path, host);
        server.write_all(request.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(Stream::from(client)));
        session.as_downstream_mut().read_request().await.unwrap();
        (session, server)
    }

    fn make_proxy() -> SunbeamProxy {
        SunbeamProxy {
            routes: Arc::new(arc_swap::ArcSwap::new(Arc::new(
                crate::ir::compile::CompiledRouteTable::empty(),
            ))),
            acme_routes: crate::acme::AcmeRoutes::default(),
            ddos_detector: None,
            scanner_detector: None,
            bot_allowlist: None,
            rate_limiter: None,
            compiled_rewrites: Arc::new(arc_swap::ArcSwap::new(Arc::new(vec![]))),
            http_client: reqwest::Client::new(),
            pipeline_bypass_cidrs: vec![],
            cluster: None,
            ddos_observe_only: false,
            scanner_observe_only: false,
        }
    }

    async fn response_status(server: &mut tokio::net::TcpStream) -> Option<u16> {
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        let line = String::from_utf8_lossy(&buf[..n]);
        line.split_whitespace().nth(1)?.parse().ok()
    }

    // ── ACME path ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn upstream_peer_acme_resolves_backend() {
        let proxy = make_proxy();
        let (mut session, _server) = make_session_pair("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(legacy_plan_without_upstream());
        ctx.acme_backend = Some("http://127.0.0.1:1".to_string());
        let peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        // No response should be written for a successful ACME peer.
        assert!(peer._address.to_string().contains("127.0.0.1:1"));
    }

    #[tokio::test]
    async fn upstream_peer_acme_unresolvable_returns_502() {
        let proxy = make_proxy();
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(legacy_plan_without_upstream());
        ctx.acme_backend = Some("http://this-host-should-not-exist.invalid:1".to_string());
        let _peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        let status = response_status(&mut server).await.unwrap();
        assert_eq!(status, 502);
    }

    // ── Missing plan ────────────────────────────────────────────────────

    #[tokio::test]
    async fn upstream_peer_no_plan_returns_404() {
        let proxy = make_proxy();
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(legacy_plan_without_upstream());
        ctx.plan = None;
        let _peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        let status = response_status(&mut server).await.unwrap();
        assert_eq!(status, 404);
    }

    // ── Upstream paths ──────────────────────────────────────────────────

    #[tokio::test]
    async fn upstream_peer_single_backend_returns_peer() {
        let proxy = make_proxy();
        let (mut session, _server) = make_session_pair("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(plan_with_upstream(vec!["http://127.0.0.1:1"], vec![]));
        let peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(ctx.backend_index, Some(0));
        assert!(peer._address.to_string().contains("127.0.0.1:1"));
    }

    #[tokio::test]
    async fn upstream_peer_multiple_backends_selects_one() {
        let proxy = make_proxy();
        let (mut session, _server) = make_session_pair("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(plan_with_upstream(
            vec!["http://127.0.0.1:1", "http://127.0.0.1:2"],
            vec![],
        ));
        let peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(ctx.backend_index.is_some());
        let addr = peer._address.to_string();
        assert!(addr.contains("127.0.0.1:1") || addr.contains("127.0.0.1:2"));
    }

    #[tokio::test]
    async fn upstream_peer_empty_backends_returns_502() {
        let proxy = make_proxy();
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(plan_with_upstream(vec![], vec![]));
        let _peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        let status = response_status(&mut server).await.unwrap();
        assert_eq!(status, 502);
    }

    #[tokio::test]
    async fn upstream_peer_unresolvable_backend_returns_502() {
        let proxy = make_proxy();
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(plan_with_upstream(
            vec!["http://this-host-should-not-exist.invalid:1"],
            vec![],
        ));
        let _peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        let status = response_status(&mut server).await.unwrap();
        assert_eq!(status, 502);
    }

    #[tokio::test]
    async fn upstream_peer_with_mirror_still_returns_peer() {
        let proxy = make_proxy();
        let (mut session, _server) = make_session_pair("GET", "/mirror-path", "example.com").await;
        let mut ctx = make_ctx_with_plan(plan_with_upstream(
            vec!["http://127.0.0.1:1"],
            vec!["http://127.0.0.1:1"],
        ));
        let peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(peer._address.to_string().contains("127.0.0.1:1"));
        // The mirror request is fire-and-forget; just ensure it spawned without
        // blocking the main path.
    }

    // ── No upstream fallback ────────────────────────────────────────────

    #[tokio::test]
    async fn upstream_peer_gateway_api_no_upstream_returns_500() {
        let proxy = make_proxy();
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(gateway_plan_without_upstream());
        let _peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        let status = response_status(&mut server).await.unwrap();
        assert_eq!(status, 500);
    }

    #[tokio::test]
    async fn upstream_peer_legacy_no_upstream_returns_404() {
        let proxy = make_proxy();
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(legacy_plan_without_upstream());
        let _peer = proxy
            .upstream_peer_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        let status = response_status(&mut server).await.unwrap();
        assert_eq!(status, 404);
    }
}
