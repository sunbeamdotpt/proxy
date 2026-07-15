// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SunbeamProxy {
    pub(crate) async fn logging_inner(
        &self,
        session: &mut Session,
        error: Option<&pingora_core::Error>,
        ctx: &mut RequestCtx,
    ) {
        metrics::ACTIVE_CONNECTIONS.dec();

        let status = session.response_written().map_or(0, |r| r.status.as_u16());
        let duration_ms = ctx.start_time.elapsed().as_millis() as u64;
        let duration_secs = ctx.start_time.elapsed().as_secs_f64();
        let method_str = session.req_header().method.to_string();
        let host = extract_host(session);
        let backend = ctx
            .plan
            .as_ref()
            .and_then(|p| p.upstream.as_ref())
            .and_then(|u| u.backends.first())
            .map(|b| b.backend.as_ref())
            .unwrap_or("-");
        let client_ip = self
            .extract_client_ip(session)
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
            c.bandwidth
                .record(req_bytes, session.body_bytes_sent() as u64);
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
        let has_cookies = session.req_header().headers.get("cookie").is_some();
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

        if let Some(detector) = &self.ddos_detector
            && let Some(ip) = self.extract_client_ip(session)
        {
            detector.record_response(ip, status, duration_ms as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::compile::UpstreamAction;
    use crate::ir::{RequestMatch, WeightedBackend};
    use pingora_core::protocols::l4::stream::Stream;
    use pingora_http::ResponseHeader;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn make_proxy() -> SunbeamProxy {
        SunbeamProxy {
            routes: Arc::new(arc_swap::ArcSwap::new(Arc::new(
                crate::ir::compile::CompiledRouteTable::empty(),
            ))),
            l4_config: Arc::new(arc_swap::ArcSwap::new(Arc::new(
                crate::ir::compile::CompiledL4Config::empty(),
            ))),
            sni_context: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            http_context: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            tls_registry: None,
            acme_routes: crate::acme::AcmeRoutes::default(),
            ddos_detector: None,
            scanner_detector: None,
            bot_allowlist: None,
            rate_limiter: None,
            compiled_rewrites: Arc::new(arc_swap::ArcSwap::new(Arc::new(vec![]))),
            http_client: reqwest::Client::new(),
            pipeline_bypass_cidrs: vec![],
            trusted_proxy_cidrs: vec![],
            x_forwarded_for: false,
            cluster: None,
            ddos_observe_only: false,
            scanner_observe_only: false,
        }
    }

    fn plan_with_backend(backend: &str) -> Arc<CompiledPlan> {
        Arc::new(CompiledPlan {
            precedence: 0,
            rule_order: 0,
            gateway_api: false,
            disable_secure_redirection: false,
            listener_hostname: None,
            matches: RequestMatch::default(),
            request_stages: vec![],
            upstream: Some(UpstreamAction {
                backends: vec![WeightedBackend {
                    backend: backend.into(),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,
                    request_filters: vec![],
                    tls: None,
                }],
                timeout: None,
                mirror: vec![],
                mirror_fractions: vec![],
                backend_request_mutations: vec![vec![]],
            }),
            upstream_request_mutations: vec![],
            response_mutations: vec![],
            body_rewrites: vec![],
            cache: None,
            websocket: false,
            client_cert_id: None,
        })
    }

    async fn make_session(method: &str, path: &str) -> (Session, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let request = format!(
            "{} {} HTTP/1.1\r\n\
             Host: log-test.example.com\r\n\
             User-Agent: test-agent/1.0\r\n\
             Referer: https://example.com/\r\n\
             Accept-Language: en-US\r\n\
             Accept: text/html\r\n\
             Accept-Encoding: gzip\r\n\
             Connection: keep-alive\r\n\
             Cookie: session=abc\r\n\
             X-Forwarded-For: 192.0.2.42\r\n\
             Content-Length: 0\r\n\
             \r\n",
            method, path
        );
        server.write_all(request.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(Stream::from(client)));
        session.as_downstream_mut().read_request().await.unwrap();
        (session, server)
    }

    #[tokio::test]
    async fn logging_inner_records_metrics_and_fields() {
        let proxy = make_proxy();
        let (mut session, _server) = make_session("GET", "/path?foo=bar").await;
        let mut resp = ResponseHeader::build(201, None).unwrap();
        resp.insert_header("Content-Length", "0").unwrap();
        session
            .write_response_header(Box::new(resp), true)
            .await
            .unwrap();

        let mut ctx = RequestCtx {
            plan: Some(plan_with_backend("test-backend")),
            start_time: Instant::now(),
            request_id: "test-req".to_string(),
            span: tracing::Span::none(),
            acme_backend: None,
            downstream_scheme: "https",
            downstream_port: 0,
            served_static: false,
            auth_headers: vec![],
            backend_index: None,
            body_buffer: None,
        };

        let counter = metrics::REQUESTS_TOTAL.with_label_values(&[
            "GET",
            "log-test.example.com",
            "201",
            "test-backend",
        ]);
        let before = counter.get();

        proxy.logging_inner(&mut session, None, &mut ctx).await;

        assert_eq!(counter.get(), before + 1);
        assert_eq!(session.response_written().unwrap().status.as_u16(), 201);
    }

    #[tokio::test]
    async fn logging_inner_with_error_records_error_string() {
        let proxy = make_proxy();
        let (mut session, _server) = make_session("POST", "/error").await;
        let mut resp = ResponseHeader::build(500, None).unwrap();
        resp.insert_header("Content-Length", "0").unwrap();
        session
            .write_response_header(Box::new(resp), true)
            .await
            .unwrap();

        let mut ctx = RequestCtx {
            plan: Some(plan_with_backend("test-backend")),
            start_time: Instant::now(),
            request_id: "test-req-err".to_string(),
            span: tracing::Span::none(),
            acme_backend: None,
            downstream_scheme: "https",
            downstream_port: 0,
            served_static: false,
            auth_headers: vec![],
            backend_index: None,
            body_buffer: None,
        };

        let err = pingora_core::Error::because(
            pingora_core::ErrorType::InternalError,
            "test error",
            std::io::Error::new(std::io::ErrorKind::Other, "boom"),
        );

        let counter = metrics::REQUESTS_TOTAL.with_label_values(&[
            "POST",
            "log-test.example.com",
            "500",
            "test-backend",
        ]);
        let before = counter.get();

        proxy
            .logging_inner(&mut session, Some(&err), &mut ctx)
            .await;

        assert_eq!(counter.get(), before + 1);
    }
}
