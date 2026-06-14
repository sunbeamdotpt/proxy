// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SunbeamProxy {
    pub(crate) async fn request_filter_inner(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<bool> {
        // TLS-terminated HTTPS and L4-relayed plain HTTP connections arrive as
        // plaintext HTTP at the internal Pingora address. Detect them by matching
        // the internal target address and use the public listener port for route
        // selection.
        let l4_config = self.l4_config.load();
        if let Some(local) = downstream_local_addr(session) {
            if let Some(ctx_info) = self.http_relay_context(session) {
                // Plain HTTP that was relayed through the L4 manager. The public
                // listener port is recovered from the per-connection context.
                ctx.downstream_scheme = "http";
                ctx.downstream_port = ctx_info.listener_port;
            } else if let Some(listener_port) = https_terminate_port(&l4_config, local) {
                ctx.downstream_scheme = "https";
                ctx.downstream_port = listener_port;
            } else if let Some(listener_port) = http_relay_port(&l4_config, local) {
                ctx.downstream_scheme = "http";
                ctx.downstream_port = listener_port;
            } else {
                ctx.downstream_scheme = if is_plain_http(session) {
                    "http"
                } else {
                    "https"
                };
                ctx.downstream_port = downstream_port(session);
            }
        } else {
            ctx.downstream_scheme = if is_plain_http(session) {
                "http"
            } else {
                "https"
            };
            ctx.downstream_port = downstream_port(session);
        }

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

        // HTTPS listener misdirected request detection: if the SNI selected a
        // different listener than the request Host/Authority, return 421.
        if ctx.downstream_scheme == "https" {
            if let Some(sni) = self.sni_for_session(session) {
                let host = extract_host(session);
                let port = ctx.downstream_port;
                let l4 = self.l4_config.load();
                let sni_listener = l4.listener_hostname_for(&sni, port);
                let host_listener = l4.listener_hostname_for(&host, port);
                let mismatched = match (&sni_listener, &host_listener) {
                    (Some(s), Some(h)) => s != h,
                    (Some(_), None) => true,
                    _ => false,
                };
                if mismatched {
                    let mut resp = ResponseHeader::build(421, None)?;
                    resp.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        if is_plain_http(session) {
            // cert-manager HTTP-01 challenge: look up the token path in the
            // Ingress-backed route table. Each challenge Ingress maps exactly
            // one token to exactly one solver Service.
            if path.starts_with("/.well-known/acme-challenge/") {
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
                let mut resp = ResponseHeader::build(404, None)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }

            // All other plain-HTTP traffic. Routes that explicitly opt out of
            // HTTPS enforcement pass through. Gateway API listeners also pass
            // through (unmatched hosts get 404 in upstream_peer, not a redirect).
            // Unknown legacy hosts are redirected. Gateway API routes take
            // precedence: if any Gateway API route exists and none matched,
            // return 404 rather than redirecting to HTTPS.
            let headers = &session.req_header().headers;
            let query = session.req_header().uri.query();
            let matched_plan =
                self.lookup_plan(&host, ctx.downstream_port, &path, &method, headers, query);

            if matched_plan.as_ref().is_some_and(|p| {
                // Gateway API HTTP listeners must serve traffic without
                // redirecting; legacy routes follow the disable-redirect flag.
                p.gateway_api || p.disable_secure_redirection
            }) {
                // Store the plan for downstream phases. If the plan is terminal
                // (e.g. a redirect or fixed response), execute it now; otherwise
                // continue to upstream_peer for normal routing.
                ctx.plan = matched_plan;

                // CORS preflight requests are answered locally so that the upstream
                // backend never sees them. The synthetic 204 carries the configured
                // CORS headers when the Origin is allowed.
                if let Some(plan) = ctx.plan.as_ref() {
                    if session.req_header().method == http::Method::OPTIONS {
                        if let Some(cors) = plan.response_mutations.iter().find_map(|m| match m {
                            crate::ir::compile::ResponseMutation::Cors(c) => Some(c),
                            _ => None,
                        }) {
                            let headers = &session.req_header().headers;
                            if headers.get("origin").is_some()
                                && headers.get("access-control-request-method").is_some()
                            {
                                let mut resp = ResponseHeader::build(204, None)?;
                                super::filters::apply_response_mutation(
                                    session,
                                    &mut resp,
                                    &crate::ir::compile::ResponseMutation::Cors(cors.clone()),
                                )?;
                                session.write_response_header(Box::new(resp), true).await?;
                                return Ok(true);
                            }
                        }
                    }
                }

                if let Some(plan) = ctx.plan.as_ref() {
                    for stage in &plan.request_stages {
                        if let crate::ir::compile::RequestStage::Terminal(terminal) = stage {
                            self.execute_terminal_stage(
                                session,
                                terminal,
                                &path,
                                &host,
                                ctx.downstream_scheme,
                                ctx.downstream_port,
                            )
                            .await?;
                            return Ok(true);
                        }
                    }
                }
                return Ok(false);
            }

            if matched_plan.is_none() && self.has_gateway_api_routes() {
                let mut resp = ResponseHeader::build(404, None)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
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
        // decision. This guarantees downstream training pipelines always
        // have the full traffic picture:
        //   - "ddos" log  = all HTTPS traffic  (scanner training data)
        //   - "scanner" log = traffic that passed DDoS (rate-limit training data)
        //   - "rate_limit" log = traffic that passed scanner (validation data)

        // Skip the detection pipeline for trusted IPs (localhost, pod network),
        // but still perform the single route lookup below.
        if self
            .extract_client_ip(session)
            .map(|ip| crate::rate_limit::cidr::is_bypassed(ip, &self.pipeline_bypass_cidrs))
            .unwrap_or(false)
        {
            // fall through to the route lookup
        } else {
            // DDoS detection: check the client IP against the KNN model.
            if let Some(detector) = &self.ddos_detector {
                if let Some(ip) = self.extract_client_ip(session) {
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
                    let has_accept_language = session
                        .req_header()
                        .headers
                        .get("accept-language")
                        .is_some();
                    let accept = session
                        .req_header()
                        .headers
                        .get("accept")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-");
                    let ddos_action = detector.check(
                        ip,
                        method,
                        path,
                        &host,
                        user_agent,
                        content_length,
                        has_cookies,
                        has_referer,
                        has_accept_language,
                    );
                    let decision = if matches!(ddos_action, DDoSAction::Block) {
                        "block"
                    } else {
                        "allow"
                    };

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
            if let Some(scanner_swap) = &self.scanner_detector {
                let method = session.req_header().method.as_str();
                let path = session.req_header().uri.path();
                let host = extract_host(session);
                let prefix = host.split('.').next().unwrap_or("");
                let has_cookies = session.req_header().headers.get("cookie").is_some();
                let has_referer = session.req_header().headers.get("referer").is_some();
                let has_accept_language = session
                    .req_header()
                    .headers
                    .get("accept-language")
                    .is_some();
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
                let client_ip = self.extract_client_ip(session);

                // Bot allowlist: verified crawlers/agents bypass the scanner model.
                let bot_reason = self
                    .bot_allowlist
                    .as_ref()
                    .and_then(|al| client_ip.and_then(|ip| al.check(user_agent, ip)));

                let (decision, score, reason) = if let Some(bot_reason) = bot_reason {
                    ("allow", -1.0f64, bot_reason)
                } else {
                    let scanner = scanner_swap.load();
                    let verdict = scanner.check(
                        method,
                        path,
                        prefix,
                        has_cookies,
                        has_referer,
                        has_accept_language,
                        accept,
                        user_agent,
                        content_length,
                    );
                    let d = if matches!(verdict.action, ScannerAction::Block) {
                        "block"
                    } else {
                        "allow"
                    };
                    (d, verdict.score, verdict.reason)
                };

                let client_ip_str = client_ip.map(|ip| ip.to_string()).unwrap_or_default();

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
                if let Some(ip) = self.extract_client_ip(session) {
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
                    let decision = if matches!(rl_result, RateLimitResult::Reject { .. }) {
                        "block"
                    } else {
                        "allow"
                    };

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
                let decision = if bw_result == BandwidthLimitResult::Reject {
                    "block"
                } else {
                    "allow"
                };
                metrics::BANDWIDTH_LIMIT_DECISIONS
                    .with_label_values(&[decision])
                    .inc();
                if bw_result == BandwidthLimitResult::Reject {
                    let body = b"{\"error\":\"bandwidth_limit_exceeded\",\"message\":\"Request rate-limited: aggregate bandwidth capacity exceeded. Please try again shortly.\"}";
                    let mut resp = ResponseHeader::build(429, None)?;
                    resp.insert_header("Retry-After", "5")?;
                    resp.insert_header("Content-Type", "application/json")?;
                    resp.insert_header("Content-Length", body.len().to_string())?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(Some(Bytes::from_static(body)), true)
                        .await?;
                    return Ok(true);
                }
            }
        }

        // Single route lookup — all subsequent phases execute this plan.
        let host = extract_host(session);
        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.to_string();
        let headers = session.req_header().headers.clone();
        let query = session.req_header().uri.query().map(|s| s.to_string());
        let plan = self.lookup_plan(
            &host,
            ctx.downstream_port,
            &path,
            &method,
            &headers,
            query.as_deref(),
        );

        if let Some(plan) = plan {
            ctx.plan = Some(Arc::clone(&plan));

            // Execute request stages in compiler-determined order.
            for stage in &plan.request_stages {
                match stage {
                    crate::ir::compile::RequestStage::Auth(auth) => {
                        if self.execute_auth_stage(session, ctx, auth, &path).await? {
                            return Ok(true);
                        }
                    }
                    crate::ir::compile::RequestStage::CorsPreflight(cors) => {
                        if self
                            .execute_cors_preflight_stage(session, cors, &headers, &method)
                            .await?
                        {
                            return Ok(true);
                        }
                    }
                    crate::ir::compile::RequestStage::StaticFiles(sfa) => {
                        if self
                            .execute_static_files_stage(session, ctx, sfa, &host, &path)
                            .await?
                        {
                            return Ok(true);
                        }
                    }
                    crate::ir::compile::RequestStage::Terminal(terminal) => {
                        self.execute_terminal_stage(
                            session,
                            terminal,
                            &path,
                            &host,
                            ctx.downstream_scheme,
                            ctx.downstream_port,
                        )
                        .await?;
                        return Ok(true);
                    }
                }
            }
        } else {
            // No matching rule.
            if self.has_matching_gateway_api_listener(&host, ctx.downstream_port) {
                // Gateway API route: unmatched hosts/paths return 404.
                ctx.plan = None;
                return Ok(false);
            }
            // Legacy route with no fallback: return 404 now.
            let mut resp = ResponseHeader::build(404, None)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
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
}

impl SunbeamProxy {
    async fn execute_auth_stage(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        auth: &crate::ir::AuthConfig,
        req_path: &str,
    ) -> Result<bool> {
        let auth_url = auth.url.as_ref();
        let mut auth_req = self.http_client.get(auth_url);
        if let Some(cookie) = session.req_header().headers.get("cookie") {
            auth_req = auth_req.header("cookie", cookie.to_str().unwrap_or(""));
        }
        if let Some(auth_hdr) = session.req_header().headers.get("authorization") {
            auth_req = auth_req.header("authorization", auth_hdr.to_str().unwrap_or(""));
        }
        auth_req = auth_req.header("x-original-uri", req_path);

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
                for hdr_name in &auth.capture_headers {
                    if let Some(val) = resp.headers().get(hdr_name.as_ref()) {
                        if let Ok(v) = val.to_str() {
                            ctx.auth_headers.push((hdr_name.to_string(), v.to_string()));
                        }
                    }
                }
                Ok(false) // continue to next stage
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
                Ok(true) // short-circuit
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
                Ok(true) // short-circuit
            }
        }
    }

    async fn execute_cors_preflight_stage(
        &self,
        session: &mut Session,
        cors: &crate::ir::CorsConfig,
        req_headers: &http::header::HeaderMap,
        req_method: &str,
    ) -> Result<bool> {
        let origin = req_headers.get("origin").and_then(|v| v.to_str().ok());
        let requested_method = req_headers
            .get("access-control-request-method")
            .and_then(|v| v.to_str().ok());
        let requested_headers = req_headers
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok());

        if req_method.eq_ignore_ascii_case("OPTIONS") && requested_method.is_some() {
            let mut resp = ResponseHeader::build(204, None)?;
            if let Some(origin) = origin {
                if cors_allow_origin(origin, &cors.allow_origins, cors.allow_credentials) {
                    resp.insert_header("Access-Control-Allow-Origin", origin)?;
                    resp.insert_header("Vary", "Origin")?;
                    if cors.allow_credentials {
                        resp.insert_header("Access-Control-Allow-Credentials", "true")?;
                    }
                }
            }
            if !cors.allow_methods.is_empty() {
                let allowed_methods = if cors.allow_methods.iter().any(|m| m.as_ref() == "*") {
                    if cors.allow_credentials {
                        requested_method.unwrap_or("*").to_string()
                    } else {
                        "*".to_string()
                    }
                } else {
                    cors.allow_methods.join(", ")
                };
                resp.insert_header("Access-Control-Allow-Methods", allowed_methods)?;
            }
            if !cors.allow_headers.is_empty() {
                let allowed = if cors.allow_headers.iter().any(|h| h.as_ref() == "*") {
                    if cors.allow_credentials {
                        requested_headers.unwrap_or("*").to_string()
                    } else {
                        "*".to_string()
                    }
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
            Ok(true) // short-circuit
        } else {
            Ok(false) // not a preflight, continue
        }
    }

    async fn execute_static_files_stage(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        sfa: &crate::ir::StaticFileAction,
        host: &str,
        req_path: &str,
    ) -> Result<bool> {
        let prefix = host.split('.').next().unwrap_or("");
        let mut serve_path = req_path.to_string();
        if let Some(rewrites) = self.find_rewrites(prefix) {
            for rw in rewrites.iter() {
                if rw.pattern.is_match(req_path) {
                    serve_path = rw.target.clone();
                    break;
                }
            }
        }

        let extra_headers: Vec<(String, String)> = sfa
            .extra_headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();

        let served = crate::static_files::try_serve(
            session,
            sfa.root.as_ref(),
            sfa.fallback.as_ref().map(|s| s.as_ref()),
            &serve_path,
            extra_headers,
        )
        .await?;

        if served {
            ctx.served_static = true;
            Ok(true) // short-circuit
        } else {
            Ok(false) // not served, continue to next stage
        }
    }

    async fn execute_terminal_stage(
        &self,
        session: &mut Session,
        terminal: &crate::ir::compile::TerminalAction,
        _req_path: &str,
        request_host: &str,
        downstream_scheme: &str,
        downstream_port: u16,
    ) -> Result<()> {
        match terminal {
            crate::ir::compile::TerminalAction::Redirect(redirect) => {
                let location = build_redirect_location_ir(
                    redirect,
                    &session.req_header().uri,
                    request_host,
                    downstream_scheme,
                    downstream_port,
                );
                let mut resp = ResponseHeader::build(redirect.status_code, None)?;
                resp.insert_header("Location", location)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
            }
            crate::ir::compile::TerminalAction::FixedResponse {
                status,
                headers,
                body,
            } => {
                let mut resp = ResponseHeader::build(*status, None)?;
                for (name, value) in headers {
                    resp.insert_header(name.to_string(), value.as_ref())?;
                }
                // Default to text/plain to prevent browsers from MIME-sniffing a
                // missing Content-Type and executing untrusted fixed responses.
                if !headers
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case("content-type"))
                {
                    resp.insert_header("Content-Type", "text/plain; charset=utf-8")?;
                }
                if let Some(body) = body {
                    resp.insert_header("Content-Length", body.len().to_string())?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(Some(Bytes::from(body.as_ref().to_owned())), true)
                        .await?;
                } else {
                    resp.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(resp), true).await?;
                }
            }
            crate::ir::compile::TerminalAction::NotFound => {
                let mut resp = ResponseHeader::build(404, None)?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BucketConfig, DDoSConfig, RateLimitConfig, RouteConfig};
    use crate::ir::compile::{
        CompiledPlan, CompiledRouteTable, HostNode, PathTrieNode, RequestStage, TerminalAction,
        UpstreamAction,
    };
    use crate::ir::{
        AuthConfig, CorsConfig, HostnameMatch, RedirectAction, RequestMatch, StaticFileAction,
        WeightedBackend,
    };
    use pingora_core::protocols::l4::stream::Stream;
    use pingora_core::protocols::tls::SslDigest;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    fn make_ctx() -> RequestCtx {
        RequestCtx {
            plan: None,
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

    fn make_proxy() -> SunbeamProxy {
        SunbeamProxy {
            routes: Arc::new(arc_swap::ArcSwap::new(
                Arc::new(CompiledRouteTable::empty()),
            )),
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
            trusted_proxy_cidrs: crate::rate_limit::cidr::parse_cidrs(&["127.0.0.0/8".into()]),
            cluster: None,
            ddos_observe_only: false,
            scanner_observe_only: false,

        }
    }

    fn make_proxy_with_routes(table: CompiledRouteTable) -> SunbeamProxy {
        let proxy = make_proxy();
        proxy.routes.store(Arc::new(table));
        proxy
    }

    async fn make_session_pair(
        method: &str,
        path: &str,
        host: &str,
        extra_headers: &[(&str, &str)],
    ) -> (Session, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let extra = extra_headers
            .iter()
            .map(|(k, v)| format!("{}: {}\r\n", k, v))
            .collect::<String>();
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n{}\r\n",
            method, path, host, extra
        );
        server.write_all(request.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(Stream::from(client)));
        session.as_downstream_mut().read_request().await.unwrap();
        set_peer_addr(&mut session, "127.0.0.1:12345".parse().unwrap());
        (session, server)
    }

    fn set_tls(session: &mut Session) {
        let digest = session.as_downstream_mut().digest_mut().unwrap();
        digest.ssl_digest = Some(Arc::new(SslDigest::new(
            "ECDHE-RSA-AES128-GCM-SHA256",
            "TLSv1.2",
            None,
            None,
            vec![],
        )));
    }

    fn set_peer_addr(session: &mut Session, addr: std::net::SocketAddr) {
        use pingora_core::protocols::l4::socket::SocketAddr as PSocketAddr;
        use pingora_core::protocols::SocketDigest;
        let digest = session.as_downstream_mut().digest_mut().unwrap();
        let socket_digest = SocketDigest::from_raw_fd(-1);
        socket_digest
            .peer_addr
            .set(Some(PSocketAddr::Inet(addr)))
            .ok();
        digest.socket_digest = Some(Arc::new(socket_digest));
    }

    fn host_node_with_plan(
        hostname: HostnameMatch,
        gateway_api: bool,
        disable_secure_redirection: bool,
        plan: Arc<CompiledPlan>,
    ) -> HostNode {
        let mut trie = PathTrieNode::default();
        trie.prefix_plans.push(plan);
        HostNode {
            hostname,
            listener_ids: vec![],
            listener_hostname: None,
            listener_port: None,
            gateway_api,
            disable_secure_redirection,
            path_trie: trie,
            exact_paths: HashMap::new(),
            regex_plans: vec![],
            static_rewrites: vec![],
        }
    }

    fn table_with_host_node(host: &str, node: HostNode) -> CompiledRouteTable {
        let mut table = CompiledRouteTable::empty();
        table.exact_hosts.insert(host.into(), vec![node]);
        table
    }

    fn base_plan() -> CompiledPlan {
        CompiledPlan {
            precedence: 0,
            rule_order: 0,
            gateway_api: false,
            disable_secure_redirection: false,
            listener_hostname: None,
            matches: RequestMatch::default(),
            request_stages: vec![],
            upstream: None,
            upstream_request_mutations: vec![],
            response_mutations: vec![],
            body_rewrites: vec![],
            cache: None,
            websocket: false,
            client_cert_id: None,

        }
    }

    async fn response_status(server: &mut tokio::net::TcpStream) -> Option<u16> {
        let mut buf = [0u8; 2048];
        let n = timeout(Duration::from_secs(5), server.read(&mut buf))
            .await
            .ok()
            .and_then(|r| r.ok())?;
        if n == 0 {
            return None;
        }
        let line = String::from_utf8_lossy(&buf[..n]);
        line.split_whitespace().nth(1)?.parse().ok()
    }

    async fn mock_auth_server(status: u16, extra_headers: &[(&str, &str)]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let headers = extra_headers
            .iter()
            .map(|(k, v)| format!("{}: {}\r\n", k, v))
            .collect::<String>();
        let status_text = match status {
            200 => "200 OK",
            403 => "403 Forbidden",
            _ => "500 Internal Server Error",
        };
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 {}\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
                status_text, headers
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        format!("http://{}", addr)
    }

    // ── Plain HTTP paths ────────────────────────────────────────────────

    #[tokio::test]
    async fn plain_http_no_plan_redirects_to_https() {
        let proxy = make_proxy();
        let (mut session, mut server) =
            make_session_pair("GET", "/foo?bar=1", "example.com", &[]).await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(301));
    }

    #[tokio::test]
    async fn plain_http_acme_known_passes_through() {
        let proxy = make_proxy();
        proxy.acme_routes.write().unwrap().insert(
            "/.well-known/acme-challenge/token".to_string(),
            "http://solver:8089".to_string(),
        );
        let (mut session, _server) = make_session_pair(
            "GET",
            "/.well-known/acme-challenge/token",
            "example.com",
            &[],
        )
        .await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert_eq!(ctx.acme_backend.as_deref(), Some("http://solver:8089"));
    }

    #[tokio::test]
    async fn plain_http_acme_unknown_returns_404() {
        let proxy = make_proxy();
        let (mut session, mut server) = make_session_pair(
            "GET",
            "/.well-known/acme-challenge/token",
            "example.com",
            &[],
        )
        .await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(404));
    }

    #[tokio::test]
    async fn plain_http_gateway_api_unmatched_returns_404() {
        let node = HostNode {
            hostname: HostnameMatch::Exact("gw.example.com".into()),
            listener_ids: vec![],
            listener_hostname: None,
            listener_port: None,
            gateway_api: true,
            disable_secure_redirection: false,
            path_trie: PathTrieNode::default(),
            exact_paths: HashMap::new(),
            regex_plans: vec![],
            static_rewrites: vec![],
        };
        let table = table_with_host_node("gw.example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) =
            make_session_pair("GET", "/", "other.example.com", &[]).await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(404));
    }

    #[tokio::test]
    async fn plain_http_legacy_match_redirects_to_https() {
        let plan = Arc::new(base_plan());
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com", &[]).await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(301));
    }

    #[tokio::test]
    async fn plain_http_gateway_api_match_passes_through() {
        let mut plan = base_plan();
        plan.gateway_api = true;
        let plan = Arc::new(plan);
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            true,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, _server) = make_session_pair("GET", "/", "example.com", &[]).await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert!(ctx.plan.as_ref().unwrap().gateway_api);
    }

    #[tokio::test]
    async fn plain_http_disable_redirect_match_passes_through() {
        let mut plan = base_plan();
        plan.disable_secure_redirection = true;
        let plan = Arc::new(plan);
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            true,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, _server) = make_session_pair("GET", "/", "example.com", &[]).await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert!(ctx.plan.as_ref().unwrap().disable_secure_redirection);
    }

    #[tokio::test]
    async fn plain_http_terminal_redirect_executes() {
        let plan = Arc::new(CompiledPlan {
            disable_secure_redirection: true,
            request_stages: vec![RequestStage::Terminal(TerminalAction::Redirect(
                RedirectAction {
                    status_code: 302,
                    scheme: Some("https".into()),
                    hostname: Some("other.example.com".into()),
                    port: None,
                    path: None,
                },
            ))],
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) = make_session_pair("GET", "/old", "example.com", &[]).await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(302));
    }

    #[tokio::test]
    async fn plain_http_terminal_fixed_response_executes() {
        let plan = Arc::new(CompiledPlan {
            disable_secure_redirection: true,
            request_stages: vec![RequestStage::Terminal(TerminalAction::FixedResponse {
                status: 201,
                headers: vec![("x-custom".into(), "value".into())],
                body: Some("created".into()),
            })],
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com", &[]).await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(201));
    }

    // ── HTTPS detection / routing paths ─────────────────────────────────

    #[tokio::test]
    async fn https_no_plan_returns_404() {
        let proxy = make_proxy();
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com", &[]).await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(404));
    }

    #[tokio::test]
    async fn https_bypass_cidr_skips_detection_and_routes() {
        let plan = Arc::new(base_plan());
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            Arc::clone(&plan),
        );
        let table = table_with_host_node("example.com", node);
        let mut proxy = make_proxy_with_routes(table);
        let local = crate::rate_limit::cidr::parse_cidrs(&["127.0.0.0/8".into()]);
        proxy.pipeline_bypass_cidrs = local.clone();
        proxy.trusted_proxy_cidrs = local;
        let (mut session, _server) = make_session_pair(
            "GET",
            "/",
            "example.com",
            &[("x-forwarded-for", "127.0.0.1")],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert!(
            ctx.plan.is_some(),
            "bypassed requests still receive a route plan"
        );
    }

    #[tokio::test]
    async fn trusted_proxy_headers_used_when_peer_is_trusted() {
        let mut proxy = make_proxy();
        proxy.trusted_proxy_cidrs = crate::rate_limit::cidr::parse_cidrs(&["127.0.0.0/8".into()]);
        let (mut session, _server) =
            make_session_pair("GET", "/", "example.com", &[("x-real-ip", "192.0.2.42")]).await;
        set_peer_addr(&mut session, "127.0.0.1:12345".parse().unwrap());
        assert_eq!(
            proxy.extract_client_ip(&session),
            Some("192.0.2.42".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn untrusted_peer_ignores_spoofed_headers() {
        let mut proxy = make_proxy();
        proxy.trusted_proxy_cidrs = vec![];
        let (mut session, _server) =
            make_session_pair("GET", "/", "example.com", &[("x-real-ip", "192.0.2.42")]).await;
        set_peer_addr(&mut session, "127.0.0.1:12345".parse().unwrap());
        let ip = proxy.extract_client_ip(&session).unwrap();
        assert!(
            ip.is_loopback(),
            "expected loopback socket address, got {ip}"
        );
    }

    #[tokio::test]
    async fn https_ddos_block_returns_429() {
        let mut proxy = make_proxy();
        proxy.ddos_detector = Some(Arc::new(DDoSDetector::new(&DDoSConfig {
            threshold: 0.6,
            window_secs: 60,
            window_capacity: 100,
            min_events: 1,
            enabled: true,
            observe_only: false,
        })));
        let (mut session, mut server) = make_session_pair(
            "GET",
            "/",
            "example.com",
            &[("x-forwarded-for", "192.0.2.1")],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(429));
    }

    #[tokio::test]
    async fn https_ddos_observe_only_passes_through() {
        let mut proxy = make_proxy();
        proxy.ddos_detector = Some(Arc::new(DDoSDetector::new(&DDoSConfig {
            threshold: 0.6,
            window_secs: 60,
            window_capacity: 100,
            min_events: 1,
            enabled: true,
            observe_only: false,
        })));
        proxy.ddos_observe_only = true;
        let plan = Arc::new(base_plan());
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        proxy.routes.store(Arc::new(table));
        let (mut session, _server) = make_session_pair(
            "GET",
            "/",
            "example.com",
            &[("x-forwarded-for", "192.0.2.2")],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert!(ctx.plan.is_some());
    }

    #[tokio::test]
    async fn https_scanner_block_returns_403() {
        let mut proxy = make_proxy();
        proxy.scanner_detector = Some(Arc::new(arc_swap::ArcSwap::new(Arc::new(
            crate::scanner::detector::ScannerDetector::new(&[RouteConfig {
                host_prefix: "example".into(),
                backend: "http://127.0.0.1:8080".into(),
                websocket: false,
                disable_secure_redirection: false,
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
                cors: None,
                timeout_secs: None,
                listener_hostname: None,
                gateway_api: false,
            }]),
        ))));
        let (mut session, mut server) = make_session_pair(
            "GET",
            "/.env",
            "example.com",
            &[
                ("x-forwarded-for", "192.0.2.3"),
                ("user-agent", "curl/7.0"),
                ("accept", "*/*"),
            ],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(403));
    }

    #[tokio::test]
    async fn https_rate_limit_block_returns_429() {
        let mut proxy = make_proxy();
        proxy.rate_limiter = Some(Arc::new(RateLimiter::new(&RateLimitConfig {
            enabled: true,
            bypass_cidrs: vec![],
            eviction_interval_secs: 60,
            stale_after_secs: 120,
            authenticated: BucketConfig {
                burst: 10,
                rate: 5.0,
            },
            unauthenticated: BucketConfig {
                burst: 0,
                rate: 1.0,
            },
        })));
        let (mut session, mut server) = make_session_pair(
            "GET",
            "/",
            "example.com",
            &[("x-forwarded-for", "192.0.2.4")],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(429));
    }

    #[tokio::test]
    async fn https_cors_preflight_returns_204() {
        let plan = Arc::new(CompiledPlan {
            request_stages: vec![RequestStage::CorsPreflight(CorsConfig {
                allow_origins: vec!["https://app.example.com".into()],
                allow_methods: vec!["GET".into()],
                allow_headers: vec!["content-type".into()],
                expose_headers: vec![],
                max_age: Some(600),
                allow_credentials: true,
            })],
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) = make_session_pair(
            "OPTIONS",
            "/",
            "example.com",
            &[
                ("origin", "https://app.example.com"),
                ("access-control-request-method", "GET"),
            ],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(204));
    }

    #[tokio::test]
    async fn https_auth_success_captures_headers() {
        let auth_url = mock_auth_server(200, &[("x-user", "alice")]).await;
        let plan = Arc::new(CompiledPlan {
            request_stages: vec![RequestStage::Auth(AuthConfig {
                url: auth_url.into(),
                capture_headers: vec!["x-user".into()],
            })],
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, _server) = make_session_pair("GET", "/", "example.com", &[]).await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert_eq!(
            ctx.auth_headers,
            vec![("x-user".to_string(), "alice".to_string())]
        );
    }

    #[tokio::test]
    async fn https_auth_denied_returns_403() {
        let auth_url = mock_auth_server(403, &[]).await;
        let plan = Arc::new(CompiledPlan {
            request_stages: vec![RequestStage::Auth(AuthConfig {
                url: auth_url.into(),
                capture_headers: vec![],
            })],
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com", &[]).await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(403));
    }

    #[tokio::test]
    async fn https_auth_unreachable_returns_502() {
        let plan = Arc::new(CompiledPlan {
            request_stages: vec![RequestStage::Auth(AuthConfig {
                url: "http://127.0.0.1:1/".into(),
                capture_headers: vec![],
            })],
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com", &[]).await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(502));
    }

    #[tokio::test]
    async fn https_static_files_serves_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello").unwrap();
        let root: Arc<str> = dir.path().to_str().unwrap().into();
        let plan = Arc::new(CompiledPlan {
            request_stages: vec![RequestStage::StaticFiles(StaticFileAction {
                root,
                fallback: None,
                rewrites: vec![],
                extra_headers: vec![],
            })],
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) =
            make_session_pair("GET", "/hello.txt", "example.com", &[]).await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert!(ctx.served_static);
        assert_eq!(response_status(&mut server).await, Some(200));
    }

    #[tokio::test]
    async fn https_expect_continue_writes_100() {
        let plan = Arc::new(CompiledPlan {
            upstream: Some(UpstreamAction {
                backends: vec![WeightedBackend {
                    backend: "http://127.0.0.1:1".into(),
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
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) = make_session_pair(
            "PUT",
            "/upload",
            "example.com",
            &[("expect", "100-continue"), ("content-length", "4")],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert_eq!(response_status(&mut server).await, Some(100));
    }

    #[tokio::test]
    async fn https_ddos_allow_passes_through() {
        let mut proxy = make_proxy();
        proxy.ddos_detector = Some(Arc::new(DDoSDetector::new(&DDoSConfig {
            threshold: 0.6,
            window_secs: 60,
            window_capacity: 100,
            min_events: 5,
            enabled: true,
            observe_only: false,
        })));
        let plan = Arc::new(base_plan());
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        proxy.routes.store(Arc::new(table));
        let (mut session, _server) = make_session_pair(
            "GET",
            "/",
            "example.com",
            &[("x-forwarded-for", "192.0.2.5")],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert!(ctx.plan.is_some());
    }

    #[tokio::test]
    async fn https_scanner_observe_only_passes_through() {
        let mut proxy = make_proxy();
        proxy.scanner_detector = Some(Arc::new(arc_swap::ArcSwap::new(Arc::new(
            crate::scanner::detector::ScannerDetector::new(&[RouteConfig {
                host_prefix: "example".into(),
                backend: "http://127.0.0.1:8080".into(),
                websocket: false,
                disable_secure_redirection: false,
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
                cors: None,
                timeout_secs: None,
                listener_hostname: None,
                gateway_api: false,
            }]),
        ))));
        proxy.scanner_observe_only = true;
        let plan = Arc::new(base_plan());
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        proxy.routes.store(Arc::new(table));
        let (mut session, _server) = make_session_pair(
            "GET",
            "/.env",
            "example.com",
            &[
                ("x-forwarded-for", "192.0.2.6"),
                ("user-agent", "curl/7.0"),
                ("accept", "*/*"),
            ],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert!(ctx.plan.is_some());
    }

    #[tokio::test]
    async fn plain_http_terminal_not_found_executes() {
        let plan = Arc::new(CompiledPlan {
            disable_secure_redirection: true,
            request_stages: vec![RequestStage::Terminal(TerminalAction::NotFound)],
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, mut server) = make_session_pair("GET", "/", "example.com", &[]).await;
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(404));
    }

    #[tokio::test]
    async fn https_gateway_api_listener_no_plan_passes_through() {
        let node = HostNode {
            hostname: HostnameMatch::Exact("example.com".into()),
            listener_ids: vec![],
            listener_hostname: None,
            listener_port: None,
            gateway_api: true,
            disable_secure_redirection: false,
            path_trie: PathTrieNode::default(),
            exact_paths: HashMap::new(),
            regex_plans: vec![],
            static_rewrites: vec![],
        };
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, _server) = make_session_pair("GET", "/", "example.com", &[]).await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert!(ctx.plan.is_none());
    }

    #[tokio::test]
    async fn https_static_files_not_found_falls_through_to_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let root: Arc<str> = dir.path().to_str().unwrap().into();
        let plan = Arc::new(CompiledPlan {
            request_stages: vec![RequestStage::StaticFiles(StaticFileAction {
                root,
                fallback: None,
                rewrites: vec![],
                extra_headers: vec![],
            })],
            upstream: Some(UpstreamAction {
                backends: vec![WeightedBackend {
                    backend: "http://127.0.0.1:1".into(),
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
            ..base_plan()
        });
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        let proxy = make_proxy_with_routes(table);
        let (mut session, _server) =
            make_session_pair("GET", "/missing.txt", "example.com", &[]).await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert!(!ctx.served_static);
        assert!(ctx.plan.is_some());
    }

    #[tokio::test]
    async fn https_rate_limit_authenticated_identity_rejects() {
        let mut proxy = make_proxy();
        proxy.rate_limiter = Some(Arc::new(RateLimiter::new(&RateLimitConfig {
            enabled: true,
            bypass_cidrs: vec![],
            eviction_interval_secs: 60,
            stale_after_secs: 120,
            authenticated: BucketConfig {
                burst: 0,
                rate: 1.0,
            },
            unauthenticated: BucketConfig {
                burst: 10,
                rate: 1.0,
            },
        })));
        let plan = Arc::new(base_plan());
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        proxy.routes.store(Arc::new(table));
        let (mut session, mut server) = make_session_pair(
            "GET",
            "/",
            "example.com",
            &[
                ("x-forwarded-for", "192.0.2.8"),
                ("authorization", "Bearer secret-token"),
            ],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result);
        assert_eq!(response_status(&mut server).await, Some(429));
    }

    #[tokio::test]
    async fn https_rate_limit_allow_passes_through() {
        let mut proxy = make_proxy();
        proxy.rate_limiter = Some(Arc::new(RateLimiter::new(&RateLimitConfig {
            enabled: true,
            bypass_cidrs: vec![],
            eviction_interval_secs: 60,
            stale_after_secs: 120,
            authenticated: BucketConfig {
                burst: 10,
                rate: 5.0,
            },
            unauthenticated: BucketConfig {
                burst: 10,
                rate: 1.0,
            },
        })));
        let plan = Arc::new(base_plan());
        let node = host_node_with_plan(
            HostnameMatch::Exact("example.com".into()),
            false,
            false,
            plan,
        );
        let table = table_with_host_node("example.com", node);
        proxy.routes.store(Arc::new(table));
        let (mut session, _server) = make_session_pair(
            "GET",
            "/",
            "example.com",
            &[("x-forwarded-for", "192.0.2.7")],
        )
        .await;
        set_tls(&mut session);
        let mut ctx = make_ctx();
        let result = proxy
            .request_filter_inner(&mut session, &mut ctx)
            .await
            .unwrap();
        assert!(!result);
        assert!(ctx.plan.is_some());
    }
}
