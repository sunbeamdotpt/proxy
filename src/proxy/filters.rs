// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// Maximum response body size that will be buffered for in-memory find/replace
/// rewrites. Responses larger than this are streamed through without rewriting
/// to avoid OOM kills.
const MAX_BODY_REWRITE_BYTES: usize = 10 * 1024 * 1024;

impl SunbeamProxy {
    pub(crate) async fn upstream_request_filter_inner(
        &self,
        session: &mut Session,
        upstream_req: &mut RequestHeader,
        ctx: &mut RequestCtx,
    ) -> Result<()> {
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
        upstream_req
            .insert_header("x-request-id", &ctx.request_id)
            .map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "failed to insert x-request-id",
                    e,
                )
            })?;

        // WebSocket upgrade headers.
        if ctx.plan.as_ref().is_some_and(|p| p.websocket) {
            for name in &[CONNECTION, UPGRADE] {
                if let Some(val) = session.req_header().headers.get(name.clone()) {
                    upstream_req.insert_header(name.clone(), val)?;
                }
            }
        }

        // Forward captured auth subrequest headers.
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

        // Apply route-level upstream request mutations in compiler order.
        if let Some(plan) = &ctx.plan {
            for mutation in &plan.upstream_request_mutations {
                apply_upstream_request_mutation(upstream_req, mutation)?;
            }

            // Apply the selected backend's request mutations, if any.
            if let (Some(idx), Some(upstream)) = (ctx.backend_index, plan.upstream.as_ref()) {
                if let Some(mutations) = upstream.backend_request_mutations.get(idx) {
                    for mutation in mutations {
                        apply_upstream_request_mutation(upstream_req, mutation)?;
                    }
                }
            }
        }

        // Strip Expect: 100-continue.
        upstream_req.remove_header("expect");

        Ok(())
    }

    pub(crate) async fn upstream_response_filter_inner(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> Result<()> {
        // Add X-Request-Id to the response so clients can correlate.
        let _ = upstream_response.insert_header("x-request-id", &ctx.request_id);

        // Apply route-level response mutations in compiler order.
        if let Some(plan) = &ctx.plan {
            for mutation in &plan.response_mutations {
                apply_response_mutation(_session, upstream_response, mutation)?;
            }

            // Set up body rewriting if the plan has any rules.
            if !plan.body_rewrites.is_empty() {
                let content_type = upstream_response
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                let should_rewrite = content_type.starts_with("text/html")
                    || content_type.starts_with("application/javascript")
                    || content_type.starts_with("text/javascript");

                if should_rewrite {
                    ctx.body_buffer = Some(Vec::new());
                    upstream_response.remove_header("content-length");
                }
            }
        }

        Ok(())
    }

    pub(crate) fn response_body_filter_inner(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut RequestCtx,
    ) -> Result<Option<std::time::Duration>> {
        if ctx.body_buffer.is_none() {
            return Ok(None);
        }

        // Accumulate chunks into the buffer, but stop buffering if the response
        // exceeds the rewrite limit. Earlier chunks are dropped and the rest of
        // the body is streamed through unmodified to prevent OOM.
        if let Some(data) = body.take() {
            let Some(buf) = ctx.body_buffer.as_mut() else {
                *body = Some(data);
                return Ok(None);
            };
            if buf.len().saturating_add(data.len()) > MAX_BODY_REWRITE_BYTES {
                tracing::warn!(
                    len = buf.len(),
                    chunk = data.len(),
                    "response body exceeds rewrite buffer limit; disabling rewrite"
                );
                ctx.body_buffer = None;
                *body = Some(data);
                return Ok(None);
            }
            buf.extend_from_slice(&data);
        }

        if end_of_stream {
            let Some(buffer) = ctx.body_buffer.take() else {
                return Ok(None);
            };
            let mut result = String::from_utf8_lossy(&buffer).into_owned();
            if let Some(plan) = &ctx.plan {
                for br in &plan.body_rewrites {
                    if br.types.is_empty()
                        || br.types.iter().any(|t| {
                            let ct = _session
                                .response_written()
                                .and_then(|h| h.headers.get("content-type"))
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");
                            ct.starts_with(t.as_ref())
                        })
                    {
                        result = result.replace(br.find.as_ref(), br.replace.as_ref());
                    }
                }
            }
            *body = Some(Bytes::from(result));
        }

        Ok(None)
    }
}

/// Normalize a URI path by resolving `.` and `..` segments and rejecting
/// traversal above the root. Returns `None` if the path escapes the root.
fn normalize_path(path: &str) -> Option<String> {
    // Reject paths that are not absolute; relative paths should not reach upstream.
    if !path.starts_with('/') {
        return None;
    }
    let mut stack = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                stack.pop()?;
            }
            s => stack.push(s),
        }
    }
    Some(format!("/{}", stack.join("/")))
}

fn apply_upstream_request_mutation(
    upstream_req: &mut RequestHeader,
    mutation: &crate::ir::compile::UpstreamRequestMutation,
) -> Result<()> {
    use crate::ir::compile::UpstreamRequestMutation;

    match mutation {
        UpstreamRequestMutation::SetHeader { name, value } => {
            upstream_req
                .insert_header(name.to_string(), value.to_string())
                .map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::InternalError,
                        "failed to set request header",
                        e,
                    )
                })?;
        }
        UpstreamRequestMutation::AddHeader { name, value } => {
            upstream_req
                .append_header(name.to_string(), value.to_string())
                .map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::InternalError,
                        "failed to add request header",
                        e,
                    )
                })?;
        }
        UpstreamRequestMutation::RemoveHeader(name) => {
            upstream_req.remove_header(name.as_ref());
        }
        UpstreamRequestMutation::StripPrefix(prefix) => {
            let old_uri = upstream_req.uri.clone();
            let old_path = old_uri.path();
            if let Some(stripped) = old_path.strip_prefix(prefix.as_ref()) {
                let new_path = if stripped.is_empty() { "/" } else { stripped };
                let new_path = normalize_path(new_path).ok_or_else(|| {
                    pingora_core::Error::explain(
                        pingora_core::ErrorType::HTTPStatus(400),
                        "invalid path after prefix strip",
                    )
                })?;
                let query_part = old_uri.query().map(|q| format!("?{q}")).unwrap_or_default();
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
                upstream_req.set_uri(http::Uri::from_parts(parts).map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::InternalError,
                        "invalid uri parts after prefix strip",
                        e,
                    )
                })?);
            }
        }
        UpstreamRequestMutation::PrependPath(prefix) => {
            let old_uri = upstream_req.uri.clone();
            let old_path = old_uri.path();
            let trimmed = old_path.strip_prefix('/').unwrap_or(old_path);
            let raw_path = if prefix.ends_with('/') {
                format!("{prefix}{trimmed}")
            } else {
                format!("{prefix}/{trimmed}")
            };
            let new_path = normalize_path(&raw_path).ok_or_else(|| {
                pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(400),
                    "invalid path after prefix prepend",
                )
            })?;
            let query_part = old_uri.query().map(|q| format!("?{q}")).unwrap_or_default();
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
            upstream_req.set_uri(http::Uri::from_parts(parts).map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "invalid uri parts after prefix prepend",
                    e,
                )
            })?);
        }
        UpstreamRequestMutation::RewritePath(path_rewrite) => {
            let old_uri = upstream_req.uri.clone();
            let old_path = old_uri.path();
            let raw_path = match path_rewrite {
                crate::ir::PathRewrite::FullReplace(path) => path.to_string(),
                crate::ir::PathRewrite::PrefixReplace {
                    prefix,
                    replacement,
                } => old_path
                    .strip_prefix(prefix.as_ref())
                    .map(|rest| {
                        let replacement = replacement.as_ref();
                        let rest = rest.strip_prefix('/').unwrap_or(rest);
                        if replacement.is_empty() || replacement == "/" {
                            format!("/{}", rest)
                        } else {
                            let replacement = replacement.strip_suffix('/').unwrap_or(replacement);
                            if rest.is_empty() {
                                replacement.to_string()
                            } else {
                                format!("{}/{}", replacement, rest)
                            }
                        }
                    })
                    .unwrap_or_else(|| old_path.to_string()),
            };
            let new_path = normalize_path(&raw_path).ok_or_else(|| {
                pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(400),
                    "invalid path after path rewrite",
                )
            })?;
            let query_part = old_uri.query().map(|q| format!("?{q}")).unwrap_or_default();
            let new_pq: http::uri::PathAndQuery =
                format!("{new_path}{query_part}").parse().map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::InternalError,
                        "invalid uri after path rewrite",
                        e,
                    )
                })?;
            let mut parts = old_uri.into_parts();
            parts.path_and_query = Some(new_pq);
            upstream_req.set_uri(http::Uri::from_parts(parts).map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "invalid uri parts after path rewrite",
                    e,
                )
            })?);
        }
        UpstreamRequestMutation::RewriteHostname(hostname) => {
            upstream_req
                .insert_header("host", hostname.as_ref())
                .map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ErrorType::InternalError,
                        "failed to rewrite host header",
                        e,
                    )
                })?;
            let old_uri = upstream_req.uri.clone();
            let mut parts = old_uri.into_parts();
            let authority = http::uri::Authority::from_str(hostname.as_ref()).map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "invalid rewrite hostname",
                    e,
                )
            })?;
            parts.authority = Some(authority);
            parts.scheme.get_or_insert(http::uri::Scheme::HTTP);
            parts
                .path_and_query
                .get_or_insert(http::uri::PathAndQuery::from_static("/"));
            upstream_req.set_uri(http::Uri::from_parts(parts).map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::InternalError,
                    "failed to rewrite uri hostname",
                    e,
                )
            })?);
        }
    }

    Ok(())
}

pub(crate) fn apply_response_mutation(
    session: &Session,
    upstream_response: &mut ResponseHeader,
    mutation: &crate::ir::compile::ResponseMutation,
) -> Result<()> {
    use crate::ir::compile::ResponseMutation;

    match mutation {
        ResponseMutation::SetHeader { name, value } => {
            let _ = upstream_response.insert_header(name.to_string(), value.to_string());
        }
        ResponseMutation::AddHeader { name, value } => {
            let _ = upstream_response.append_header(name.to_string(), value.to_string());
        }
        ResponseMutation::RemoveHeader(name) => {
            upstream_response.remove_header(name.as_ref());
        }
        ResponseMutation::Cors(cors) => {
            let origin = session
                .req_header()
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok());
            let requested_method = session
                .req_header()
                .headers
                .get("access-control-request-method")
                .and_then(|v| v.to_str().ok());
            let requested_headers = session
                .req_header()
                .headers
                .get("access-control-request-headers")
                .and_then(|v| v.to_str().ok());
            let allowed = origin.is_some_and(|origin| {
                cors_allow_origin(origin, &cors.allow_origins, cors.allow_credentials)
            });
            if allowed {
                if let Some(origin) = origin {
                    let _ = upstream_response.insert_header("Access-Control-Allow-Origin", origin);
                    let _ = upstream_response.insert_header("Vary", "Origin");
                    if cors.allow_credentials {
                        let _ = upstream_response
                            .insert_header("Access-Control-Allow-Credentials", "true");
                    }
                    if !cors.allow_methods.is_empty() {
                        let methods = if cors.allow_methods.iter().any(|m| m.as_ref() == "*") {
                            if cors.allow_credentials {
                                requested_method.unwrap_or("*").to_string()
                            } else {
                                "*".to_string()
                            }
                        } else {
                            cors.allow_methods
                                .iter()
                                .map(|s| s.as_ref())
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        let _ = upstream_response
                            .insert_header("Access-Control-Allow-Methods", methods);
                    }
                    if !cors.allow_headers.is_empty() {
                        let headers = if cors.allow_headers.iter().any(|h| h.as_ref() == "*") {
                            if cors.allow_credentials {
                                requested_headers.unwrap_or("*").to_string()
                            } else {
                                "*".to_string()
                            }
                        } else {
                            cors.allow_headers
                                .iter()
                                .map(|s| s.as_ref())
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        let _ = upstream_response
                            .insert_header("Access-Control-Allow-Headers", headers);
                    }
                    if !cors.expose_headers.is_empty() {
                        let headers: String = cors
                            .expose_headers
                            .iter()
                            .map(|s| s.as_ref())
                            .collect::<Vec<_>>()
                            .join(", ");
                        let _ = upstream_response
                            .insert_header("Access-Control-Expose-Headers", headers);
                    }
                    if let Some(max_age) = cors.max_age {
                        let _ = upstream_response
                            .insert_header("Access-Control-Max-Age", max_age.to_string());
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        compile::{ResponseMutation, UpstreamRequestMutation},
        BodyRewrite, CorsConfig, PathRewrite,
    };
    use pingora_core::protocols::l4::stream::Stream;
    use pingora_http::{RequestHeader, ResponseHeader};
    use std::time::Instant;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn build_get(path: &str) -> RequestHeader {
        RequestHeader::build("GET", path.as_bytes(), None).unwrap()
    }

    #[test]
    fn set_header_replaces_existing() {
        let mut req = build_get("/");
        req.insert_header("x-foo", "old").unwrap();
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::SetHeader {
                name: "x-foo".into(),
                value: "new".into(),
            },
        )
        .unwrap();
        assert_eq!(req.headers.get("x-foo").unwrap().to_str().unwrap(), "new");
    }

    #[test]
    fn add_header_appends_without_removing_existing() {
        let mut req = build_get("/");
        req.insert_header("x-foo", "first").unwrap();
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::AddHeader {
                name: "x-foo".into(),
                value: "second".into(),
            },
        )
        .unwrap();
        let vals: Vec<_> = req
            .headers
            .get_all("x-foo")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(vals, vec!["first", "second"]);
    }

    #[test]
    fn remove_header_drops_it() {
        let mut req = build_get("/");
        req.insert_header("x-foo", "value").unwrap();
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::RemoveHeader("x-foo".into()),
        )
        .unwrap();
        assert!(req.headers.get("x-foo").is_none());
    }

    #[test]
    fn strip_prefix_to_root() {
        let mut req = build_get("/api?foo=bar");
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::StripPrefix("/api".into()),
        )
        .unwrap();
        assert_eq!(req.uri.path(), "/");
        assert_eq!(req.uri.query(), Some("foo=bar"));
    }

    #[test]
    fn strip_prefix_leaves_remainder() {
        let mut req = build_get("/api/v1/users");
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::StripPrefix("/api".into()),
        )
        .unwrap();
        assert_eq!(req.uri.path(), "/v1/users");
    }

    #[test]
    fn prepend_path_adds_prefix() {
        let mut req = build_get("/v1/users");
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::PrependPath("/prefix".into()),
        )
        .unwrap();
        assert_eq!(req.uri.path(), "/prefix/v1/users");
    }

    #[test]
    fn prepend_path_with_trailing_slash() {
        let mut req = build_get("/v1/users");
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::PrependPath("/prefix/".into()),
        )
        .unwrap();
        assert_eq!(req.uri.path(), "/prefix/v1/users");
    }

    #[test]
    fn rewrite_path_full_replace() {
        let mut req = build_get("/old/path?k=v");
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::RewritePath(PathRewrite::FullReplace(
                "/new".into(),
            )),
        )
        .unwrap();
        assert_eq!(req.uri.path(), "/new");
        assert_eq!(req.uri.query(), Some("k=v"));
    }

    #[test]
    fn rewrite_path_prefix_replace() {
        let mut req = build_get("/api/v1/users");
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::RewritePath(PathRewrite::PrefixReplace {
                prefix: "/api".into(),
                replacement: "/v2".into(),
            }),
        )
        .unwrap();
        assert_eq!(req.uri.path(), "/v2/v1/users");
    }

    #[test]
    fn rewrite_path_prefix_replace_no_match_unchanged() {
        let mut req = build_get("/other");
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::RewritePath(PathRewrite::PrefixReplace {
                prefix: "/api".into(),
                replacement: "/v2".into(),
            }),
        )
        .unwrap();
        assert_eq!(req.uri.path(), "/other");
    }

    #[test]
    fn rewrite_hostname_updates_host_and_authority() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.set_uri(http::Uri::from_static("http://original.example.com/"));
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::RewriteHostname(
                "upstream.example.com".into(),
            ),
        )
        .unwrap();
        assert_eq!(
            req.headers.get("host").unwrap().to_str().unwrap(),
            "upstream.example.com"
        );
        assert_eq!(req.uri.host(), Some("upstream.example.com"));
        assert_eq!(req.uri.scheme(), Some(&http::uri::Scheme::HTTP));
    }

    #[test]
    fn rewrite_hostname_defaults_scheme_and_path_for_origin_form() {
        let mut req = RequestHeader::build("GET", b"/api", None).unwrap();
        apply_upstream_request_mutation(
            &mut req,
            &crate::ir::compile::UpstreamRequestMutation::RewriteHostname(
                "upstream.example.com".into(),
            ),
        )
        .unwrap();
        assert_eq!(req.uri.host(), Some("upstream.example.com"));
        assert_eq!(req.uri.scheme(), Some(&http::uri::Scheme::HTTP));
        assert_eq!(req.uri.path(), "/api");
    }

    fn base_plan() -> crate::ir::compile::CompiledPlan {
        crate::ir::compile::CompiledPlan {
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
            client_cert_id: None,
        }
    }

    fn make_ctx_with_plan(plan: Arc<crate::ir::compile::CompiledPlan>) -> RequestCtx {
        RequestCtx {
            plan: Some(plan),
            start_time: Instant::now(),
            request_id: "req-42".to_string(),
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

    async fn session_with_headers(method: &str, path: &str, headers: &[(&str, &str)]) -> Session {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let extra = headers
            .iter()
            .map(|(k, v)| format!("{}: {}\r\n", k, v))
            .collect::<String>();
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: example.com\r\n{}\r\n",
            method, path, extra
        );
        server.write_all(request.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(Stream::from(client)));
        session.as_downstream_mut().read_request().await.unwrap();
        session
    }

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
            cluster: None,
            ddos_observe_only: false,
            scanner_observe_only: false,
        }
    }

    // ── upstream_request_filter_inner ───────────────────────────────────

    #[tokio::test]
    async fn upstream_request_filter_adds_forwarded_headers_and_strips_expect() {
        let proxy = make_proxy();
        let mut session = session_with_headers("GET", "/", &[]).await;
        let mut upstream_req = RequestHeader::build("GET", b"/api", None).unwrap();
        upstream_req
            .insert_header("expect", "100-continue")
            .unwrap();
        let mut ctx = make_ctx_with_plan(Arc::new(base_plan()));
        ctx.downstream_scheme = "https";

        proxy
            .upstream_request_filter_inner(&mut session, &mut upstream_req, &mut ctx)
            .await
            .unwrap();

        assert_eq!(
            upstream_req
                .headers
                .get("x-forwarded-proto")
                .unwrap()
                .to_str()
                .unwrap(),
            "https"
        );
        assert_eq!(
            upstream_req
                .headers
                .get("x-request-id")
                .unwrap()
                .to_str()
                .unwrap(),
            "req-42"
        );
        assert!(upstream_req.headers.get("expect").is_none());
    }

    #[tokio::test]
    async fn upstream_request_filter_forwards_websocket_headers() {
        let proxy = make_proxy();
        let mut session = session_with_headers(
            "GET",
            "/ws",
            &[("upgrade", "websocket"), ("connection", "Upgrade")],
        )
        .await;
        let mut upstream_req = RequestHeader::build("GET", b"/ws", None).unwrap();
        let mut plan = base_plan();
        plan.websocket = true;
        let mut ctx = make_ctx_with_plan(Arc::new(plan));

        proxy
            .upstream_request_filter_inner(&mut session, &mut upstream_req, &mut ctx)
            .await
            .unwrap();

        assert_eq!(
            upstream_req
                .headers
                .get("upgrade")
                .unwrap()
                .to_str()
                .unwrap(),
            "websocket"
        );
        assert_eq!(
            upstream_req
                .headers
                .get("connection")
                .unwrap()
                .to_str()
                .unwrap(),
            "Upgrade"
        );
    }

    #[tokio::test]
    async fn upstream_request_filter_applies_mutations_and_auth_headers() {
        let proxy = make_proxy();
        let mut session = session_with_headers("GET", "/", &[]).await;
        let mut upstream_req = RequestHeader::build("GET", b"/api", None).unwrap();
        let mut plan = base_plan();
        plan.upstream_request_mutations = vec![UpstreamRequestMutation::SetHeader {
            name: "x-route".into(),
            value: "yes".into(),
        }];
        plan.upstream = Some(crate::ir::compile::UpstreamAction {
            backends: vec![crate::ir::WeightedBackend {
                backend: "http://127.0.0.1:1".into(),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,
                request_filters: vec![],
                tls: None,
            }],
            timeout: None,
            mirror: vec![],
            mirror_fractions: vec![],
            backend_request_mutations: vec![vec![UpstreamRequestMutation::SetHeader {
                name: "x-backend".into(),
                value: "first".into(),
            }]],
        });
        let mut ctx = make_ctx_with_plan(Arc::new(plan));
        ctx.backend_index = Some(0);
        ctx.auth_headers
            .push(("x-auth".to_string(), "token".to_string()));

        proxy
            .upstream_request_filter_inner(&mut session, &mut upstream_req, &mut ctx)
            .await
            .unwrap();

        assert_eq!(
            upstream_req
                .headers
                .get("x-route")
                .unwrap()
                .to_str()
                .unwrap(),
            "yes"
        );
        assert_eq!(
            upstream_req
                .headers
                .get("x-backend")
                .unwrap()
                .to_str()
                .unwrap(),
            "first"
        );
        assert_eq!(
            upstream_req
                .headers
                .get("x-auth")
                .unwrap()
                .to_str()
                .unwrap(),
            "token"
        );
        assert!(ctx.auth_headers.is_empty());
    }

    // ── upstream_response_filter_inner ──────────────────────────────────

    #[tokio::test]
    async fn upstream_response_filter_adds_request_id_and_mutations() {
        let proxy = make_proxy();
        let mut session = session_with_headers("GET", "/", &[]).await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        let mut plan = base_plan();
        plan.response_mutations = vec![
            ResponseMutation::SetHeader {
                name: "x-resp".into(),
                value: "set".into(),
            },
            ResponseMutation::AddHeader {
                name: "x-added".into(),
                value: "one".into(),
            },
            ResponseMutation::RemoveHeader("x-removed".into()),
        ];
        let mut ctx = make_ctx_with_plan(Arc::new(plan));

        proxy
            .upstream_response_filter_inner(&mut session, &mut resp, &mut ctx)
            .await
            .unwrap();

        assert_eq!(
            resp.headers.get("x-request-id").unwrap().to_str().unwrap(),
            "req-42"
        );
        assert_eq!(resp.headers.get("x-resp").unwrap().to_str().unwrap(), "set");
        assert_eq!(resp.headers.get_all("x-added").iter().count(), 1);
    }

    #[tokio::test]
    async fn upstream_response_filter_sets_up_body_rewrite_buffer() {
        let proxy = make_proxy();
        let mut session = session_with_headers("GET", "/", &[]).await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "text/html; charset=utf-8")
            .unwrap();
        resp.insert_header("content-length", "100").unwrap();
        let mut plan = base_plan();
        plan.body_rewrites = vec![BodyRewrite {
            find: "old".into(),
            replace: "new".into(),
            types: vec![],
        }];
        let mut ctx = make_ctx_with_plan(Arc::new(plan));

        proxy
            .upstream_response_filter_inner(&mut session, &mut resp, &mut ctx)
            .await
            .unwrap();

        assert!(ctx.body_buffer.is_some());
        assert!(resp.headers.get("content-length").is_none());
    }

    // ── response_body_filter_inner ──────────────────────────────────────

    #[tokio::test]
    async fn response_body_filter_rewrites_at_end_of_stream() {
        let proxy = make_proxy();
        let mut session = session_with_headers("GET", "/", &[]).await;
        let mut plan = base_plan();
        plan.body_rewrites = vec![BodyRewrite {
            find: "old".into(),
            replace: "new".into(),
            types: vec![],
        }];
        let mut ctx = make_ctx_with_plan(Arc::new(plan));
        ctx.body_buffer = Some(Vec::new());

        let mut chunk = Some(bytes::Bytes::from_static(b"old "));
        proxy
            .response_body_filter_inner(&mut session, &mut chunk, false, &mut ctx)
            .unwrap();
        assert!(chunk.is_none());

        let mut chunk = Some(bytes::Bytes::from_static(b"text"));
        proxy
            .response_body_filter_inner(&mut session, &mut chunk, true, &mut ctx)
            .unwrap();
        assert_eq!(chunk.as_deref().unwrap(), b"new text");
        assert!(ctx.body_buffer.is_none());
    }

    #[tokio::test]
    async fn response_body_filter_no_buffer_leaves_body_unchanged() {
        let proxy = make_proxy();
        let mut session = session_with_headers("GET", "/", &[]).await;
        let mut ctx = make_ctx_with_plan(Arc::new(base_plan()));
        let mut chunk = Some(bytes::Bytes::from_static(b"payload"));
        proxy
            .response_body_filter_inner(&mut session, &mut chunk, true, &mut ctx)
            .unwrap();
        assert_eq!(chunk.as_deref().unwrap(), b"payload");
    }

    // ── apply_response_mutation ─────────────────────────────────────────

    #[tokio::test]
    async fn apply_response_mutation_remove_header_drops_it() {
        let session = session_with_headers("GET", "/", &[]).await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("x-trace", "1").unwrap();
        apply_response_mutation(
            &session,
            &mut resp,
            &ResponseMutation::RemoveHeader("x-trace".into()),
        )
        .unwrap();
        assert!(resp.headers.get("x-trace").is_none());
    }

    #[tokio::test]
    async fn apply_response_mutation_add_header_appends() {
        let session = session_with_headers("GET", "/", &[]).await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("x-foo", "first").unwrap();
        apply_response_mutation(
            &session,
            &mut resp,
            &ResponseMutation::AddHeader {
                name: "x-foo".into(),
                value: "second".into(),
            },
        )
        .unwrap();
        let vals: Vec<_> = resp
            .headers
            .get_all("x-foo")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(vals, vec!["first", "second"]);
    }

    #[tokio::test]
    async fn apply_response_mutation_cors_adds_all_headers() {
        let session =
            session_with_headers("OPTIONS", "/", &[("origin", "https://app.example.com")]).await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        let cors = CorsConfig {
            allow_origins: vec!["https://app.example.com".into()],
            allow_methods: vec!["GET, POST".into()],
            allow_headers: vec!["content-type".into()],
            expose_headers: vec!["x-custom".into()],
            max_age: Some(600),
            allow_credentials: true,
        };
        apply_response_mutation(&session, &mut resp, &ResponseMutation::Cors(cors)).unwrap();

        assert_eq!(
            resp.headers
                .get("access-control-allow-origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "https://app.example.com"
        );
        assert_eq!(
            resp.headers
                .get("access-control-allow-credentials")
                .unwrap()
                .to_str()
                .unwrap(),
            "true"
        );
        assert!(resp.headers.get("access-control-allow-methods").is_some());
        assert!(resp.headers.get("access-control-allow-headers").is_some());
        assert!(resp.headers.get("access-control-expose-headers").is_some());
        assert!(resp.headers.get("access-control-max-age").is_some());
    }

    #[tokio::test]
    async fn apply_response_mutation_cors_wildcard_origin_with_scheme() {
        let session = session_with_headers("GET", "/", &[("origin", "https://www.bar.com")]).await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        let cors = CorsConfig {
            allow_origins: vec!["https://*.bar.com".into()],
            allow_methods: vec![],
            allow_headers: vec![],
            expose_headers: vec![],
            max_age: None,
            allow_credentials: true,
        };
        apply_response_mutation(&session, &mut resp, &ResponseMutation::Cors(cors)).unwrap();

        assert_eq!(
            resp.headers
                .get("access-control-allow-origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "https://www.bar.com"
        );
    }

    #[tokio::test]
    async fn apply_response_mutation_cors_wildcard_methods_echo_with_credentials() {
        let session = session_with_headers(
            "OPTIONS",
            "/",
            &[
                ("origin", "https://other.foo.com"),
                ("access-control-request-method", "PUT"),
                ("access-control-request-headers", "x-header-1, x-header-2"),
            ],
        )
        .await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        let cors = CorsConfig {
            allow_origins: vec!["*".into()],
            allow_methods: vec!["*".into()],
            allow_headers: vec!["*".into()],
            expose_headers: vec![],
            max_age: None,
            allow_credentials: true,
        };
        apply_response_mutation(&session, &mut resp, &ResponseMutation::Cors(cors)).unwrap();

        assert_eq!(
            resp.headers
                .get("access-control-allow-origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "https://other.foo.com"
        );
        assert_eq!(
            resp.headers
                .get("access-control-allow-methods")
                .unwrap()
                .to_str()
                .unwrap(),
            "PUT"
        );
        assert_eq!(
            resp.headers
                .get("access-control-allow-headers")
                .unwrap()
                .to_str()
                .unwrap(),
            "x-header-1, x-header-2"
        );
        assert_eq!(
            resp.headers
                .get("access-control-allow-credentials")
                .unwrap()
                .to_str()
                .unwrap(),
            "true"
        );
    }
}
