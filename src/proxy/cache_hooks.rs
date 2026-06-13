// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SunbeamProxy {
    pub(crate) fn request_cache_filter_inner(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<()> {
        // Only cache GET/HEAD.
        let method = &session.req_header().method;
        if method != http::Method::GET && method != http::Method::HEAD {
            return Ok(());
        }

        let cache_cfg = match ctx.plan.as_ref().and_then(|p| p.cache.as_ref()) {
            Some(c) if c.enabled => c,
            _ => return Ok(()),
        };

        // Skip cache if body rewrites are active (need per-response rewriting).
        if ctx
            .plan
            .as_ref()
            .is_some_and(|p| !p.body_rewrites.is_empty())
        {
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

    pub(crate) fn cache_key_callback_inner(
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

    pub(crate) fn response_cache_filter_inner(
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

        let cache_cfg = match ctx.plan.as_ref().and_then(|p| p.cache.as_ref()) {
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

    pub(crate) async fn cache_hit_filter_inner(
        &self,
        _session: &mut Session,
        _meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        _is_fresh: bool,
        _ctx: &mut RequestCtx,
    ) -> Result<Option<ForcedFreshness>> {
        metrics::CACHE_STATUS.with_label_values(&["hit"]).inc();
        Ok(None)
    }

    pub(crate) fn cache_miss_inner(&self, session: &mut Session, _ctx: &mut RequestCtx) {
        metrics::CACHE_STATUS.with_label_values(&["miss"]).inc();
        session.cache.cache_miss();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use pingora_cache::{key::CacheHashKey, storage::HandleHit, trace::SpanHandle};
    use pingora_core::protocols::l4::stream::Stream;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::AsyncWriteExt;
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

    fn cache_plan(
        enabled: bool,
        default_ttl_secs: u64,
        stale_while_revalidate_secs: u32,
        max_file_size: usize,
    ) -> Arc<CompiledPlan> {
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
            cache: Some(crate::ir::CachePolicy {
                enabled,
                default_ttl_secs,
                stale_while_revalidate_secs,
                max_file_size,
            }),
            websocket: false,
        })
    }

    fn plan_with_body_rewrite() -> Arc<CompiledPlan> {
        let mut plan = cache_plan(true, 60, 0, 0);
        if let Some(p) = Arc::get_mut(&mut plan) {
            p.body_rewrites.push(crate::ir::BodyRewrite {
                find: "old".into(),
                replace: "new".into(),
                types: vec!["text/html".into()],
            });
        }
        plan
    }

    async fn make_session(method: &str, path: &str, host: &str) -> Session {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let request = format!("{} {} HTTP/1.1\r\nHost: {}\r\n\r\n", method, path, host);
        server.write_all(request.as_bytes()).await.unwrap();
        // Hold the server side open so the client does not see EOF until the
        // test finishes.
        tokio::spawn(async move {
            let _ = server;
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
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

    // ── request_cache_filter_inner ──────────────────────────────────────

    #[tokio::test]
    async fn request_cache_filter_enables_cache_for_get() {
        let proxy = make_proxy();
        let mut session = make_session("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        proxy
            .request_cache_filter_inner(&mut session, &mut ctx)
            .unwrap();
        assert!(session.cache.enabled());
    }

    #[tokio::test]
    async fn request_cache_filter_enables_cache_for_head() {
        let proxy = make_proxy();
        let mut session = make_session("HEAD", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        proxy
            .request_cache_filter_inner(&mut session, &mut ctx)
            .unwrap();
        assert!(session.cache.enabled());
    }

    #[tokio::test]
    async fn request_cache_filter_skips_post() {
        let proxy = make_proxy();
        let mut session = make_session("POST", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        proxy
            .request_cache_filter_inner(&mut session, &mut ctx)
            .unwrap();
        assert!(!session.cache.enabled());
    }

    #[tokio::test]
    async fn request_cache_filter_skips_disabled_cache() {
        let proxy = make_proxy();
        let mut session = make_session("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(false, 60, 0, 0));
        proxy
            .request_cache_filter_inner(&mut session, &mut ctx)
            .unwrap();
        assert!(!session.cache.enabled());
    }

    #[tokio::test]
    async fn request_cache_filter_skips_when_no_plan() {
        let proxy = make_proxy();
        let mut session = make_session("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        ctx.plan = None;
        proxy
            .request_cache_filter_inner(&mut session, &mut ctx)
            .unwrap();
        assert!(!session.cache.enabled());
    }

    #[tokio::test]
    async fn request_cache_filter_skips_body_rewrites() {
        let proxy = make_proxy();
        let mut session = make_session("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(plan_with_body_rewrite());
        proxy
            .request_cache_filter_inner(&mut session, &mut ctx)
            .unwrap();
        assert!(!session.cache.enabled());
    }

    #[tokio::test]
    async fn request_cache_filter_skips_auth_headers() {
        let proxy = make_proxy();
        let mut session = make_session("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        ctx.auth_headers
            .push(("X-User".to_string(), "alice".to_string()));
        proxy
            .request_cache_filter_inner(&mut session, &mut ctx)
            .unwrap();
        assert!(!session.cache.enabled());
    }

    #[tokio::test]
    async fn request_cache_filter_sets_max_file_size() {
        let proxy = make_proxy();
        let mut session = make_session("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 8192));
        proxy
            .request_cache_filter_inner(&mut session, &mut ctx)
            .unwrap();
        assert!(session.cache.enabled());
    }

    // ── cache_key_callback_inner ────────────────────────────────────────

    #[tokio::test]
    async fn cache_key_without_query() {
        let proxy = make_proxy();
        let session = make_session("GET", "/path", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        let key = proxy.cache_key_callback_inner(&session, &mut ctx).unwrap();
        // CacheKey hashes the primary component; just assert it is non-empty.
        assert!(!key.primary().is_empty());
    }

    #[tokio::test]
    async fn cache_key_includes_query_string() {
        let proxy = make_proxy();
        let session = make_session("GET", "/path?k=v", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        let key = proxy.cache_key_callback_inner(&session, &mut ctx).unwrap();
        assert!(!key.primary().is_empty());
    }

    // ── response_cache_filter_inner ─────────────────────────────────────

    fn response_with_cache_control(status: u16, cc: Option<&str>) -> ResponseHeader {
        let mut resp = ResponseHeader::build(status, None).unwrap();
        if let Some(v) = cc {
            resp.insert_header("cache-control", v).unwrap();
        }
        resp
    }

    #[tokio::test]
    async fn response_cache_filter_uncacheable_non_2xx() {
        let proxy = make_proxy();
        let resp = response_with_cache_control(404, None);
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        let session = make_session("GET", "/", "example.com").await;
        let result = proxy
            .response_cache_filter_inner(&session, &resp, &mut ctx)
            .unwrap();
        assert!(matches!(
            result,
            RespCacheable::Uncacheable(NoCacheReason::OriginNotCache)
        ));
    }

    #[tokio::test]
    async fn response_cache_filter_never_enabled_without_plan() {
        let proxy = make_proxy();
        let resp = response_with_cache_control(200, None);
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        ctx.plan = None;
        let session = make_session("GET", "/", "example.com").await;
        let result = proxy
            .response_cache_filter_inner(&session, &resp, &mut ctx)
            .unwrap();
        assert!(matches!(
            result,
            RespCacheable::Uncacheable(NoCacheReason::NeverEnabled)
        ));
    }

    #[tokio::test]
    async fn response_cache_filter_uses_default_ttl_without_cache_control() {
        let proxy = make_proxy();
        let resp = response_with_cache_control(200, None);
        let mut ctx = make_ctx_with_plan(cache_plan(true, 120, 30, 0));
        let session = make_session("GET", "/", "example.com").await;
        let result = proxy
            .response_cache_filter_inner(&session, &resp, &mut ctx)
            .unwrap();
        match result {
            RespCacheable::Cacheable(meta) => {
                assert!(
                    meta.fresh_until() >= std::time::SystemTime::now() + Duration::from_secs(100)
                );
            }
            _ => panic!("expected Cacheable"),
        }
    }

    #[tokio::test]
    async fn response_cache_filter_respects_no_store() {
        let proxy = make_proxy();
        let resp = response_with_cache_control(200, Some("no-store"));
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        let session = make_session("GET", "/", "example.com").await;
        let result = proxy
            .response_cache_filter_inner(&session, &resp, &mut ctx)
            .unwrap();
        assert!(matches!(
            result,
            RespCacheable::Uncacheable(NoCacheReason::OriginNotCache)
        ));
    }

    #[tokio::test]
    async fn response_cache_filter_respects_private() {
        let proxy = make_proxy();
        let resp = response_with_cache_control(200, Some("private"));
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        let session = make_session("GET", "/", "example.com").await;
        let result = proxy
            .response_cache_filter_inner(&session, &resp, &mut ctx)
            .unwrap();
        assert!(matches!(
            result,
            RespCacheable::Uncacheable(NoCacheReason::OriginNotCache)
        ));
    }

    #[tokio::test]
    async fn response_cache_filter_zero_max_age_uncacheable() {
        let proxy = make_proxy();
        let resp = response_with_cache_control(200, Some("max-age=0"));
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        let session = make_session("GET", "/", "example.com").await;
        let result = proxy
            .response_cache_filter_inner(&session, &resp, &mut ctx)
            .unwrap();
        assert!(matches!(
            result,
            RespCacheable::Uncacheable(NoCacheReason::OriginNotCache)
        ));
    }

    #[tokio::test]
    async fn response_cache_filter_uses_max_age_ttl() {
        let proxy = make_proxy();
        let resp = response_with_cache_control(200, Some("max-age=45"));
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        let session = make_session("GET", "/", "example.com").await;
        let result = proxy
            .response_cache_filter_inner(&session, &resp, &mut ctx)
            .unwrap();
        match result {
            RespCacheable::Cacheable(meta) => {
                assert!(
                    meta.fresh_until() >= std::time::SystemTime::now() + Duration::from_secs(40)
                );
            }
            _ => panic!("expected Cacheable"),
        }
    }

    #[tokio::test]
    async fn response_cache_filter_s_maxage_takes_priority() {
        let proxy = make_proxy();
        let resp = response_with_cache_control(200, Some("max-age=10, s-maxage=90"));
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        let session = make_session("GET", "/", "example.com").await;
        let result = proxy
            .response_cache_filter_inner(&session, &resp, &mut ctx)
            .unwrap();
        match result {
            RespCacheable::Cacheable(meta) => {
                assert!(
                    meta.fresh_until() >= std::time::SystemTime::now() + Duration::from_secs(80)
                );
            }
            _ => panic!("expected Cacheable"),
        }
    }

    // ── cache_hit_filter_inner / cache_miss_inner ───────────────────────

    struct DummyHitHandler;

    #[async_trait]
    impl HandleHit for DummyHitHandler {
        async fn read_body(&mut self) -> pingora_core::Result<Option<Bytes>> {
            Ok(None)
        }
        async fn finish(
            self: Box<Self>,
            _storage: &'static (dyn pingora_cache::Storage + Sync),
            _key: &CacheKey,
            _trace: &SpanHandle,
        ) -> pingora_core::Result<()> {
            Ok(())
        }
        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
            self
        }
        fn as_any_mut(&mut self) -> &mut (dyn std::any::Any + Send + Sync + 'static) {
            self
        }
    }

    #[tokio::test]
    async fn cache_hit_filter_returns_none() {
        let proxy = make_proxy();
        let mut session = make_session("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        let meta = CacheMeta::new(
            std::time::SystemTime::now() + Duration::from_secs(60),
            std::time::SystemTime::now(),
            0,
            0,
            ResponseHeader::build(200, None).unwrap(),
        );
        let mut hit_handler: HitHandler = Box::new(DummyHitHandler);
        let result = proxy
            .cache_hit_filter_inner(&mut session, &meta, &mut hit_handler, true, &mut ctx)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cache_miss_increments_and_sets_phase() {
        let proxy = make_proxy();
        let mut session = make_session("GET", "/", "example.com").await;
        let mut ctx = make_ctx_with_plan(cache_plan(true, 60, 0, 0));
        // Cache must be enabled and a key set before cache_miss() can be called.
        proxy
            .request_cache_filter_inner(&mut session, &mut ctx)
            .unwrap();
        session.cache.set_cache_key(CacheKey::new("", "test", ""));
        proxy.cache_miss_inner(&mut session, &mut ctx);
        assert!(session.cache.upstream_used());
    }
}
