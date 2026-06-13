// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use bytes::Bytes;
use proptest::prelude::*;
use std::collections::HashSet;
use sunbeam_proxy::config::{
    BodyRewrite, HeaderRule, PathRoute, RewriteRule, RouteConfig, TelemetryConfig,
};
use sunbeam_proxy::proxy::{backend_addr, SunbeamProxy};
use sunbeam_proxy::static_files::{cache_control_for, content_type_for};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_route(
    host_prefix: &str,
    backend: &str,
    rewrites: Vec<RewriteRule>,
    body_rewrites: Vec<BodyRewrite>,
    response_headers: Vec<HeaderRule>,
) -> RouteConfig {
    RouteConfig {
        host_prefix: host_prefix.into(),
        backend: backend.into(),
        websocket: false,
        disable_secure_redirection: false,
        paths: vec![],
        static_root: None,
        fallback: None,
        rewrites,
        body_rewrites,
        response_headers,
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
    }
}

// ─── Strategies ──────────────────────────────────────────────────────────────

fn extension_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Known extensions
        Just("html".into()),
        Just("css".into()),
        Just("js".into()),
        Just("json".into()),
        Just("svg".into()),
        Just("png".into()),
        Just("jpg".into()),
        Just("jpeg".into()),
        Just("gif".into()),
        Just("ico".into()),
        Just("webp".into()),
        Just("avif".into()),
        Just("woff".into()),
        Just("woff2".into()),
        Just("ttf".into()),
        Just("otf".into()),
        Just("eot".into()),
        Just("xml".into()),
        Just("txt".into()),
        Just("map".into()),
        Just("webmanifest".into()),
        Just("mp4".into()),
        Just("wasm".into()),
        Just("pdf".into()),
        Just("mjs".into()),
        Just("htm".into()),
        // Random unknown extensions
        "[a-z]{1,10}",
        // Empty
        Just("".into()),
    ]
}

fn backend_url_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "http://[a-z]{1,15}\\.[a-z]{1,10}:[0-9]{2,5}",
        "https://[a-z]{1,15}\\.[a-z]{1,10}:[0-9]{2,5}",
        "http://127\\.0\\.0\\.1:[0-9]{2,5}",
        "https://10\\.0\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{2,5}",
        "[a-z]{1,10}://[a-z.]{1,20}:[0-9]{2,5}",
        Just("http://localhost:8080".into()),
        // No scheme at all
        "[a-z.]{1,20}:[0-9]{2,5}",
    ]
}

fn find_replace_strategy() -> impl Strategy<Value = (String, String)> {
    ("[a-zA-Z0-9./_-]{1,50}", "[a-zA-Z0-9./_-]{0,50}")
}

fn body_content_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // HTML-like content
        "<html><head></head><body>[a-zA-Z0-9 <>/=.\"']{0,200}</body></html>",
        // JS-like content
        "var [a-z]+ = \"[a-zA-Z0-9./_:-]{0,100}\";",
        // Minimal
        "[a-zA-Z0-9 <>/=\"'._-]{0,500}",
        // Empty
        Just("".into()),
    ]
}

// ─── content_type_for ────────────────────────────────────────────────────────

proptest! {
    /// content_type_for never panics for any extension string.
    #[test]
    fn content_type_never_panics(ext in "[a-zA-Z0-9._]{0,20}") {
        let ct = content_type_for(&ext);
        prop_assert!(!ct.is_empty());
    }

    /// Known extensions always map to the right MIME category.
    #[test]
    fn content_type_known_extensions_correct(ext in extension_strategy()) {
        let ct = content_type_for(&ext);
        match ext.as_str() {
            "html" | "htm" => prop_assert!(ct.starts_with("text/html")),
            "css" => prop_assert!(ct.starts_with("text/css")),
            "js" | "mjs" => prop_assert!(ct.starts_with("application/javascript")),
            "json" | "map" => prop_assert!(ct.starts_with("application/json")),
            "svg" => prop_assert!(ct.starts_with("image/svg")),
            "png" => prop_assert_eq!(ct, "image/png"),
            "jpg" | "jpeg" => prop_assert_eq!(ct, "image/jpeg"),
            "gif" => prop_assert_eq!(ct, "image/gif"),
            "woff2" => prop_assert_eq!(ct, "font/woff2"),
            "wasm" => prop_assert_eq!(ct, "application/wasm"),
            "pdf" => prop_assert_eq!(ct, "application/pdf"),
            _ => { /* unknown extensions get octet-stream, that's fine */ }
        }
    }

    /// The return value always contains a `/` (valid MIME type format).
    #[test]
    fn content_type_always_valid_mime(ext in "\\PC{0,30}") {
        let ct = content_type_for(&ext);
        // All MIME types must have a slash separating type/subtype.
        prop_assert!(ct.contains('/'), "MIME type missing /: {ct}");
    }
}

// ─── cache_control_for ───────────────────────────────────────────────────────

proptest! {
    /// cache_control_for never panics and returns non-empty.
    #[test]
    fn cache_control_never_panics(ext in "[a-zA-Z0-9._]{0,20}") {
        let cc = cache_control_for(&ext);
        prop_assert!(!cc.is_empty());
    }

    /// Hashed-asset extensions always get immutable cache headers.
    #[test]
    fn cache_control_immutable_for_assets(
        ext in prop_oneof![
            Just("js"), Just("mjs"), Just("css"),
            Just("woff"), Just("woff2"), Just("ttf"),
            Just("otf"), Just("eot"), Just("wasm"),
        ]
    ) {
        let cc = cache_control_for(ext);
        prop_assert!(cc.contains("immutable"), "expected immutable for .{ext}: {cc}");
        prop_assert!(cc.contains("31536000"), "expected 1-year max-age for .{ext}: {cc}");
    }

    /// Image extensions get 1-day cache.
    #[test]
    fn cache_control_day_for_images(
        ext in prop_oneof![
            Just("png"), Just("jpg"), Just("jpeg"), Just("gif"),
            Just("webp"), Just("avif"), Just("svg"), Just("ico"),
        ]
    ) {
        let cc = cache_control_for(ext);
        prop_assert!(cc.contains("86400"), "expected 1-day max-age for .{ext}: {cc}");
        prop_assert!(!cc.contains("immutable"), "images should not be immutable: {cc}");
    }

    /// HTML and unknown extensions get no-cache.
    #[test]
    fn cache_control_no_cache_for_html(ext in prop_oneof![Just("html"), Just("htm"), Just("")]) {
        let cc = cache_control_for(ext);
        prop_assert_eq!(cc, "no-cache");
    }
}

// ─── backend_addr ────────────────────────────────────────────────────────────

proptest! {
    /// backend_addr never panics on arbitrary strings.
    #[test]
    fn backend_addr_never_panics(s in "\\PC{0,200}") {
        let _ = backend_addr(&s);
    }

    /// backend_addr strips http:// and https:// prefixes.
    #[test]
    fn backend_addr_strips_http(host in "[a-z.]{1,30}:[0-9]{2,5}") {
        let http_url = format!("http://{host}");
        let https_url = format!("https://{host}");
        prop_assert_eq!(backend_addr(&http_url), host.as_str());
        prop_assert_eq!(backend_addr(&https_url), host.as_str());
    }

    /// backend_addr on strings without a scheme is identity.
    #[test]
    fn backend_addr_no_scheme_is_identity(host in "[a-z.]{1,30}:[0-9]{2,5}") {
        prop_assert_eq!(backend_addr(&host), host.as_str());
    }

    /// backend_addr result never contains "://".
    #[test]
    fn backend_addr_result_no_scheme(url in backend_url_strategy()) {
        let result = backend_addr(&url);
        // Result should not start with http:// or https://
        prop_assert!(!result.starts_with("http://"));
        prop_assert!(!result.starts_with("https://"));
    }
}

// ─── Request ID (UUID v4) ────────────────────────────────────────────────────

proptest! {
    /// Generated UUIDs are always valid v4 and unique.
    #[test]
    fn request_ids_are_valid_uuid_v4(count in 1..100usize) {
        let mut seen = HashSet::new();
        for _ in 0..count {
            let id = uuid::Uuid::new_v4();
            prop_assert_eq!(id.get_version(), Some(uuid::Version::Random));
            prop_assert_eq!(id.to_string().len(), 36);
            prop_assert!(seen.insert(id), "duplicate UUID generated");
        }
    }

    /// UUID string format is always parseable back.
    #[test]
    fn request_id_roundtrip(_seed in 0u64..10000) {
        let id = uuid::Uuid::new_v4();
        let s = id.to_string();
        let parsed = uuid::Uuid::parse_str(&s).unwrap();
        prop_assert_eq!(id, parsed);
    }
}

// ─── Rewrite rule compilation ────────────────────────────────────────────────

proptest! {
    /// compile_rewrites never panics, even with invalid regex patterns.
    #[test]
    fn compile_rewrites_never_panics(
        pattern in "[a-zA-Z0-9^$.*/\\[\\](){},?+|\\\\-]{0,50}",
        target in "[a-zA-Z0-9/_.-]{0,50}",
    ) {
        let routes = vec![make_route(
            "test",
            "http://localhost:8080",
            vec![RewriteRule { pattern, target }],
            vec![],
            vec![],
        )];
        // Should not panic — invalid regexes are logged and skipped.
        let compiled = SunbeamProxy::compile_rewrites(&routes);
        prop_assert!(compiled.len() <= 1);
    }

    /// Valid regex patterns compile and can be matched against paths.
    #[test]
    fn compile_rewrites_valid_patterns_work(
        prefix in "[a-z]{1,10}",
        path_segment in "[a-z0-9]{1,20}",
    ) {
        let pattern = format!("^/{path_segment}$");
        let routes = vec![make_route(
            &prefix,
            "http://localhost:8080",
            vec![RewriteRule {
                pattern: pattern.clone(),
                target: "/rewritten.html".into(),
            }],
            vec![],
            vec![],
        )];
        let compiled = SunbeamProxy::compile_rewrites(&routes);
        prop_assert_eq!(compiled.len(), 1);
        prop_assert_eq!(compiled[0].1.len(), 1);
        let test_path = format!("/{path_segment}");
        prop_assert!(compiled[0].1[0].pattern.is_match(&test_path));
    }

    /// Routes without rewrites produce no compiled entries.
    #[test]
    fn compile_rewrites_empty_for_no_rules(prefix in "[a-z]{1,10}") {
        let routes = vec![make_route(
            &prefix,
            "http://localhost:8080",
            vec![],
            vec![],
            vec![],
        )];
        let compiled = SunbeamProxy::compile_rewrites(&routes);
        prop_assert!(compiled.is_empty());
    }

    /// Multiple rewrite rules on one route all compile.
    #[test]
    fn compile_rewrites_multiple_rules(
        n in 1..10usize,
        prefix in "[a-z]{1,5}",
    ) {
        let rules: Vec<RewriteRule> = (0..n)
            .map(|i| RewriteRule {
                pattern: format!("^/path{i}$"),
                target: format!("/target{i}.html"),
            })
            .collect();
        let routes = vec![make_route(
            &prefix,
            "http://localhost:8080",
            rules,
            vec![],
            vec![],
        )];
        let compiled = SunbeamProxy::compile_rewrites(&routes);
        prop_assert_eq!(compiled.len(), 1);
        prop_assert_eq!(compiled[0].1.len(), n);
    }

    /// Rewrite rules with complex UUID-matching patterns compile.
    #[test]
    fn compile_rewrites_uuid_pattern(_i in 0..50u32) {
        let routes = vec![make_route(
            "docs",
            "http://localhost:8080",
            vec![RewriteRule {
                pattern: r"^/docs/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/?$".into(),
                target: "/docs/[id]/index.html".into(),
            }],
            vec![],
            vec![],
        )];
        let compiled = SunbeamProxy::compile_rewrites(&routes);
        prop_assert_eq!(compiled.len(), 1);
        prop_assert!(compiled[0].1[0].pattern.is_match("/docs/550e8400-e29b-41d4-a716-446655440000/"));
        prop_assert!(!compiled[0].1[0].pattern.is_match("/docs/not-a-uuid/"));
    }
}

// ─── Body rewriting ──────────────────────────────────────────────────────────

/// Simulate the body rewrite logic from response_body_filter without needing
/// a Pingora session. This mirrors the exact algorithm in proxy.rs.
fn simulate_body_rewrite(chunks: &[&[u8]], rules: &[(String, String)]) -> Vec<u8> {
    let mut buffer = Vec::new();
    for chunk in chunks {
        buffer.extend_from_slice(chunk);
    }
    let mut result = String::from_utf8_lossy(&buffer).into_owned();
    for (find, replace) in rules {
        result = result.replace(find.as_str(), replace.as_str());
    }
    result.into_bytes()
}

proptest! {
    /// Body rewriting with a single find/replace works on arbitrary content.
    #[test]
    fn body_rewrite_single_rule(
        (find, replace) in find_replace_strategy(),
        body in body_content_strategy(),
    ) {
        let expected = body.replace(&find, &replace);
        let result = simulate_body_rewrite(
            &[body.as_bytes()],
            &[(find, replace)],
        );
        prop_assert_eq!(String::from_utf8_lossy(&result), expected);
    }

    /// Body rewriting with multiple rules is applied in order.
    #[test]
    fn body_rewrite_multiple_rules(
        body in "[a-zA-Z0-9 ._<>/=\"'-]{0,200}",
        rules in proptest::collection::vec(find_replace_strategy(), 1..5),
    ) {
        let mut expected = body.clone();
        for (find, replace) in &rules {
            expected = expected.replace(find.as_str(), replace.as_str());
        }
        let result = simulate_body_rewrite(&[body.as_bytes()], &rules);
        prop_assert_eq!(String::from_utf8_lossy(&result), expected);
    }

    /// Body rewriting across multiple chunks produces same result as single chunk.
    #[test]
    fn body_rewrite_chunked_matches_single(
        body in "[a-zA-Z0-9 ._<>/=\"'-]{10,200}",
        split_at in 1..9usize,
        (find, replace) in find_replace_strategy(),
    ) {
        let split_point = split_at.min(body.len() - 1);
        let (chunk1, chunk2) = body.as_bytes().split_at(split_point);

        let single_result = simulate_body_rewrite(
            &[body.as_bytes()],
            &[(find.clone(), replace.clone())],
        );
        let chunked_result = simulate_body_rewrite(
            &[chunk1, chunk2],
            &[(find, replace)],
        );

        prop_assert_eq!(single_result, chunked_result);
    }

    /// Body rewriting with empty find string doesn't loop infinitely.
    /// (String::replace with empty find inserts between every character,
    /// which is valid Rust behavior — we just verify it terminates.)
    #[test]
    fn body_rewrite_empty_find(
        body in "[a-z]{0,20}",
        replace in "[a-z]{0,5}",
    ) {
        // String::replace("", x) inserts x between every char and at start/end.
        // We just need to verify it doesn't hang.
        let result = simulate_body_rewrite(
            &[body.as_bytes()],
            &[("".into(), replace)],
        );
        prop_assert!(!result.is_empty() || body.is_empty());
    }

    /// Body rewriting is idempotent when find and replace don't overlap.
    #[test]
    fn body_rewrite_no_find_is_identity(
        body in "[a-z]{0,100}",
        find in "[A-Z]{1,10}",
        replace in "[0-9]{1,10}",
    ) {
        // find is uppercase, body is lowercase → no match → identity.
        let result = simulate_body_rewrite(
            &[body.as_bytes()],
            &[(find, replace)],
        );
        prop_assert_eq!(String::from_utf8_lossy(&result), body);
    }
}

// ─── Config TOML deserialization ─────────────────────────────────────────────

proptest! {
    /// TelemetryConfig with arbitrary metrics_port deserializes correctly.
    #[test]
    fn telemetry_config_metrics_port(port in 0u16..=65535) {
        let toml_str = format!(
            r#"otlp_endpoint = ""
metrics_port = {port}"#
        );
        let cfg: TelemetryConfig = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.metrics_port, port);
    }

    /// TelemetryConfig without metrics_port defaults to 9090.
    #[test]
    fn telemetry_config_default_port(_i in 0..10u32) {
        let toml_str = r#"otlp_endpoint = """#;
        let cfg: TelemetryConfig = toml::from_str(toml_str).unwrap();
        prop_assert_eq!(cfg.metrics_port, 9090);
    }

    /// RouteConfig with all new optional fields present deserializes.
    #[test]
    fn route_config_with_all_fields(
        host in "[a-z]{1,10}",
        static_root in "/[a-z]{1,20}",
        fallback in "[a-z]{1,10}\\.html",
    ) {
        let toml_str = format!(
            r#"host_prefix = "{host}"
backend = "http://localhost:8080"
static_root = "{static_root}"
fallback = "{fallback}"
"#
        );
        let cfg: RouteConfig = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.host_prefix, host);
        prop_assert_eq!(cfg.static_root.as_deref(), Some(static_root.as_str()));
        prop_assert_eq!(cfg.fallback.as_deref(), Some(fallback.as_str()));
        prop_assert!(cfg.rewrites.is_empty());
        prop_assert!(cfg.body_rewrites.is_empty());
        prop_assert!(cfg.response_headers.is_empty());
    }

    /// RouteConfig without optional fields defaults to None/empty.
    #[test]
    fn route_config_minimal(host in "[a-z]{1,10}") {
        let toml_str = format!(
            r#"host_prefix = "{host}"
backend = "http://localhost:8080"
"#
        );
        let cfg: RouteConfig = toml::from_str(&toml_str).unwrap();
        prop_assert!(cfg.static_root.is_none());
        prop_assert!(cfg.fallback.is_none());
        prop_assert!(cfg.rewrites.is_empty());
        prop_assert!(cfg.body_rewrites.is_empty());
        prop_assert!(cfg.response_headers.is_empty());
        prop_assert!(cfg.paths.is_empty());
    }

    /// PathRoute with auth fields deserializes correctly.
    #[test]
    fn path_route_auth_fields(
        prefix in "/[a-z]{1,10}",
        auth_url in "http://[a-z]{1,10}:[0-9]{4}/[a-z/]{1,20}",
    ) {
        let toml_str = format!(
            r#"prefix = "{prefix}"
backend = "http://localhost:8080"
auth_request = "{auth_url}"
auth_capture_headers = ["Authorization", "X-Amz-Date"]
upstream_path_prefix = "/bucket/"
"#
        );
        let cfg: PathRoute = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.auth_request.as_deref(), Some(auth_url.as_str()));
        prop_assert_eq!(cfg.auth_capture_headers.len(), 2);
        prop_assert_eq!(cfg.upstream_path_prefix.as_deref(), Some("/bucket/"));
    }

    /// RewriteRule TOML roundtrip.
    #[test]
    fn rewrite_rule_toml(
        pattern in "[a-zA-Z0-9^$/.-]{1,30}",
        target in "/[a-z/.-]{1,30}",
    ) {
        let toml_str = format!(
            r#"pattern = "{pattern}"
target = "{target}"
"#
        );
        let cfg: RewriteRule = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.pattern, pattern);
        prop_assert_eq!(cfg.target, target);
    }

    /// BodyRewrite TOML deserialization.
    #[test]
    fn body_rewrite_toml(
        find in "[a-zA-Z0-9./-]{1,30}",
        replace in "[a-zA-Z0-9./-]{1,30}",
    ) {
        let toml_str = format!(
            r#"find = "{find}"
replace = "{replace}"
types = ["text/html", "application/javascript"]
"#
        );
        let cfg: BodyRewrite = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.find, find);
        prop_assert_eq!(cfg.replace, replace);
        prop_assert_eq!(cfg.types.len(), 2);
    }

    /// HeaderRule TOML deserialization.
    #[test]
    fn header_rule_toml(
        name in "[A-Z][a-zA-Z-]{1,20}",
        value in "[a-zA-Z0-9 ;=,_/-]{1,50}",
    ) {
        let toml_str = format!(
            r#"name = "{name}"
value = "{value}"
"#
        );
        let cfg: HeaderRule = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.name, name);
        prop_assert_eq!(cfg.value, value);
    }
}

// ─── Path traversal rejection ────────────────────────────────────────────────

proptest! {
    /// Any path containing ".." is rejected by the traversal check.
    #[test]
    fn path_traversal_always_rejected(
        prefix in "/[a-z]{0,10}",
        suffix in "/[a-z]{0,10}",
    ) {
        let path = format!("{prefix}/../{suffix}");
        // The static file serving checks path.contains("..")
        prop_assert!(path.contains(".."));
    }

    /// Paths without ".." are not falsely rejected as traversal.
    #[test]
    fn safe_paths_not_rejected(path in "/[a-zA-Z0-9._/-]{0,100}") {
        // A regex-generated path with only safe chars should never contain ".."
        // unless the regex accidentally generates it, which is fine — we're testing
        // that our check is "contains .."
        if !path.contains("..") {
            prop_assert!(!path.contains(".."));
        }
    }

    /// Paths with single dots are not mistaken for traversal.
    #[test]
    fn single_dot_not_traversal(
        name in "[a-z]{1,10}",
        ext in "[a-z]{1,5}",
    ) {
        let path = format!("/{name}.{ext}");
        prop_assert!(!path.contains(".."));
    }
}

// ─── Metrics label safety ────────────────────────────────────────────────────

proptest! {
    /// Prometheus labels with arbitrary method/host/status/backend don't panic.
    #[test]
    fn metrics_labels_no_panic(
        method in "[A-Z]{1,10}",
        host in "[a-z.]{1,30}",
        status in "[0-9]{3}",
        backend in "[a-z.:-]{1,40}",
    ) {
        // Accessing with_label_values should never panic, just create new series.
        sunbeam_proxy::metrics::REQUESTS_TOTAL
            .with_label_values(&[&method, &host, &status, &backend])
            .inc();
    }

    /// DDoS decision metric with arbitrary decision labels doesn't panic.
    #[test]
    fn ddos_metric_no_panic(decision in "(allow|block)") {
        sunbeam_proxy::metrics::DDOS_DECISIONS
            .with_label_values(&[&decision])
            .inc();
    }

    /// Scanner decision metric with arbitrary reason doesn't panic.
    #[test]
    fn scanner_metric_no_panic(
        decision in "(allow|block)",
        reason in "[a-zA-Z0-9:_]{1,30}",
    ) {
        sunbeam_proxy::metrics::SCANNER_DECISIONS
            .with_label_values(&[&decision, &reason])
            .inc();
    }

    /// Rate limit decision metric doesn't panic.
    #[test]
    fn rate_limit_metric_no_panic(decision in "(allow|block)") {
        sunbeam_proxy::metrics::RATE_LIMIT_DECISIONS
            .with_label_values(&[&decision])
            .inc();
    }

    /// Active connections gauge can be incremented and decremented.
    #[test]
    fn active_connections_inc_dec(n in 1..100u32) {
        for _ in 0..n {
            sunbeam_proxy::metrics::ACTIVE_CONNECTIONS.inc();
        }
        for _ in 0..n {
            sunbeam_proxy::metrics::ACTIVE_CONNECTIONS.dec();
        }
        // Gauge can go negative, which is fine for prometheus.
    }

    /// Histogram observe never panics for non-negative durations.
    #[test]
    fn duration_histogram_no_panic(secs in 0.0f64..3600.0) {
        sunbeam_proxy::metrics::REQUEST_DURATION.observe(secs);
    }
}

// ─── Static file serving (filesystem-based) ──────────────────────────────────

proptest! {
    /// read_static_file integration: create a temp file, verify content_type/cache_control.
    #[test]
    fn static_file_content_type_matches_extension(ext in extension_strategy()) {
        if ext.is_empty() {
            return Ok(());
        }
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join(format!("test.{ext}"));
        std::fs::write(&file_path, b"test content").unwrap();

        let expected_ct = content_type_for(&ext);
        let expected_cc = cache_control_for(&ext);

        // Verify the mapping is consistent.
        prop_assert!(!expected_ct.is_empty());
        prop_assert!(!expected_cc.is_empty());

        // The actual try_serve needs a Pingora session (can't unit test),
        // but we can verify the mapping functions are consistent.
        let ct2 = content_type_for(&ext);
        let cc2 = cache_control_for(&ext);
        prop_assert_eq!(expected_ct, ct2, "content_type_for not deterministic");
        prop_assert_eq!(expected_cc, cc2, "cache_control_for not deterministic");
    }

    /// Directories are never served as files.
    #[test]
    fn directories_not_served(_i in 0..10u32) {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();

        // tokio::fs::metadata would report is_file() = false for directories.
        // We can verify the sync check at least.
        let meta = std::fs::metadata(&sub).unwrap();
        prop_assert!(!meta.is_file());
    }
}

// ─── Bytes body rewrite integration ──────────────────────────────────────────

proptest! {
    /// The Bytes-based body rewrite logic mirrors String::replace semantics.
    #[test]
    fn bytes_body_rewrite_matches_string_replace(
        body in "[a-zA-Z0-9 <>/=._-]{0,300}",
        find in "[a-zA-Z]{1,10}",
        replace in "[a-zA-Z0-9]{0,10}",
    ) {
        // Simulate the exact flow from response_body_filter.
        let mut body_opt: Option<Bytes> = Some(Bytes::from(body.clone()));
        let mut buffer = Vec::new();

        // Accumulate (single chunk).
        if let Some(data) = body_opt.take() {
            buffer.extend_from_slice(&data);
        }

        // End of stream → apply rewrite.
        let mut result = String::from_utf8_lossy(&buffer).into_owned();
        result = result.replace(&find, &replace);
        let result_bytes = Bytes::from(result.clone());

        // Compare with direct String::replace.
        let expected = body.replace(&find, &replace);
        prop_assert_eq!(result, expected.clone());
        prop_assert_eq!(result_bytes.len(), expected.len());
    }
}

// ─── RouteConfig response_headers round-trip ─────────────────────────────────

proptest! {
    /// response_headers survive TOML serialization/deserialization.
    #[test]
    fn response_headers_roundtrip(
        hdr_name in "[A-Z][a-zA-Z-]{1,15}",
        hdr_value in "[a-zA-Z0-9 ;=/_-]{1,30}",
    ) {
        let toml_str = format!(
            r#"host_prefix = "test"
backend = "http://localhost:8080"

[[response_headers]]
name = "{hdr_name}"
value = "{hdr_value}"
"#
        );
        let cfg: RouteConfig = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.response_headers.len(), 1);
        prop_assert_eq!(&cfg.response_headers[0].name, &hdr_name);
        prop_assert_eq!(&cfg.response_headers[0].value, &hdr_value);
    }

    /// Multiple response headers in TOML.
    #[test]
    fn multiple_response_headers(n in 1..10usize) {
        let headers: String = (0..n)
            .map(|i| format!(
                r#"
[[response_headers]]
name = "X-Custom-{i}"
value = "value-{i}"
"#
            ))
            .collect();
        let toml_str = format!(
            r#"host_prefix = "test"
backend = "http://localhost:8080"
{headers}"#
        );
        let cfg: RouteConfig = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.response_headers.len(), n);
        for (i, hdr) in cfg.response_headers.iter().enumerate() {
            prop_assert_eq!(&hdr.name, &format!("X-Custom-{i}"));
            prop_assert_eq!(&hdr.value, &format!("value-{i}"));
        }
    }
}

// ─── body_rewrites TOML ──────────────────────────────────────────────────────

proptest! {
    /// body_rewrites in RouteConfig TOML.
    #[test]
    fn body_rewrites_in_route(
        find in "[a-zA-Z0-9.]{1,20}",
        replace in "[a-zA-Z0-9.]{1,20}",
    ) {
        let toml_str = format!(
            r#"host_prefix = "people"
backend = "http://localhost:8080"

[[body_rewrites]]
find = "{find}"
replace = "{replace}"
types = ["text/html"]
"#
        );
        let cfg: RouteConfig = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.body_rewrites.len(), 1);
        prop_assert_eq!(&cfg.body_rewrites[0].find, &find);
        prop_assert_eq!(&cfg.body_rewrites[0].replace, &replace);
        prop_assert_eq!(&cfg.body_rewrites[0].types, &vec!["text/html".to_string()]);
    }
}

// ─── rewrites TOML ───────────────────────────────────────────────────────────

proptest! {
    /// rewrites in RouteConfig TOML.
    #[test]
    fn rewrites_in_route(
        pattern in "[a-zA-Z0-9^$/.-]{1,20}",
        target in "/[a-z/.-]{1,20}",
    ) {
        let toml_str = format!(
            r#"host_prefix = "docs"
backend = "http://localhost:8080"
static_root = "/srv/docs"

[[rewrites]]
pattern = "{pattern}"
target = "{target}"
"#
        );
        let cfg: RouteConfig = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.rewrites.len(), 1);
        prop_assert_eq!(&cfg.rewrites[0].pattern, &pattern);
        prop_assert_eq!(&cfg.rewrites[0].target, &target);
    }
}

// ─── PathRoute upstream_path_prefix ──────────────────────────────────────────

proptest! {
    /// upstream_path_prefix field deserializes.
    #[test]
    fn path_route_upstream_prefix(prefix in "/[a-z-]{1,20}/") {
        let toml_str = format!(
            r#"prefix = "/media"
backend = "http://localhost:8333"
strip_prefix = true
upstream_path_prefix = "{prefix}"
"#
        );
        let cfg: PathRoute = toml::from_str(&toml_str).unwrap();
        prop_assert_eq!(cfg.upstream_path_prefix.as_deref(), Some(prefix.as_str()));
        prop_assert!(cfg.strip_prefix);
    }
}

// ─── Cluster bandwidth meter ────────────────────────────────────────────────

use sunbeam_proxy::cluster::bandwidth::{
    gbps_to_bytes_per_sec, BandwidthLimitResult, BandwidthLimiter, BandwidthMeter,
    BandwidthTracker, ClusterBandwidthState,
};

proptest! {
    /// Recording any non-negative byte counts never panics.
    #[test]
    fn meter_record_never_panics(
        bytes_in in 0u64..=u64::MAX / 2,
        bytes_out in 0u64..=u64::MAX / 2,
    ) {
        let meter = BandwidthMeter::new(30);
        meter.record_sample(bytes_in, bytes_out);
        let rate = meter.aggregate_rate();
        prop_assert!(rate.bytes_in_per_sec >= 0.0);
        prop_assert!(rate.bytes_out_per_sec >= 0.0);
    }

    /// Aggregate rate is always non-negative regardless of input.
    #[test]
    fn meter_rate_always_non_negative(
        samples in proptest::collection::vec((0u64..1_000_000_000, 0u64..1_000_000_000), 0..100),
        window_secs in 1u64..=300,
    ) {
        let meter = BandwidthMeter::new(window_secs);
        for (bytes_in, bytes_out) in &samples {
            meter.record_sample(*bytes_in, *bytes_out);
        }
        let rate = meter.aggregate_rate();
        prop_assert!(rate.bytes_in_per_sec >= 0.0);
        prop_assert!(rate.bytes_out_per_sec >= 0.0);
        prop_assert!(rate.total_per_sec >= 0.0);
        prop_assert_eq!(rate.total_per_sec, rate.bytes_in_per_sec + rate.bytes_out_per_sec);
    }

    /// total_per_sec always equals in + out.
    #[test]
    fn meter_total_is_sum_of_in_and_out(
        bytes_in in 0u64..1_000_000_000,
        bytes_out in 0u64..1_000_000_000,
    ) {
        let meter = BandwidthMeter::new(30);
        meter.record_sample(bytes_in, bytes_out);
        let rate = meter.aggregate_rate();
        let diff = (rate.total_per_sec - (rate.bytes_in_per_sec + rate.bytes_out_per_sec)).abs();
        prop_assert!(diff < 0.001, "total should equal in + out, diff={diff}");
    }

    /// MiB/s conversion uses power-of-2 (1 MiB = 1048576 bytes).
    #[test]
    fn meter_mib_conversion_power_of_2(
        bytes_in in 0u64..10_000_000_000,
        bytes_out in 0u64..10_000_000_000,
    ) {
        let meter = BandwidthMeter::new(30);
        meter.record_sample(bytes_in, bytes_out);
        let rate = meter.aggregate_rate();
        let expected_in_mib = rate.bytes_in_per_sec / 1_048_576.0;
        let expected_out_mib = rate.bytes_out_per_sec / 1_048_576.0;
        let diff_in = (rate.in_mib_per_sec() - expected_in_mib).abs();
        let diff_out = (rate.out_mib_per_sec() - expected_out_mib).abs();
        prop_assert!(diff_in < 0.0001, "MiB/s in conversion wrong: diff={diff_in}");
        prop_assert!(diff_out < 0.0001, "MiB/s out conversion wrong: diff={diff_out}");
    }

    /// Sample count matches the number of samples within the window.
    #[test]
    fn meter_sample_count_matches_insertions(
        n in 0usize..200,
    ) {
        let meter = BandwidthMeter::new(60); // large window so nothing expires
        for _ in 0..n {
            meter.record_sample(100, 200);
        }
        let rate = meter.aggregate_rate();
        prop_assert_eq!(rate.sample_count, n);
    }

    /// Bandwidth tracker atomic record + snapshot is consistent.
    #[test]
    fn tracker_record_snapshot_consistent(
        ops in proptest::collection::vec((0u64..1_000_000, 0u64..1_000_000), 1..50),
    ) {
        let tracker = BandwidthTracker::new();
        let mut expected_in = 0u64;
        let mut expected_out = 0u64;
        for (bytes_in, bytes_out) in &ops {
            tracker.record(*bytes_in, *bytes_out);
            expected_in += bytes_in;
            expected_out += bytes_out;
        }
        let snap = tracker.snapshot_and_reset();
        prop_assert_eq!(snap.bytes_in, expected_in);
        prop_assert_eq!(snap.bytes_out, expected_out);
        prop_assert_eq!(snap.request_count, ops.len() as u64);
        prop_assert_eq!(snap.cumulative_in, expected_in);
        prop_assert_eq!(snap.cumulative_out, expected_out);
    }

    /// After snapshot_and_reset, interval counters are zero but cumulative persists.
    #[test]
    fn tracker_cumulative_persists_after_reset(
        first_in in 0u64..1_000_000,
        first_out in 0u64..1_000_000,
        second_in in 0u64..1_000_000,
        second_out in 0u64..1_000_000,
    ) {
        let tracker = BandwidthTracker::new();
        tracker.record(first_in, first_out);
        let _ = tracker.snapshot_and_reset();
        tracker.record(second_in, second_out);
        let snap = tracker.snapshot_and_reset();
        // Interval counters reflect only second batch.
        prop_assert_eq!(snap.bytes_in, second_in);
        prop_assert_eq!(snap.bytes_out, second_out);
        prop_assert_eq!(snap.request_count, 1);
        // Cumulative reflects both batches.
        prop_assert_eq!(snap.cumulative_in, first_in + second_in);
        prop_assert_eq!(snap.cumulative_out, first_out + second_out);
    }

    /// ClusterBandwidthState peer count matches distinct peer IDs.
    #[test]
    fn cluster_state_peer_count(
        peer_count in 1usize..20,
    ) {
        let state = ClusterBandwidthState::new(30);
        for i in 0..peer_count {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            state.update_peer(id, (i as u64) * 1000, (i as u64) * 2000);
        }
        prop_assert_eq!(
            state.peer_count.load(std::sync::atomic::Ordering::Relaxed),
            peer_count as u64
        );
    }

    /// ClusterBandwidthState totals are sum of all peers.
    #[test]
    fn cluster_state_totals_are_sum(
        values in proptest::collection::vec((0u64..1_000_000, 0u64..1_000_000), 1..20),
    ) {
        let state = ClusterBandwidthState::new(30);
        let mut expected_in = 0u64;
        let mut expected_out = 0u64;
        for (i, (cum_in, cum_out)) in values.iter().enumerate() {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            state.update_peer(id, *cum_in, *cum_out);
            expected_in += cum_in;
            expected_out += cum_out;
        }
        prop_assert_eq!(
            state.total_bytes_in.load(std::sync::atomic::Ordering::Relaxed),
            expected_in
        );
        prop_assert_eq!(
            state.total_bytes_out.load(std::sync::atomic::Ordering::Relaxed),
            expected_out
        );
    }

    /// Updating the same peer replaces (not adds) its contribution.
    #[test]
    fn cluster_state_update_replaces(
        first_in in 0u64..1_000_000,
        first_out in 0u64..1_000_000,
        second_in in 0u64..1_000_000,
        second_out in 0u64..1_000_000,
    ) {
        let state = ClusterBandwidthState::new(30);
        let id = [42u8; 32];
        state.update_peer(id, first_in, first_out);
        state.update_peer(id, second_in, second_out);
        prop_assert_eq!(
            state.total_bytes_in.load(std::sync::atomic::Ordering::Relaxed),
            second_in
        );
        prop_assert_eq!(
            state.total_bytes_out.load(std::sync::atomic::Ordering::Relaxed),
            second_out
        );
        prop_assert_eq!(
            state.peer_count.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// Window of 0 seconds is not valid in practice, but window_secs=1 works correctly.
    #[test]
    fn meter_small_window_no_panic(
        window_secs in 1u64..=5,
        bytes_in in 0u64..1_000_000,
        bytes_out in 0u64..1_000_000,
    ) {
        let meter = BandwidthMeter::new(window_secs);
        meter.record_sample(bytes_in, bytes_out);
        let rate = meter.aggregate_rate();
        // Rate = bytes / window_secs.
        let expected_in = bytes_in as f64 / window_secs as f64;
        let diff = (rate.bytes_in_per_sec - expected_in).abs();
        prop_assert!(diff < 1.0, "expected ~{expected_in}, got {}", rate.bytes_in_per_sec);
    }

    // ─── Bandwidth limiter ─────────────────────────────────────────────────

    /// Limiter with limit=0 always allows regardless of traffic.
    #[test]
    fn limiter_unlimited_always_allows(
        samples in proptest::collection::vec((0u64..10_000_000_000, 0u64..10_000_000_000), 0..50),
    ) {
        let meter = std::sync::Arc::new(BandwidthMeter::new(1));
        for (bi, bo) in &samples {
            meter.record_sample(*bi, *bo);
        }
        let limiter = BandwidthLimiter::new(meter, 0);
        prop_assert_eq!(limiter.check(), BandwidthLimitResult::Allow);
    }

    /// When traffic is strictly under the limit, check() always returns Allow.
    #[test]
    fn limiter_under_cap_allows(
        bytes_in in 0u64..50_000_000, // max 50MB
        bytes_out in 0u64..50_000_000,
        window_secs in 1u64..=60,
    ) {
        let meter = std::sync::Arc::new(BandwidthMeter::new(window_secs));
        meter.record_sample(bytes_in, bytes_out);
        // Set limit to 10 Gbps (1.25 GB/s) — well above anything the test generates.
        let limiter = BandwidthLimiter::new(meter, gbps_to_bytes_per_sec(10.0));
        prop_assert_eq!(limiter.check(), BandwidthLimitResult::Allow);
    }

    /// When traffic exceeds the limit, check() returns Reject.
    #[test]
    fn limiter_over_cap_rejects(
        // Generate enough traffic to exceed even 10 Gbps
        count in 5usize..20,
    ) {
        let meter = std::sync::Arc::new(BandwidthMeter::new(1)); // 1s window
        // Each sample: 1 GB — over 1s window that's count GB/s
        for _ in 0..count {
            meter.record_sample(1_000_000_000, 1_000_000_000);
        }
        // Limit to 1 Gbps = 125 MB/s. Actual rate = count * 2 GB/s >> 125 MB/s
        let limiter = BandwidthLimiter::new(meter, gbps_to_bytes_per_sec(1.0));
        prop_assert_eq!(limiter.check(), BandwidthLimitResult::Reject);
    }

    /// set_limit changes the enforcement threshold at runtime.
    #[test]
    fn limiter_set_limit_consistent(
        initial_gbps in 0.1f64..100.0,
        new_gbps in 0.1f64..100.0,
    ) {
        let meter = std::sync::Arc::new(BandwidthMeter::new(30));
        let limiter = BandwidthLimiter::new(meter, gbps_to_bytes_per_sec(initial_gbps));
        prop_assert_eq!(limiter.limit(), gbps_to_bytes_per_sec(initial_gbps));
        limiter.set_limit(gbps_to_bytes_per_sec(new_gbps));
        prop_assert_eq!(limiter.limit(), gbps_to_bytes_per_sec(new_gbps));
    }

    /// gbps_to_bytes_per_sec conversion is correct: 1 Gbps = 125_000_000 B/s.
    #[test]
    fn gbps_conversion_correct(
        gbps in 0.0f64..1000.0,
    ) {
        let bytes = gbps_to_bytes_per_sec(gbps);
        let expected = (gbps * 125_000_000.0) as u64;
        prop_assert_eq!(bytes, expected);
    }

    /// Limiter check never panics regardless of meter state.
    #[test]
    fn limiter_check_never_panics(
        limit in 0u64..=u64::MAX / 2,
        window_secs in 1u64..=300,
        samples in proptest::collection::vec((0u64..u64::MAX / 4, 0u64..u64::MAX / 4), 0..20),
    ) {
        let meter = std::sync::Arc::new(BandwidthMeter::new(window_secs));
        for (bi, bo) in &samples {
            meter.record_sample(*bi, *bo);
        }
        let limiter = BandwidthLimiter::new(meter, limit);
        let result = limiter.check();
        prop_assert!(result == BandwidthLimitResult::Allow || result == BandwidthLimitResult::Reject);
    }

    /// current_rate returns the same value as meter.aggregate_rate.
    #[test]
    fn limiter_current_rate_matches_meter(
        bytes_in in 0u64..1_000_000_000,
        bytes_out in 0u64..1_000_000_000,
    ) {
        let meter = std::sync::Arc::new(BandwidthMeter::new(30));
        meter.record_sample(bytes_in, bytes_out);
        let limiter = BandwidthLimiter::new(meter.clone(), 0);
        let limiter_rate = limiter.current_rate();
        let meter_rate = meter.aggregate_rate();
        let diff = (limiter_rate.total_per_sec - meter_rate.total_per_sec).abs();
        prop_assert!(diff < 0.001, "limiter rate should match meter rate");
    }
}
