// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use sunbeam_proxy::config::RouteConfig;
use sunbeam_proxy::ensemble::mlp::mlp_predict_32;
use sunbeam_proxy::ensemble::scanner::scanner_ensemble_predict;
use sunbeam_proxy::ensemble::tree::tree_predict;
use sunbeam_proxy::ensemble::weights::scanner_weights;
use sunbeam_proxy::scanner::detector::ScannerDetector;
use sunbeam_proxy::scanner::features::{self, fx_hash_bytes};

fn make_detector() -> ScannerDetector {
    let routes = vec![
        RouteConfig {
            host_prefix: "admin".into(),
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
        },
        RouteConfig {
            host_prefix: "src".into(),
            backend: "http://127.0.0.1:8081".into(),
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
        },
        RouteConfig {
            host_prefix: "docs".into(),
            backend: "http://127.0.0.1:8082".into(),
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
        },
    ];

    ScannerDetector::new(&routes)
}

fn bench_check_normal_browser(c: &mut Criterion) {
    let detector = make_detector();
    c.bench_function("scanner::check normal_browser", |b| {
        b.iter(|| {
            detector.check(
                black_box("GET"),
                black_box("/blog/hello-world"),
                black_box("admin"),
                black_box(true),
                black_box(true),
                black_box(true),
                black_box("text/html,application/xhtml+xml"),
                black_box("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"),
                black_box(0),
            )
        })
    });
}

fn bench_check_allowlist_host_cookies(c: &mut Criterion) {
    let detector = make_detector();
    c.bench_function("scanner::check allowlist:host+cookies", |b| {
        b.iter(|| {
            detector.check(
                black_box("POST"),
                black_box("/api/v1/data"),
                black_box("src"),
                black_box(true),
                black_box(false),
                black_box(true),
                black_box("application/json"),
                black_box("MyApp/2.0"),
                black_box(256),
            )
        })
    });
}

fn bench_check_scanner_env_probe(c: &mut Criterion) {
    let detector = make_detector();
    c.bench_function("scanner::check env_probe (block)", |b| {
        b.iter(|| {
            detector.check(
                black_box("GET"),
                black_box("/.env"),
                black_box("unknown"),
                black_box(false),
                black_box(false),
                black_box(false),
                black_box("*/*"),
                black_box("curl/7.0"),
                black_box(0),
            )
        })
    });
}

fn bench_check_wordpress_scan(c: &mut Criterion) {
    let detector = make_detector();
    c.bench_function("scanner::check wp_scan (block)", |b| {
        b.iter(|| {
            detector.check(
                black_box("GET"),
                black_box("/wp-admin/install.php"),
                black_box("random"),
                black_box(false),
                black_box(false),
                black_box(false),
                black_box("*/*"),
                black_box(""),
                black_box(0),
            )
        })
    });
}

fn bench_check_path_traversal(c: &mut Criterion) {
    let detector = make_detector();
    c.bench_function("scanner::check path_traversal (block)", |b| {
        b.iter(|| {
            detector.check(
                black_box("GET"),
                black_box("/etc/../../../passwd"),
                black_box("unknown"),
                black_box(false),
                black_box(false),
                black_box(false),
                black_box("*/*"),
                black_box("python-requests/2.28"),
                black_box(0),
            )
        })
    });
}

fn bench_check_deep_path(c: &mut Criterion) {
    let detector = make_detector();
    c.bench_function("scanner::check deep_path (10 segments)", |b| {
        b.iter(|| {
            detector.check(
                black_box("GET"),
                black_box("/a/b/c/d/e/f/g/h/i/j"),
                black_box("unknown"),
                black_box(false),
                black_box(false),
                black_box(false),
                black_box("*/*"),
                black_box("Go-http-client/1.1"),
                black_box(0),
            )
        })
    });
}

fn bench_check_api_legitimate(c: &mut Criterion) {
    let detector = make_detector();
    c.bench_function("scanner::check api_legit (model path, allow)", |b| {
        b.iter(|| {
            detector.check(
                black_box("POST"),
                black_box("/api/webhooks/github"),
                black_box("unknown"),
                black_box(false),
                black_box(false),
                black_box(true),
                black_box("application/json"),
                black_box("GitHub-Hookshot/abc123"),
                black_box(1024),
            )
        })
    });
}

fn bench_extract_features(c: &mut Criterion) {
    let fragment_hashes: rustc_hash::FxHashSet<u64> = [
        ".env",
        "wp-admin",
        "wp-login",
        "phpinfo",
        "phpmyadmin",
        "cgi-bin",
        ".git",
    ]
    .iter()
    .map(|f| fx_hash_bytes(f.as_bytes()))
    .collect();
    let extension_hashes: rustc_hash::FxHashSet<u64> = features::SUSPICIOUS_EXTENSIONS_LIST
        .iter()
        .map(|e| fx_hash_bytes(e.as_bytes()))
        .collect();
    let configured_hosts: rustc_hash::FxHashSet<u64> = ["admin", "src", "docs"]
        .iter()
        .map(|h| fx_hash_bytes(h.as_bytes()))
        .collect();

    c.bench_function("scanner::extract_features", |b| {
        b.iter(|| {
            features::extract_features(
                black_box("GET"),
                black_box("/wp-admin/install.php"),
                black_box("unknown"),
                black_box(false),
                black_box(false),
                black_box(false),
                black_box("*/*"),
                black_box("Mozilla/5.0 Chrome/120"),
                black_box(0),
                black_box(&fragment_hashes),
                black_box(&extension_hashes),
                black_box(&configured_hosts),
            )
        })
    });
}

fn bench_ensemble_scanner_full(c: &mut Criterion) {
    let raw: [f32; 12] = [0.8, 3.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0, 1.0];
    c.bench_function("ensemble::scanner full predict", |b| {
        b.iter(|| scanner_ensemble_predict(black_box(&raw)))
    });
}

fn bench_ensemble_scanner_tree_only(c: &mut Criterion) {
    let input: [f32; 12] = [0.8, 0.3, 1.0, 0.0, 0.0, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0, 1.0];
    c.bench_function("ensemble::scanner tree_only", |b| {
        b.iter(|| tree_predict(black_box(&scanner_weights::TREE_NODES), black_box(&input)))
    });
}

fn bench_ensemble_scanner_mlp_only(c: &mut Criterion) {
    let input: [f32; 12] = [0.5; 12];
    c.bench_function("ensemble::scanner mlp_only", |b| {
        b.iter(|| {
            mlp_predict_32::<12>(
                black_box(&scanner_weights::W1),
                black_box(&scanner_weights::B1),
                black_box(&scanner_weights::W2),
                black_box(scanner_weights::B2),
                black_box(&input),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_check_normal_browser,
    bench_check_allowlist_host_cookies,
    bench_check_scanner_env_probe,
    bench_check_wordpress_scan,
    bench_check_path_traversal,
    bench_check_deep_path,
    bench_check_api_legitimate,
    bench_extract_features,
    bench_ensemble_scanner_full,
    bench_ensemble_scanner_tree_only,
    bench_ensemble_scanner_mlp_only,
);
criterion_main!(benches);
