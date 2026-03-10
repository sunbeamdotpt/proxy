use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sunbeam_proxy::config::RouteConfig;
use sunbeam_proxy::scanner::detector::ScannerDetector;
use sunbeam_proxy::scanner::features::{
    self, fx_hash_bytes, ScannerNormParams, NUM_SCANNER_FEATURES, NUM_SCANNER_WEIGHTS,
};
use sunbeam_proxy::scanner::model::ScannerModel;

fn make_detector() -> ScannerDetector {
    // Use realistic trained weights (from the base model)
    let mut weights = [0.0f64; NUM_SCANNER_WEIGHTS];
    weights[0] = 0.155;   // suspicious_path_score
    weights[1] = 0.039;   // path_depth
    weights[2] = 0.328;   // has_suspicious_extension
    weights[3] = -1.376;  // has_cookies
    weights[4] = -0.196;  // has_referer
    weights[5] = -0.590;  // has_accept_language
    weights[7] = -0.254;  // ua_category
    weights[8] = 0.023;   // method_is_unusual
    weights[11] = 0.001;  // path_has_traversal
    weights[12] = 0.155;  // interaction:path*no_cookies
    weights[13] = 1.051;  // interaction:no_host*no_lang
    weights[14] = 0.461;  // bias

    let model = ScannerModel {
        weights,
        threshold: 0.5,
        norm_params: ScannerNormParams {
            mins: [0.0; NUM_SCANNER_FEATURES],
            maxs: [1.0; NUM_SCANNER_FEATURES],
        },
        fragments: vec![
            ".env".into(), "wp-admin".into(), "wp-login".into(), "wp-includes".into(),
            "wp-content".into(), "xmlrpc".into(), "phpinfo".into(), "phpmyadmin".into(),
            "cgi-bin".into(), ".git".into(), ".htaccess".into(), ".htpasswd".into(),
            "config.".into(), "admin".into(), "actuator".into(), "telescope".into(),
            "debug".into(), "shell".into(), "eval-stdin".into(),
        ],
    };

    let routes = vec![
        RouteConfig {
            host_prefix: "admin".into(),
            backend: "http://127.0.0.1:8080".into(),
            websocket: false,
            disable_secure_redirection: false,
            paths: vec![],
        },
        RouteConfig {
            host_prefix: "src".into(),
            backend: "http://127.0.0.1:8081".into(),
            websocket: false,
            disable_secure_redirection: false,
            paths: vec![],
        },
        RouteConfig {
            host_prefix: "docs".into(),
            backend: "http://127.0.0.1:8082".into(),
            websocket: false,
            disable_secure_redirection: false,
            paths: vec![],
        },
    ];

    ScannerDetector::new(&model, &routes)
}

fn bench_check_normal_browser(c: &mut Criterion) {
    let detector = make_detector();
    c.bench_function("scanner::check normal_browser", |b| {
        b.iter(|| {
            detector.check(
                black_box("GET"),
                black_box("/blog/hello-world"),
                black_box("admin"),
                black_box(true),   // has_cookies
                black_box(true),   // has_referer
                black_box(true),   // has_accept_language
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
                black_box("unknown"),    // unknown host, no allowlist shortcut
                black_box(false),
                black_box(false),
                black_box(true),         // has accept-language
                black_box("application/json"),
                black_box("GitHub-Hookshot/abc123"),
                black_box(1024),
            )
        })
    });
}

fn bench_extract_features(c: &mut Criterion) {
    let fragment_hashes: rustc_hash::FxHashSet<u64> = [
        ".env", "wp-admin", "wp-login", "phpinfo", "phpmyadmin", "cgi-bin", ".git",
    ]
    .iter()
    .map(|f| fx_hash_bytes(f.as_bytes()))
    .collect();
    let extension_hashes: rustc_hash::FxHashSet<u64> = features::SUSPICIOUS_EXTENSIONS_LIST
        .iter()
        .map(|e| fx_hash_bytes(e.as_bytes()))
        .collect();
    let configured_hosts: rustc_hash::FxHashSet<u64> =
        ["admin", "src", "docs"].iter().map(|h| fx_hash_bytes(h.as_bytes())).collect();

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
);
criterion_main!(benches);
