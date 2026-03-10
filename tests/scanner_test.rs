use sunbeam_proxy::config::RouteConfig;
use sunbeam_proxy::scanner::detector::ScannerDetector;
use sunbeam_proxy::scanner::features::{
    ScannerNormParams, NUM_SCANNER_FEATURES, NUM_SCANNER_WEIGHTS,
};
use sunbeam_proxy::scanner::model::{ScannerAction, ScannerModel};

fn test_routes() -> Vec<RouteConfig> {
    vec![
        RouteConfig {
            host_prefix: "app".into(),
            backend: "http://127.0.0.1:8080".into(),
            websocket: false,
            disable_secure_redirection: false,
            paths: vec![],
            static_root: None,
            fallback: None,
            rewrites: vec![],
            body_rewrites: vec![],
            response_headers: vec![],
        },
        RouteConfig {
            host_prefix: "api".into(),
            backend: "http://127.0.0.1:8081".into(),
            websocket: false,
            disable_secure_redirection: false,
            paths: vec![],
            static_root: None,
            fallback: None,
            rewrites: vec![],
            body_rewrites: vec![],
            response_headers: vec![],
        },
    ]
}

fn scanner_weights() -> [f64; NUM_SCANNER_WEIGHTS] {
    let mut w = [0.0; NUM_SCANNER_WEIGHTS];
    w[0] = 2.0;   // suspicious_path_score
    w[2] = 2.0;   // has_suspicious_extension
    w[3] = -2.0;  // has_cookies (negative = good)
    w[4] = -1.0;  // has_referer
    w[5] = -1.0;  // has_accept_language
    w[6] = -0.5;  // accept_quality
    w[7] = -1.0;  // ua_category (browser = good)
    w[9] = -1.5;  // host_is_configured
    w[11] = 2.0;  // path_has_traversal
    w[12] = 1.5;  // interaction: suspicious_path AND no_cookies
    w[13] = 1.0;  // interaction: unknown_host AND no_accept_lang
    w[14] = 0.5;  // bias
    w
}

fn make_detector() -> ScannerDetector {
    let model = ScannerModel {
        weights: scanner_weights(),
        threshold: 0.5,
        norm_params: ScannerNormParams {
            mins: [0.0; NUM_SCANNER_FEATURES],
            maxs: [1.0; NUM_SCANNER_FEATURES],
        },
        fragments: vec![
            ".env".into(),
            "wp-admin".into(),
            "wp-login".into(),
            "phpinfo".into(),
            "phpmyadmin".into(),
            ".git".into(),
            "cgi-bin".into(),
            ".htaccess".into(),
            ".htpasswd".into(),
        ],
    };
    ScannerDetector::new(&model, &test_routes())
}

#[test]
fn normal_browser_with_cookies_allowed() {
    let d = make_detector();
    let v = d.check(
        "GET", "/blog/hello-world", "app",
        true, true, true,
        "text/html,application/xhtml+xml",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        0,
    );
    assert_eq!(v.action, ScannerAction::Allow);
    assert_eq!(v.reason, "allowlist:host+cookies");
}

#[test]
fn api_client_with_auth_allowed() {
    let d = make_detector();
    let v = d.check(
        "POST", "/api/v1/users", "api",
        true, false, true,
        "application/json",
        "MyApp/2.0",
        256,
    );
    assert_eq!(v.action, ScannerAction::Allow);
    assert_eq!(v.reason, "allowlist:host+cookies");
}

#[test]
fn env_probe_from_unknown_host_blocked() {
    let d = make_detector();
    let v = d.check(
        "GET", "/.env", "unknown",
        false, false, false,
        "*/*", "curl/7.0", 0,
    );
    assert_eq!(v.action, ScannerAction::Block);
    assert_eq!(v.reason, "model");
}

#[test]
fn wordpress_scan_blocked() {
    let d = make_detector();
    let v = d.check(
        "GET", "/wp-admin/install.php", "unknown",
        false, false, false,
        "*/*", "", 0,
    );
    assert_eq!(v.action, ScannerAction::Block);
    assert_eq!(v.reason, "model");
}

#[test]
fn path_traversal_blocked() {
    let d = make_detector();
    let v = d.check(
        "GET", "/etc/../../../passwd", "unknown",
        false, false, false,
        "*/*", "python-requests/2.28", 0,
    );
    assert_eq!(v.action, ScannerAction::Block);
    assert_eq!(v.reason, "model");
}

#[test]
fn legitimate_php_path_allowed() {
    let d = make_detector();
    let v = d.check(
        "GET", "/blog/php-is-dead", "app",
        true, true, true,
        "text/html", "Mozilla/5.0 Chrome/120", 0,
    );
    assert_eq!(v.action, ScannerAction::Allow);
    // hits allowlist:host+cookies
}

#[test]
fn browser_on_known_host_without_cookies_allowed() {
    let d = make_detector();
    let v = d.check(
        "GET", "/", "app",
        false, false, true,
        "text/html",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537.36",
        0,
    );
    assert_eq!(v.action, ScannerAction::Allow);
    assert_eq!(v.reason, "allowlist:host+browser");
}

#[test]
fn model_serialization_roundtrip() {
    let model = ScannerModel {
        weights: scanner_weights(),
        threshold: 0.5,
        norm_params: ScannerNormParams {
            mins: [0.0; NUM_SCANNER_FEATURES],
            maxs: [1.0; NUM_SCANNER_FEATURES],
        },
        fragments: vec![".env".into(), "wp-admin".into()],
    };

    let dir = std::env::temp_dir().join("scanner_e2e_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_scanner_model.bin");

    model.save(&path).unwrap();
    let loaded = ScannerModel::load(&path).unwrap();

    assert_eq!(loaded.weights, model.weights);
    assert_eq!(loaded.threshold, model.threshold);
    assert_eq!(loaded.fragments, model.fragments);

    let _ = std::fs::remove_dir_all(&dir);
}
