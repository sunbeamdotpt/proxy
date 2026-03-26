// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Scanner detection tests.
//!
//! The detector uses ensemble inference (decision tree + MLP) with compiled-in
//! weights. These tests exercise the allowlist and ensemble classification paths.

use sunbeam_proxy::config::RouteConfig;
use sunbeam_proxy::scanner::detector::ScannerDetector;
use sunbeam_proxy::scanner::model::ScannerAction;

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
            cache: None,
            timeout_secs: None,
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
            cache: None,
            timeout_secs: None,
        },
    ]
}

fn make_detector() -> ScannerDetector {
    ScannerDetector::new(&test_routes())
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
