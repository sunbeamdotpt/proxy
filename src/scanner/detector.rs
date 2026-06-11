// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use crate::config::RouteConfig;
use crate::scanner::features::{self, fx_hash_bytes, SUSPICIOUS_EXTENSIONS_LIST};
use crate::scanner::model::{ScannerAction, ScannerVerdict};
use rustc_hash::FxHashSet;

/// Immutable, zero-state per-request scanner detector.
/// Safe to share across threads via `Arc<ScannerDetector>` with no locks.
pub struct ScannerDetector {
    fragment_hashes: FxHashSet<u64>,
    extension_hashes: FxHashSet<u64>,
    configured_hosts: FxHashSet<u64>,
}

impl ScannerDetector {
    pub fn new(routes: &[RouteConfig]) -> Self {
        let fragment_hashes: FxHashSet<u64> = crate::scanner::train::DEFAULT_FRAGMENTS
            .iter()
            .map(|f| fx_hash_bytes(f.to_ascii_lowercase().as_bytes()))
            .collect();

        let extension_hashes: FxHashSet<u64> = SUSPICIOUS_EXTENSIONS_LIST
            .iter()
            .map(|e| fx_hash_bytes(e.as_bytes()))
            .collect();

        let configured_hosts: FxHashSet<u64> = routes
            .iter()
            .map(|r| fx_hash_bytes(r.host_prefix.as_bytes()))
            .collect();

        Self {
            fragment_hashes,
            extension_hashes,
            configured_hosts,
        }
    }

    /// Classify a single request. ~200ns, no heap allocation, no state mutation.
    ///
    /// Returns a verdict with the action, raw score, and reason.
    /// The score and reason are captured in pipeline logs so the training
    /// pipeline always has unfiltered data to retrain from.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        method: &str,
        path: &str,
        host_prefix: &str,
        has_cookies: bool,
        has_referer: bool,
        has_accept_language: bool,
        accept: &str,
        user_agent: &str,
        content_length: u64,
    ) -> ScannerVerdict {
        // Hard allowlist: obviously legitimate traffic bypasses the model.
        let host_known = {
            let hash = features::fx_hash_bytes(host_prefix.as_bytes());
            self.configured_hosts.contains(&hash)
        };

        if host_known && has_cookies {
            return ScannerVerdict {
                action: ScannerAction::Allow,
                score: -1.0,
                reason: "allowlist:host+cookies",
            };
        }

        if host_known && has_accept_language && features::ua_is_browser(user_agent) {
            return ScannerVerdict {
                action: ScannerAction::Allow,
                score: -1.0,
                reason: "allowlist:host+browser",
            };
        }

        // Ensemble path: extract f32 features → decision tree + MLP.
        let raw_f32 = features::extract_features_f32(
            method, path, host_prefix,
            has_cookies, has_referer, has_accept_language,
            accept, user_agent, content_length,
            &self.fragment_hashes, &self.extension_hashes, &self.configured_hosts,
        );
        let ev = crate::ensemble::scanner::scanner_ensemble_predict(&raw_f32);
        crate::metrics::SCANNER_ENSEMBLE_PATH
            .with_label_values(&[match ev.path {
                crate::ensemble::scanner::EnsemblePath::TreeBlock => "tree_block",
                crate::ensemble::scanner::EnsemblePath::TreeAllow => "tree_allow",
                crate::ensemble::scanner::EnsemblePath::Mlp => "mlp",
            }])
            .inc();
        ev.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteConfig;

    fn test_routes() -> Vec<RouteConfig> {
        vec![RouteConfig {
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
        }]
    }

    #[test]
    fn test_normal_browser_request_allowed() {
        let detector = ScannerDetector::new(&test_routes());
        let verdict = detector.check(
            "GET",
            "/blog/hello-world",
            "app",
            true,  // has_cookies
            true,  // has_referer
            true,  // has_accept_language
            "text/html,application/xhtml+xml",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
            0,
        );
        assert_eq!(verdict.action, ScannerAction::Allow);
        assert_eq!(verdict.reason, "allowlist:host+cookies");
    }

    #[test]
    fn test_api_client_with_auth_allowed() {
        let detector = ScannerDetector::new(&test_routes());
        let verdict = detector.check(
            "POST",
            "/api/v1/data",
            "app",
            true,  // has_cookies (session cookie)
            false,
            true,
            "application/json",
            "MyApp/2.0",
            256,
        );
        assert_eq!(verdict.action, ScannerAction::Allow);
        assert_eq!(verdict.reason, "allowlist:host+cookies");
    }

    #[test]
    fn test_env_probe_blocked() {
        let detector = ScannerDetector::new(&test_routes());
        let verdict = detector.check(
            "GET",
            "/.env",
            "unknown",
            false,
            false,
            false,
            "*/*",
            "curl/7.0",
            0,
        );
        assert_eq!(verdict.action, ScannerAction::Block);
    }

    #[test]
    fn test_allowlist_browser_on_known_host() {
        let detector = ScannerDetector::new(&test_routes());
        let verdict = detector.check(
            "GET",
            "/",
            "app",
            false,
            false,
            true,
            "text/html",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537.36",
            0,
        );
        assert_eq!(verdict.action, ScannerAction::Allow);
        assert_eq!(verdict.reason, "allowlist:host+browser");
    }
}
