use crate::config::RouteConfig;
use crate::scanner::features::{
    self, fx_hash_bytes, ScannerNormParams, SUSPICIOUS_EXTENSIONS_LIST, NUM_SCANNER_FEATURES,
    NUM_SCANNER_WEIGHTS,
};
use crate::scanner::model::{ScannerAction, ScannerModel, ScannerVerdict};
use rustc_hash::FxHashSet;

/// Immutable, zero-state per-request scanner detector.
/// Safe to share across threads via `Arc<ScannerDetector>` with no locks.
pub struct ScannerDetector {
    fragment_hashes: FxHashSet<u64>,
    extension_hashes: FxHashSet<u64>,
    configured_hosts: FxHashSet<u64>,
    weights: [f64; NUM_SCANNER_WEIGHTS],
    threshold: f64,
    norm_params: ScannerNormParams,
    use_ensemble: bool,
}

impl ScannerDetector {
    pub fn new(model: &ScannerModel, routes: &[RouteConfig]) -> Self {
        let fragment_hashes: FxHashSet<u64> = model
            .fragments
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
            weights: model.weights,
            threshold: model.threshold,
            norm_params: model.norm_params.clone(),
            use_ensemble: false,
        }
    }

    /// Create a detector that uses the ensemble (decision tree + MLP) path
    /// instead of the linear model. No model file needed — weights are compiled in.
    pub fn new_ensemble(routes: &[RouteConfig]) -> Self {
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
            weights: [0.0; NUM_SCANNER_WEIGHTS],
            threshold: 0.5,
            norm_params: ScannerNormParams {
                mins: [0.0; NUM_SCANNER_FEATURES],
                maxs: [1.0; NUM_SCANNER_FEATURES],
            },
            use_ensemble: true,
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
        // This prevents model drift from ever blocking real users and ensures
        // the training pipeline always has clean positive labels.
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

        if self.use_ensemble {
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
            return ev.into();
        }

        // 1. Extract 12 features
        let raw = features::extract_features(
            method,
            path,
            host_prefix,
            has_cookies,
            has_referer,
            has_accept_language,
            accept,
            user_agent,
            content_length,
            &self.fragment_hashes,
            &self.extension_hashes,
            &self.configured_hosts,
        );

        // 2. Normalize
        let f = self.norm_params.normalize(&raw);

        // 3. Compute score = bias + dot(weights, features) + interaction terms
        let mut score = self.weights[NUM_SCANNER_FEATURES + 2]; // bias (index 14)
        for (i, &fi) in f.iter().enumerate().take(NUM_SCANNER_FEATURES) {
            score += self.weights[i] * fi;
        }
        // Interaction: suspicious_path AND no_cookies
        score += self.weights[12] * f[0] * (1.0 - f[3]);
        // Interaction: unknown_host AND no_accept_language
        score += self.weights[13] * (1.0 - f[9]) * (1.0 - f[5]);

        // 4. Threshold
        let action = if score > self.threshold {
            ScannerAction::Block
        } else {
            ScannerAction::Allow
        };

        ScannerVerdict {
            action,
            score,
            reason: "model",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::features::NUM_SCANNER_FEATURES;

    fn make_detector(weights: [f64; NUM_SCANNER_WEIGHTS], threshold: f64) -> ScannerDetector {
        let model = ScannerModel {
            weights,
            threshold,
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
        let routes = vec![RouteConfig {
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
        }];
        ScannerDetector::new(&model, &routes)
    }

    /// Weights tuned to block scanner-like requests:
    /// High weight on suspicious_path (w[0]), no_cookies interaction (w[12]),
    /// has_suspicious_extension (w[2]), traversal (w[11]).
    /// Negative weight on has_cookies (w[3]), has_referer (w[4]),
    /// accept_quality (w[6]), ua_category (w[7]), host_is_configured (w[9]).
    fn attack_tuned_weights() -> [f64; NUM_SCANNER_WEIGHTS] {
        let mut w = [0.0; NUM_SCANNER_WEIGHTS];
        w[0] = 2.0;  // suspicious_path_score
        w[2] = 2.0;  // has_suspicious_extension
        w[3] = -2.0; // has_cookies (negative = good)
        w[4] = -1.0; // has_referer (negative = good)
        w[5] = -1.0; // has_accept_language (negative = good)
        w[6] = -0.5; // accept_quality (negative = good)
        w[7] = -1.0; // ua_category (negative = browser is good)
        w[9] = -1.5; // host_is_configured (negative = known host is good)
        w[11] = 2.0; // path_has_traversal
        w[12] = 1.5; // interaction: suspicious_path AND no_cookies
        w[13] = 1.0; // interaction: unknown_host AND no_accept_lang
        w[14] = 0.5; // bias
        w
    }

    #[test]
    fn test_normal_browser_request_allowed() {
        let detector = make_detector(attack_tuned_weights(), 0.5);
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
        let detector = make_detector(attack_tuned_weights(), 0.5);
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
        let detector = make_detector(attack_tuned_weights(), 0.5);
        let verdict = detector.check(
            "GET",
            "/.env",
            "unknown",
            false, // no cookies
            false, // no referer
            false, // no accept-language
            "*/*",
            "curl/7.0",
            0,
        );
        assert_eq!(verdict.action, ScannerAction::Block);
        assert_eq!(verdict.reason, "model");
    }

    #[test]
    fn test_wordpress_scan_blocked() {
        let detector = make_detector(attack_tuned_weights(), 0.5);
        let verdict = detector.check(
            "GET",
            "/wp-admin/install.php",
            "unknown",
            false,
            false,
            false,
            "*/*",
            "",
            0,
        );
        assert_eq!(verdict.action, ScannerAction::Block);
        assert_eq!(verdict.reason, "model");
    }

    #[test]
    fn test_path_traversal_blocked() {
        let detector = make_detector(attack_tuned_weights(), 0.5);
        let verdict = detector.check(
            "GET",
            "/etc/../../../passwd",
            "unknown",
            false,
            false,
            false,
            "*/*",
            "python-requests/2.28",
            0,
        );
        assert_eq!(verdict.action, ScannerAction::Block);
        assert_eq!(verdict.reason, "model");
    }

    #[test]
    fn test_legitimate_php_path_allowed() {
        let detector = make_detector(attack_tuned_weights(), 0.5);
        // "/blog/php-is-dead" — "php-is-dead" is not a known fragment
        // has_cookies=true + known host "app" → hits allowlist
        let verdict = detector.check(
            "GET",
            "/blog/php-is-dead",
            "app",
            true,
            true,
            true,
            "text/html",
            "Mozilla/5.0 Chrome/120",
            0,
        );
        assert_eq!(verdict.action, ScannerAction::Allow);
    }

    #[test]
    fn test_allowlist_browser_on_known_host() {
        let detector = make_detector(attack_tuned_weights(), 0.5);
        // No cookies but browser UA + accept-language + known host → allowlist
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

    #[test]
    fn test_model_path_for_non_allowlisted() {
        let detector = make_detector(attack_tuned_weights(), 0.5);
        // Unknown host, no cookies, curl UA → goes through model
        let verdict = detector.check(
            "GET",
            "/robots.txt",
            "unknown",
            false,
            false,
            false,
            "*/*",
            "curl/7.0",
            0,
        );
        assert_eq!(verdict.reason, "model");
    }
}
