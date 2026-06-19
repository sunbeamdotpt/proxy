// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

/// Num scanner features.
pub const NUM_SCANNER_FEATURES: usize = 12;
/// Scannerfeaturevector.
pub type ScannerFeatureVector = [f64; NUM_SCANNER_FEATURES];
/// 12 features + 2 interaction terms + 1 bias
pub const NUM_SCANNER_WEIGHTS: usize = 15;

/// Suspicious extensions list.
pub const SUSPICIOUS_EXTENSIONS_LIST: &[&str] = &[
    ".php", ".env", ".sql", ".bak", ".asp", ".jsp", ".cgi", ".tar", ".zip", ".git",
];

const TRAVERSAL_PATTERNS: &[&str] = &["..", "%00", "%0a", "%27", "%3c"];

/// Extract all 12 scanner features from a single request.
/// No heap allocation — all work done on references and stack buffers.
#[allow(clippy::too_many_arguments)]
pub fn extract_features(
    method: &str,
    path: &str,
    host_prefix: &str,
    has_cookies: bool,
    has_referer: bool,
    has_accept_language: bool,
    accept: &str,
    user_agent: &str,
    content_length: u64,
    fragment_hashes: &FxHashSet<u64>,
    extension_hashes: &FxHashSet<u64>,
    configured_hosts: &FxHashSet<u64>,
) -> ScannerFeatureVector {
    [
        suspicious_path_score(path, fragment_hashes),
        path_depth(path),
        has_suspicious_extension(path, extension_hashes),
        if has_cookies { 1.0 } else { 0.0 },
        if has_referer { 1.0 } else { 0.0 },
        if has_accept_language { 1.0 } else { 0.0 },
        accept_quality(accept),
        ua_category(user_agent),
        method_is_unusual(method),
        host_is_configured(host_prefix, configured_hosts),
        content_length_mismatch(method, content_length),
        path_has_traversal(path),
    ]
}

/// Fraction of path segments matching known-bad fragment hashes.
fn suspicious_path_score(path: &str, fragment_hashes: &FxHashSet<u64>) -> f64 {
    let mut matches = 0u32;
    let mut segments = 0u32;
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        segments += 1;
        let mut buf = [0u8; 256];
        let len = segment.len().min(256);
        for (i, &b) in segment.as_bytes()[..len].iter().enumerate() {
            buf[i] = b.to_ascii_lowercase();
        }
        let hash = fx_hash_bytes(&buf[..len]);
        if fragment_hashes.contains(&hash) {
            matches += 1;
        }
    }
    if segments == 0 {
        0.0
    } else {
        matches as f64 / segments as f64
    }
}

/// Count '/' characters, capped at 20.
fn path_depth(path: &str) -> f64 {
    let depth = path.bytes().filter(|&b| b == b'/').count().min(20);
    depth as f64
}

/// Check if path ends with a suspicious file extension.
fn has_suspicious_extension(path: &str, extension_hashes: &FxHashSet<u64>) -> f64 {
    // Strip query string for extension check
    let clean = path.split('?').next().unwrap_or(path);
    for ext in SUSPICIOUS_EXTENSIONS_LIST {
        if clean.len() >= ext.len() {
            let suffix = &clean[clean.len() - ext.len()..];
            let hash = fx_hash_bytes(suffix.as_bytes());
            if extension_hashes.contains(&hash) {
                return 1.0;
            }
        }
    }
    0.0
}

fn accept_quality(accept: &str) -> f64 {
    if accept.is_empty() || accept == "-" || accept == "*/*" {
        return 0.0;
    }
    let lower = accept.to_ascii_lowercase();
    if lower.contains("text/html") || lower.contains("application/json") {
        1.0
    } else {
        0.0
    }
}

/// Returns true if the UA string looks like a real browser (Mozilla/Chrome/Safari).
pub fn ua_is_browser(ua: &str) -> bool {
    let lower = ua.to_ascii_lowercase();
    lower.contains("mozilla/") || lower.contains("chrome/") || lower.contains("safari/")
}

fn ua_category(ua: &str) -> f64 {
    if ua.is_empty() || ua == "-" {
        return 0.0;
    }
    let lower = ua.to_ascii_lowercase();
    if lower.starts_with("curl/")
        || lower.starts_with("wget/")
        || lower.starts_with("python")
        || lower.starts_with("go-http")
        || lower.starts_with("libwww")
    {
        return 0.25;
    }
    if lower.contains("mozilla/") || lower.contains("chrome/") || lower.contains("safari/") {
        return 1.0;
    }
    0.5
}

fn method_is_unusual(method: &str) -> f64 {
    match method {
        "GET" | "HEAD" | "POST" | "OPTIONS" => 0.0,
        _ => 1.0,
    }
}

fn host_is_configured(host_prefix: &str, configured_hosts: &FxHashSet<u64>) -> f64 {
    if host_prefix.is_empty() {
        return 0.0;
    }
    let hash = fx_hash_bytes(host_prefix.as_bytes());
    if configured_hosts.contains(&hash) {
        1.0
    } else {
        0.0
    }
}

fn content_length_mismatch(method: &str, content_length: u64) -> f64 {
    match method {
        "GET" | "HEAD" if content_length > 0 => 1.0,
        "POST" | "PUT" | "PATCH" if content_length == 0 => 1.0,
        _ => 0.0,
    }
}

fn path_has_traversal(path: &str) -> f64 {
    let lower = path.to_ascii_lowercase();
    for pattern in TRAVERSAL_PATTERNS {
        if lower.contains(pattern) {
            return 1.0;
        }
    }
    0.0
}

/// Num scanner features f32.
pub const NUM_SCANNER_FEATURES_F32: usize = NUM_SCANNER_FEATURES;
/// Scannerfeaturevectorf32.
pub type ScannerFeatureVectorF32 = [f32; NUM_SCANNER_FEATURES];

/// Same as `extract_features` but returns f32 for ensemble inference.
#[allow(clippy::too_many_arguments)]
pub fn extract_features_f32(
    method: &str,
    path: &str,
    host_prefix: &str,
    has_cookies: bool,
    has_referer: bool,
    has_accept_language: bool,
    accept: &str,
    user_agent: &str,
    content_length: u64,
    fragment_hashes: &FxHashSet<u64>,
    extension_hashes: &FxHashSet<u64>,
    configured_hosts: &FxHashSet<u64>,
) -> ScannerFeatureVectorF32 {
    let f64_features = extract_features(
        method,
        path,
        host_prefix,
        has_cookies,
        has_referer,
        has_accept_language,
        accept,
        user_agent,
        content_length,
        fragment_hashes,
        extension_hashes,
        configured_hosts,
    );
    let mut out = [0.0f32; NUM_SCANNER_FEATURES];
    for i in 0..NUM_SCANNER_FEATURES {
        out[i] = f64_features[i] as f32;
    }
    out
}

/// Fx hash bytes.
pub fn fx_hash_bytes(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = rustc_hash::FxHasher::default();
    bytes.hash(&mut h);
    h.finish()
}

#[derive(Debug, Clone, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
/// Scannernormparams.
pub struct ScannerNormParams {
    /// Mins.
    pub mins: [f64; NUM_SCANNER_FEATURES],
    /// Maxs.
    pub maxs: [f64; NUM_SCANNER_FEATURES],
}

impl ScannerNormParams {
    pub fn from_data(vectors: &[ScannerFeatureVector]) -> Self {
        let mut mins = [f64::MAX; NUM_SCANNER_FEATURES];
        let mut maxs = [f64::MIN; NUM_SCANNER_FEATURES];
        for v in vectors {
            for i in 0..NUM_SCANNER_FEATURES {
                mins[i] = mins[i].min(v[i]);
                maxs[i] = maxs[i].max(v[i]);
            }
        }
        Self { mins, maxs }
    }

    pub fn normalize(&self, v: &ScannerFeatureVector) -> ScannerFeatureVector {
        let mut out = [0.0; NUM_SCANNER_FEATURES];
        for i in 0..NUM_SCANNER_FEATURES {
            let range = self.maxs[i] - self.mins[i];
            out[i] = if range > 0.0 {
                ((v[i] - self.mins[i]) / range).clamp(0.0, 1.0)
            } else {
                0.0
            };
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fragment_hashes() -> FxHashSet<u64> {
        let fragments = [
            ".env",
            "wp-admin",
            "wp-login",
            "phpinfo",
            "phpmyadmin",
            ".git",
            "cgi-bin",
            "shell",
            ".htaccess",
            ".htpasswd",
        ];
        fragments
            .iter()
            .map(|f| fx_hash_bytes(f.as_bytes()))
            .collect()
    }

    fn make_extension_hashes() -> FxHashSet<u64> {
        SUSPICIOUS_EXTENSIONS_LIST
            .iter()
            .map(|e| fx_hash_bytes(e.as_bytes()))
            .collect()
    }

    fn make_configured_hosts() -> FxHashSet<u64> {
        ["test", "app", "api"]
            .iter()
            .map(|h| fx_hash_bytes(h.as_bytes()))
            .collect()
    }

    #[test]
    fn test_suspicious_path_score_known_fragment() {
        let hashes = make_fragment_hashes();
        let score = suspicious_path_score("/.env", &hashes);
        assert!(score > 0.0, "should detect .env: {score}");
    }

    #[test]
    fn test_suspicious_path_score_clean() {
        let hashes = make_fragment_hashes();
        let score = suspicious_path_score("/blog/hello-world", &hashes);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_path_depth() {
        assert_eq!(path_depth("/"), 1.0);
        assert_eq!(path_depth("/a/b/c"), 3.0);
        assert_eq!(path_depth("/a"), 1.0);
    }

    #[test]
    fn test_has_suspicious_extension() {
        let ext_hashes = make_extension_hashes();
        assert_eq!(has_suspicious_extension("/test.php", &ext_hashes), 1.0);
        assert_eq!(has_suspicious_extension("/test.html", &ext_hashes), 0.0);
        assert_eq!(has_suspicious_extension("/config.env", &ext_hashes), 1.0);
    }

    #[test]
    fn test_ua_category() {
        assert_eq!(ua_category(""), 0.0);
        assert_eq!(ua_category("-"), 0.0);
        assert_eq!(ua_category("curl/7.0"), 0.25);
        assert_eq!(ua_category("python-requests/2.28"), 0.25);
        assert_eq!(
            ua_category("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"),
            1.0
        );
        assert_eq!(ua_category("SomeRandomBot/1.0"), 0.5);
    }

    #[test]
    fn test_method_is_unusual() {
        assert_eq!(method_is_unusual("GET"), 0.0);
        assert_eq!(method_is_unusual("POST"), 0.0);
        assert_eq!(method_is_unusual("DELETE"), 1.0);
        assert_eq!(method_is_unusual("TRACE"), 1.0);
    }

    #[test]
    fn test_host_is_configured() {
        let hosts = make_configured_hosts();
        assert_eq!(host_is_configured("test", &hosts), 1.0);
        assert_eq!(host_is_configured("unknown", &hosts), 0.0);
    }

    #[test]
    fn test_content_length_mismatch() {
        assert_eq!(content_length_mismatch("GET", 100), 1.0);
        assert_eq!(content_length_mismatch("GET", 0), 0.0);
        assert_eq!(content_length_mismatch("POST", 0), 1.0);
        assert_eq!(content_length_mismatch("POST", 100), 0.0);
    }

    #[test]
    fn test_path_has_traversal() {
        assert_eq!(path_has_traversal("/etc/../passwd"), 1.0);
        assert_eq!(path_has_traversal("/normal/path"), 0.0);
        assert_eq!(path_has_traversal("/foo%00bar"), 1.0);
    }

    #[test]
    fn test_extract_features_returns_12() {
        let fh = make_fragment_hashes();
        let eh = make_extension_hashes();
        let ch = make_configured_hosts();
        let features = extract_features(
            "GET",
            "/blog/post",
            "test",
            true,
            true,
            true,
            "text/html",
            "Mozilla/5.0",
            0,
            &fh,
            &eh,
            &ch,
        );
        assert_eq!(features.len(), NUM_SCANNER_FEATURES);
    }

    #[test]
    fn test_norm_params_roundtrip() {
        let data = vec![
            [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            [1.0, 5.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
        ];
        let params = ScannerNormParams::from_data(&data);
        let mid = [0.5, 3.0, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5];
        let norm = params.normalize(&mid);
        assert!((norm[0] - 0.5).abs() < 1e-10);
        assert!((norm[1] - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_legitimate_path_with_php_substring_not_flagged() {
        let hashes = make_fragment_hashes();
        // "php-is-dead" is NOT a known fragment
        let score = suspicious_path_score("/blog/php-is-dead", &hashes);
        assert_eq!(
            score, 0.0,
            "legitimate path with 'php' substring should not match"
        );
    }
}
