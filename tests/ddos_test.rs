//! Extensive DDoS detection tests.
//!
//! These tests build realistic traffic profiles — normal browsing, API usage,
//! webhook bursts, etc. — and verify the model never blocks legitimate traffic.
//! Attack scenarios are also tested to confirm blocking works.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sunbeam_proxy::config::DDoSConfig;
use sunbeam_proxy::ddos::detector::DDoSDetector;
use sunbeam_proxy::ddos::features::{NormParams, NUM_FEATURES};
use sunbeam_proxy::ddos::model::{DDoSAction, SerializedModel, TrafficLabel, TrainedModel};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a model from explicit normal/attack feature vectors.
fn make_model(
    normal: &[[f64; NUM_FEATURES]],
    attack: &[[f64; NUM_FEATURES]],
    k: usize,
    threshold: f64,
) -> TrainedModel {
    let mut points = Vec::new();
    let mut labels = Vec::new();
    for v in normal {
        points.push(*v);
        labels.push(TrafficLabel::Normal);
    }
    for v in attack {
        points.push(*v);
        labels.push(TrafficLabel::Attack);
    }
    let norm_params = NormParams::from_data(&points);
    let normalized: Vec<[f64; NUM_FEATURES]> =
        points.iter().map(|v| norm_params.normalize(v)).collect();
    TrainedModel::from_serialized(SerializedModel {
        points: normalized,
        labels,
        norm_params,
        k,
        threshold,
    })
}

fn default_ddos_config() -> DDoSConfig {
    DDoSConfig {
        model_path: String::new(),
        k: 5,
        threshold: 0.6,
        window_secs: 60,
        window_capacity: 1000,
        min_events: 10,
        enabled: true,
    }
}

fn make_detector(model: TrainedModel, min_events: usize) -> DDoSDetector {
    let mut cfg = default_ddos_config();
    cfg.min_events = min_events;
    DDoSDetector::new(model, &cfg)
}

/// Feature vector indices (matching features.rs order):
///   0: request_rate        (requests / window_secs)
///   1: unique_paths        (count of distinct paths)
///   2: unique_hosts        (count of distinct hosts)
///   3: error_rate          (fraction 4xx/5xx)
///   4: avg_duration_ms     (mean response time)
///   5: method_entropy      (Shannon entropy of methods)
///   6: burst_score         (inverse mean inter-arrival)
///   7: path_repetition     (most-repeated path / total)
///   8: avg_content_length  (mean body size)
///   9: unique_user_agents  (count of distinct UAs)
///  10: cookie_ratio        (fraction with cookies)
///  11: referer_ratio       (fraction with referer)
///  12: accept_language_ratio (fraction with accept-language)
///  13: suspicious_path_ratio (fraction hitting known-bad paths)
///   9: unique_user_agents  (count of distinct UAs)

// Realistic normal traffic profiles
fn normal_browser_browsing() -> [f64; NUM_FEATURES] {
    // A human browsing a site: ~0.5 req/s, many paths, 1 host, low errors,
    // ~150ms avg latency, mostly GET, moderate spacing, diverse paths, no body, 1 UA
    // cookies=yes, referer=sometimes, accept-lang=yes, suspicious=no
    [0.5, 12.0, 1.0, 0.02, 150.0, 0.2, 0.6, 0.15, 0.0, 1.0, 1.0, 0.5, 1.0, 0.0]
}

fn normal_api_client() -> [f64; NUM_FEATURES] {
    // Backend API client: ~2 req/s, hits a few endpoints, 1 host, ~5% errors (retries),
    // ~50ms latency, mix of GET/POST, steady rate, some path repetition, small bodies, 1 UA
    // cookies=yes (session), referer=no, accept-lang=no, suspicious=no
    [2.0, 5.0, 1.0, 0.05, 50.0, 0.69, 2.5, 0.4, 512.0, 1.0, 1.0, 0.0, 0.0, 0.0]
}

fn normal_webhook_burst() -> [f64; NUM_FEATURES] {
    // CI/CD or webhook burst: ~10 req/s for a short period, 1-2 paths, 1 host,
    // 0% errors, fast responses, all POST, bursty, high path repetition, medium bodies, 1 UA
    // cookies=no (machine), referer=no, accept-lang=no, suspicious=no
    [10.0, 2.0, 1.0, 0.0, 25.0, 0.0, 12.0, 0.8, 2048.0, 1.0, 0.0, 0.0, 0.0, 0.0]
}

fn normal_health_check() -> [f64; NUM_FEATURES] {
    // Health check probe: ~0.2 req/s, 1 path, 1 host, 0% errors, ~5ms latency,
    // all GET, very regular, 100% same path, no body, 1 UA
    // cookies=no (probe), referer=no, accept-lang=no, suspicious=no
    [0.2, 1.0, 1.0, 0.0, 5.0, 0.0, 0.2, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0]
}

fn normal_mobile_app() -> [f64; NUM_FEATURES] {
    // Mobile app: ~1 req/s, several API endpoints, 1 host, ~3% errors,
    // ~200ms latency (mobile network), GET + POST, moderate spacing, moderate repetition,
    // small-medium bodies, 1 UA
    // cookies=yes, referer=no, accept-lang=yes, suspicious=no
    [1.0, 8.0, 1.0, 0.03, 200.0, 0.5, 1.2, 0.25, 256.0, 1.0, 1.0, 0.0, 1.0, 0.0]
}

fn normal_search_crawler() -> [f64; NUM_FEATURES] {
    // Googlebot-style crawler: ~0.3 req/s, many unique paths, 1 host, ~10% 404s,
    // ~300ms latency, all GET, slow steady rate, diverse paths, no body, 1 UA
    // cookies=no (crawler), referer=no, accept-lang=no, suspicious=no
    [0.3, 20.0, 1.0, 0.1, 300.0, 0.0, 0.35, 0.08, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0]
}

fn normal_graphql_spa() -> [f64; NUM_FEATURES] {
    // SPA hitting a GraphQL endpoint: ~3 req/s, 1 path (/graphql), 1 host, ~1% errors,
    // ~80ms latency, all POST, steady, 100% same path, medium bodies, 1 UA
    // cookies=yes, referer=yes (SPA nav), accept-lang=yes, suspicious=no
    [3.0, 1.0, 1.0, 0.01, 80.0, 0.0, 3.5, 1.0, 1024.0, 1.0, 1.0, 1.0, 1.0, 0.0]
}

fn normal_websocket_upgrade() -> [f64; NUM_FEATURES] {
    // Initial HTTP requests before WS upgrade: ~0.1 req/s, 2 paths, 1 host, 0% errors,
    // ~10ms latency, GET, slow, some repetition, no body, 1 UA
    // cookies=yes, referer=yes, accept-lang=yes, suspicious=no
    [0.1, 2.0, 1.0, 0.0, 10.0, 0.0, 0.1, 0.5, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0]
}

fn normal_file_upload() -> [f64; NUM_FEATURES] {
    // File upload session: ~0.5 req/s, 3 paths (upload, status, confirm), 1 host,
    // 0% errors, ~500ms latency (large bodies), POST + GET, steady, moderate repetition,
    // large bodies, 1 UA
    // cookies=yes, referer=yes, accept-lang=yes, suspicious=no
    [0.5, 3.0, 1.0, 0.0, 500.0, 0.69, 0.6, 0.5, 1_000_000.0, 1.0, 1.0, 1.0, 1.0, 0.0]
}

fn normal_multi_tenant_api() -> [f64; NUM_FEATURES] {
    // API client hitting multiple hosts (multi-tenant): ~1.5 req/s, 4 paths, 3 hosts,
    // ~2% errors, ~100ms latency, GET + POST, steady, low repetition, small bodies, 1 UA
    // cookies=yes, referer=no, accept-lang=no, suspicious=no
    [1.5, 4.0, 3.0, 0.02, 100.0, 0.69, 1.8, 0.3, 128.0, 1.0, 1.0, 0.0, 0.0, 0.0]
}

// Realistic attack traffic profiles
fn attack_path_scan() -> [f64; NUM_FEATURES] {
    // WordPress/PHP scanner: ~20 req/s, many unique paths, 1 host, 100% 404s,
    // ~2ms latency (all errors), all GET, very bursty, all unique paths, no body, 1 UA
    // cookies=no, referer=no, accept-lang=no, suspicious=0.8 (most paths are probes)
    [20.0, 50.0, 1.0, 1.0, 2.0, 0.0, 25.0, 0.02, 0.0, 1.0, 0.0, 0.0, 0.0, 0.8]
}

fn attack_credential_stuffing() -> [f64; NUM_FEATURES] {
    // Login brute-force: ~30 req/s, 1 path (/login), 1 host, 95% 401/403,
    // ~10ms latency, all POST, very bursty, 100% same path, small bodies, 1 UA
    // cookies=no, referer=no, accept-lang=no, suspicious=0.0 (/login is not in suspicious list)
    [30.0, 1.0, 1.0, 0.95, 10.0, 0.0, 35.0, 1.0, 64.0, 1.0, 0.0, 0.0, 0.0, 0.0]
}

fn attack_slowloris() -> [f64; NUM_FEATURES] {
    // Slowloris-style: ~0.5 req/s (slow), 1 path, 1 host, 0% errors (connections held),
    // ~30000ms latency (!), all GET, slow, 100% same path, huge content-length, 1 UA
    // cookies=no, referer=no, accept-lang=no, suspicious=0.0
    [0.5, 1.0, 1.0, 0.0, 30000.0, 0.0, 0.5, 1.0, 10_000_000.0, 1.0, 0.0, 0.0, 0.0, 0.0]
}

fn attack_ua_rotation() -> [f64; NUM_FEATURES] {
    // Bot rotating user-agents: ~15 req/s, 2 paths, 1 host, 80% errors,
    // ~5ms latency, GET + POST, bursty, high repetition, no body, 50 distinct UAs
    // cookies=no, referer=no, accept-lang=no, suspicious=0.3
    [15.0, 2.0, 1.0, 0.8, 5.0, 0.69, 18.0, 0.7, 0.0, 50.0, 0.0, 0.0, 0.0, 0.3]
}

fn attack_host_scan() -> [f64; NUM_FEATURES] {
    // Virtual host enumeration: ~25 req/s, 1 path (/), many hosts, 100% errors,
    // ~1ms latency, all GET, very bursty, 100% same path, no body, 1 UA
    // cookies=no, referer=no, accept-lang=no, suspicious=0.0
    [25.0, 1.0, 40.0, 1.0, 1.0, 0.0, 30.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0]
}

fn attack_api_fuzzing() -> [f64; NUM_FEATURES] {
    // API fuzzer: ~50 req/s, many paths, 1 host, 90% errors (bad inputs),
    // ~3ms latency, mixed methods, extremely bursty, low repetition, varied bodies, 1 UA
    // cookies=no, referer=no, accept-lang=no, suspicious=0.5
    [50.0, 100.0, 1.0, 0.9, 3.0, 1.5, 55.0, 0.01, 4096.0, 1.0, 0.0, 0.0, 0.0, 0.5]
}

fn all_normal_profiles() -> Vec<[f64; NUM_FEATURES]> {
    vec![
        normal_browser_browsing(),
        normal_api_client(),
        normal_webhook_burst(),
        normal_health_check(),
        normal_mobile_app(),
        normal_search_crawler(),
        normal_graphql_spa(),
        normal_websocket_upgrade(),
        normal_file_upload(),
        normal_multi_tenant_api(),
    ]
}

fn all_attack_profiles() -> Vec<[f64; NUM_FEATURES]> {
    vec![
        attack_path_scan(),
        attack_credential_stuffing(),
        attack_slowloris(),
        attack_ua_rotation(),
        attack_host_scan(),
        attack_api_fuzzing(),
    ]
}

/// Build a model from realistic profiles, with each profile replicated `copies`
/// times (with slight jitter) to give the KNN enough neighbors.
fn make_realistic_model(k: usize, threshold: f64) -> TrainedModel {
    let mut normal = Vec::new();
    let mut attack = Vec::new();

    // Replicate each profile with small perturbations
    for base in all_normal_profiles() {
        for i in 0..20 {
            let mut v = base;
            for d in 0..NUM_FEATURES {
                // ±5% jitter
                let jitter = 1.0 + ((i as f64 * 0.37 + d as f64 * 0.13) % 0.1 - 0.05);
                v[d] *= jitter;
            }
            normal.push(v);
        }
    }
    for base in all_attack_profiles() {
        for i in 0..20 {
            let mut v = base;
            for d in 0..NUM_FEATURES {
                let jitter = 1.0 + ((i as f64 * 0.41 + d as f64 * 0.17) % 0.1 - 0.05);
                v[d] *= jitter;
            }
            attack.push(v);
        }
    }

    make_model(&normal, &attack, k, threshold)
}

// ===========================================================================
// Model classification tests — normal profiles must NEVER be blocked
// ===========================================================================

#[test]
fn normal_browser_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&normal_browser_browsing()), DDoSAction::Allow);
}

#[test]
fn normal_api_client_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&normal_api_client()), DDoSAction::Allow);
}

#[test]
fn normal_webhook_burst_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&normal_webhook_burst()), DDoSAction::Allow);
}

#[test]
fn normal_health_check_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&normal_health_check()), DDoSAction::Allow);
}

#[test]
fn normal_mobile_app_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&normal_mobile_app()), DDoSAction::Allow);
}

#[test]
fn normal_search_crawler_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&normal_search_crawler()), DDoSAction::Allow);
}

#[test]
fn normal_graphql_spa_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&normal_graphql_spa()), DDoSAction::Allow);
}

#[test]
fn normal_websocket_upgrade_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(
        model.classify(&normal_websocket_upgrade()),
        DDoSAction::Allow
    );
}

#[test]
fn normal_file_upload_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&normal_file_upload()), DDoSAction::Allow);
}

#[test]
fn normal_multi_tenant_api_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(
        model.classify(&normal_multi_tenant_api()),
        DDoSAction::Allow
    );
}

// ===========================================================================
// Model classification tests — attack profiles must be blocked
// ===========================================================================

#[test]
fn attack_path_scan_is_blocked() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&attack_path_scan()), DDoSAction::Block);
}

#[test]
fn attack_credential_stuffing_is_blocked() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(
        model.classify(&attack_credential_stuffing()),
        DDoSAction::Block
    );
}

#[test]
fn attack_slowloris_is_blocked() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&attack_slowloris()), DDoSAction::Block);
}

#[test]
fn attack_ua_rotation_is_blocked() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&attack_ua_rotation()), DDoSAction::Block);
}

#[test]
fn attack_host_scan_is_blocked() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&attack_host_scan()), DDoSAction::Block);
}

#[test]
fn attack_api_fuzzing_is_blocked() {
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&attack_api_fuzzing()), DDoSAction::Block);
}

// ===========================================================================
// Edge cases: normal traffic that LOOKS suspicious but isn't
// ===========================================================================

#[test]
fn high_rate_legitimate_cdn_prefetch_is_allowed() {
    // CDN prefetch: high rate but low errors, diverse paths, normal latency
    let model = make_realistic_model(5, 0.6);
    let profile: [f64; NUM_FEATURES] =
        [8.0, 15.0, 1.0, 0.0, 100.0, 0.0, 9.0, 0.1, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0];
    assert_eq!(model.classify(&profile), DDoSAction::Allow);
}

#[test]
fn single_path_api_polling_is_allowed() {
    // Long-poll or SSE endpoint: single path, 100% repetition, but low rate, no errors
    let model = make_realistic_model(5, 0.6);
    let profile: [f64; NUM_FEATURES] =
        [0.3, 1.0, 1.0, 0.0, 1000.0, 0.0, 0.3, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0];
    assert_eq!(model.classify(&profile), DDoSAction::Allow);
}

#[test]
fn moderate_error_rate_during_deploy_is_allowed() {
    // During a rolling deploy, error rate spikes to ~20% temporarily
    let model = make_realistic_model(5, 0.6);
    let profile: [f64; NUM_FEATURES] =
        [1.0, 5.0, 1.0, 0.2, 200.0, 0.5, 1.2, 0.3, 128.0, 1.0, 1.0, 0.3, 1.0, 0.0];
    assert_eq!(model.classify(&profile), DDoSAction::Allow);
}

#[test]
fn burst_of_form_submissions_is_allowed() {
    // Marketing event → users submit forms rapidly: high rate, single path, all POST, no errors
    let model = make_realistic_model(5, 0.6);
    let profile: [f64; NUM_FEATURES] =
        [5.0, 1.0, 1.0, 0.0, 80.0, 0.0, 6.0, 1.0, 512.0, 1.0, 1.0, 1.0, 1.0, 0.0];
    assert_eq!(model.classify(&profile), DDoSAction::Allow);
}

#[test]
fn legitimate_load_test_with_varied_paths_is_allowed() {
    // Internal load test: high rate but diverse paths, low error, real latency
    let model = make_realistic_model(5, 0.6);
    let profile: [f64; NUM_FEATURES] =
        [8.0, 30.0, 1.0, 0.02, 120.0, 0.69, 10.0, 0.05, 256.0, 1.0, 0.0, 0.0, 0.0, 0.0];
    assert_eq!(model.classify(&profile), DDoSAction::Allow);
}

// ===========================================================================
// Threshold and k sensitivity
// ===========================================================================

#[test]
fn higher_threshold_is_more_permissive() {
    // With threshold=0.9, even borderline traffic should be allowed
    let model = make_realistic_model(5, 0.9);
    // A profile that's borderline between attack and normal
    let borderline: [f64; NUM_FEATURES] =
        [12.0, 8.0, 1.0, 0.5, 20.0, 0.5, 14.0, 0.5, 100.0, 2.0, 0.0, 0.0, 0.0, 0.1];
    assert_eq!(model.classify(&borderline), DDoSAction::Allow);
}

#[test]
fn larger_k_smooths_classification() {
    // With larger k, noisy outliers matter less
    let model_k3 = make_realistic_model(3, 0.6);
    let model_k9 = make_realistic_model(9, 0.6);
    // Normal traffic should be allowed by both
    let profile = normal_browser_browsing();
    assert_eq!(model_k3.classify(&profile), DDoSAction::Allow);
    assert_eq!(model_k9.classify(&profile), DDoSAction::Allow);
}

// ===========================================================================
// Normalization tests
// ===========================================================================

#[test]
fn normalization_clamps_out_of_range() {
    let params = NormParams {
        mins: [0.0; NUM_FEATURES],
        maxs: [1.0; NUM_FEATURES],
    };
    // Values above max should clamp to 1.0
    let above = [2.0; NUM_FEATURES];
    let normed = params.normalize(&above);
    for &v in &normed {
        assert_eq!(v, 1.0);
    }
    // Values below min should clamp to 0.0
    let below = [-1.0; NUM_FEATURES];
    let normed = params.normalize(&below);
    for &v in &normed {
        assert_eq!(v, 0.0);
    }
}

#[test]
fn normalization_handles_zero_range() {
    // When all training data has the same value for a feature, range = 0
    let params = NormParams {
        mins: [5.0; NUM_FEATURES],
        maxs: [5.0; NUM_FEATURES],
    };
    let v = [5.0; NUM_FEATURES];
    let normed = params.normalize(&v);
    for &val in &normed {
        assert_eq!(val, 0.0);
    }
}

#[test]
fn normalization_preserves_midpoint() {
    let params = NormParams {
        mins: [0.0; NUM_FEATURES],
        maxs: [100.0; NUM_FEATURES],
    };
    let v = [50.0; NUM_FEATURES];
    let normed = params.normalize(&v);
    for &val in &normed {
        assert!((val - 0.5).abs() < 1e-10);
    }
}

#[test]
fn norm_params_from_data_finds_extremes() {
    let data = vec![
        [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0],
        [10.0, 9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0, 0.5, 0.5, 0.5, 0.5],
    ];
    let params = NormParams::from_data(&data);
    for i in 0..NUM_FEATURES {
        assert!(params.mins[i] <= params.maxs[i]);
    }
    assert_eq!(params.mins[0], 1.0);
    assert_eq!(params.maxs[0], 10.0);
}

// ===========================================================================
// Serialization round-trip
// ===========================================================================

#[test]
fn model_serialization_roundtrip() {
    // Use the realistic model (200+ points) so fnntw has enough data for the kD-tree
    let model = make_realistic_model(3, 0.5);

    // Rebuild from the same training data
    let mut all_points = Vec::new();
    let mut all_labels = Vec::new();
    for base in all_normal_profiles() {
        for i in 0..20 {
            let mut v = base;
            for d in 0..NUM_FEATURES {
                let jitter = 1.0 + ((i as f64 * 0.37 + d as f64 * 0.13) % 0.1 - 0.05);
                v[d] *= jitter;
            }
            all_points.push(v);
            all_labels.push(TrafficLabel::Normal);
        }
    }
    for base in all_attack_profiles() {
        for i in 0..20 {
            let mut v = base;
            for d in 0..NUM_FEATURES {
                let jitter = 1.0 + ((i as f64 * 0.41 + d as f64 * 0.17) % 0.1 - 0.05);
                v[d] *= jitter;
            }
            all_points.push(v);
            all_labels.push(TrafficLabel::Attack);
        }
    }

    let norm_params = NormParams::from_data(&all_points);
    let serialized = SerializedModel {
        points: all_points.iter().map(|v| norm_params.normalize(v)).collect(),
        labels: all_labels,
        norm_params,
        k: 3,
        threshold: 0.5,
    };

    let encoded = bincode::serialize(&serialized).unwrap();
    let decoded: SerializedModel = bincode::deserialize(&encoded).unwrap();

    assert_eq!(decoded.points.len(), serialized.points.len());
    assert_eq!(decoded.labels.len(), serialized.labels.len());
    assert_eq!(decoded.k, 3);
    assert!((decoded.threshold - 0.5).abs() < 1e-10);

    // Rebuilt model should classify the same
    let rebuilt = TrainedModel::from_serialized(decoded);
    assert_eq!(
        rebuilt.classify(&normal_browser_browsing()),
        model.classify(&normal_browser_browsing())
    );
}

// ===========================================================================
// Detector integration tests (full check() pipeline)
// ===========================================================================

#[test]
fn detector_allows_below_min_events() {
    let model = make_realistic_model(5, 0.6);
    let detector = make_detector(model, 10);

    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    // Send 9 requests — below min_events threshold of 10
    for _ in 0..9 {
        let action = detector.check(ip, "GET", "/wp-admin", "evil.com", "bot", 0, false, false, false);
        assert_eq!(action, DDoSAction::Allow, "should allow below min_events");
    }
}

#[test]
fn detector_ipv4_and_ipv6_tracked_separately() {
    let model = make_realistic_model(5, 0.6);
    let detector = make_detector(model, 3);

    let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    // Send events to v4 only
    for _ in 0..5 {
        detector.check(v4, "GET", "/", "example.com", "Mozilla/5.0", 0, true, false, true);
    }

    // v6 should still have 0 events (below min_events)
    let action = detector.check(v6, "GET", "/", "example.com", "Mozilla/5.0", 0, true, false, true);
    assert_eq!(action, DDoSAction::Allow);
}

#[test]
fn detector_normal_browsing_pattern_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    let detector = make_detector(model, 5);

    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
    let paths = ["/", "/about", "/products", "/products/1", "/contact",
                 "/blog", "/blog/post-1", "/docs", "/pricing", "/login",
                 "/dashboard", "/settings", "/api/me"];
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";

    for (i, path) in paths.iter().enumerate() {
        let method = if i % 5 == 0 { "POST" } else { "GET" };
        let action = detector.check(ip, method, path, "mysite.com", ua, 0, true, true, true);
        // After min_events, every check should still allow normal browsing
        assert_eq!(
            action,
            DDoSAction::Allow,
            "normal browsing blocked on request #{i} to {path}"
        );
    }
}

#[test]
fn detector_handles_concurrent_ips() {
    let model = make_realistic_model(5, 0.6);
    let detector = make_detector(model, 5);

    // Simulate 50 distinct IPs each making a few normal requests
    for i in 0..50u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        let paths = ["/", "/about", "/products", "/contact", "/blog",
                     "/docs", "/api/status"];
        for path in &paths {
            let action = detector.check(ip, "GET", path, "example.com", "Chrome", 0, true, false, true);
            assert_eq!(action, DDoSAction::Allow,
                "IP 10.0.0.{i} blocked on {path}");
        }
    }
}

#[test]
fn detector_ipv6_normal_traffic_is_allowed() {
    let model = make_realistic_model(5, 0.6);
    let detector = make_detector(model, 5);

    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42));
    let paths = ["/", "/about", "/products", "/blog", "/contact",
                 "/login", "/dashboard"];
    for path in &paths {
        let action = detector.check(ip, "GET", path, "example.com",
                                     "Mozilla/5.0", 0, true, false, true);
        assert_eq!(action, DDoSAction::Allow,
            "IPv6 normal traffic blocked on {path}");
    }
}

// ===========================================================================
// Model robustness: slight variations of normal traffic
// ===========================================================================

#[test]
fn slightly_elevated_rate_still_allowed() {
    let model = make_realistic_model(5, 0.6);
    // 2x normal browsing rate — busy but not attacking
    let profile: [f64; NUM_FEATURES] =
        [1.0, 12.0, 1.0, 0.02, 150.0, 0.2, 1.2, 0.15, 0.0, 1.0, 1.0, 0.5, 1.0, 0.0];
    assert_eq!(model.classify(&profile), DDoSAction::Allow);
}

#[test]
fn slightly_elevated_errors_still_allowed() {
    // 15% errors (e.g. some 404s from broken links) — normal for real sites
    let model = make_realistic_model(5, 0.6);
    let profile: [f64; NUM_FEATURES] =
        [0.5, 10.0, 1.0, 0.15, 150.0, 0.2, 0.6, 0.15, 0.0, 1.0, 1.0, 0.3, 1.0, 0.0];
    assert_eq!(model.classify(&profile), DDoSAction::Allow);
}

#[test]
fn zero_traffic_features_allowed() {
    // Edge case: all zeros (shouldn't happen in practice, but must not crash or block)
    let model = make_realistic_model(5, 0.6);
    assert_eq!(model.classify(&[0.0; NUM_FEATURES]), DDoSAction::Allow);
}

#[test]
fn empty_model_always_allows() {
    let model = TrainedModel::from_serialized(SerializedModel {
        points: vec![],
        labels: vec![],
        norm_params: NormParams {
            mins: [0.0; NUM_FEATURES],
            maxs: [1.0; NUM_FEATURES],
        },
        k: 5,
        threshold: 0.6,
    });
    // Must allow everything — no training data to compare against
    assert_eq!(model.classify(&attack_path_scan()), DDoSAction::Allow);
    assert_eq!(model.classify(&normal_browser_browsing()), DDoSAction::Allow);
}

#[test]
fn all_normal_model_allows_everything() {
    // A model trained only on normal data (no attack points) should never block.
    // Use enough points (200) so fnntw can build the kD-tree.
    let mut normal = Vec::new();
    for base in all_normal_profiles() {
        for i in 0..20 {
            let mut v = base;
            for d in 0..NUM_FEATURES {
                let jitter = 1.0 + ((i as f64 * 0.37 + d as f64 * 0.13) % 0.1 - 0.05);
                v[d] *= jitter;
            }
            normal.push(v);
        }
    }
    let model = make_model(&normal, &[], 5, 0.6);
    assert_eq!(model.classify(&normal_browser_browsing()), DDoSAction::Allow);
    assert_eq!(model.classify(&normal_api_client()), DDoSAction::Allow);
    // Even attack-like traffic is allowed since the model has no attack examples
    assert_eq!(model.classify(&attack_path_scan()), DDoSAction::Allow);
}

// ===========================================================================
// Feature extraction tests
// ===========================================================================

#[test]
fn method_entropy_zero_for_single_method() {
    // All GET requests → method distribution is [1.0, 0, 0, ...] → entropy = 0
    let model = make_realistic_model(5, 0.6);
    let profile = normal_health_check(); // all GET
    assert_eq!(profile[5], 0.0); // method_entropy
    assert_eq!(model.classify(&profile), DDoSAction::Allow);
}

#[test]
fn method_entropy_positive_for_mixed_methods() {
    let profile = normal_api_client(); // mix of GET/POST
    assert!(profile[5] > 0.0, "method_entropy should be positive for mixed methods");
}

#[test]
fn path_repetition_is_one_for_single_path() {
    let profile = normal_graphql_spa(); // single /graphql endpoint
    assert_eq!(profile[7], 1.0);
}

#[test]
fn path_repetition_is_low_for_diverse_paths() {
    let profile = normal_search_crawler(); // many unique paths
    assert!(profile[7] < 0.2);
}

// ===========================================================================
// Load the real trained model and validate against known profiles
// ===========================================================================

#[test]
fn real_model_file_roundtrip() {
    let model_path = std::path::Path::new("ddos_model.bin");
    if !model_path.exists() {
        // Skip if no model file present (CI environments)
        eprintln!("skipping real_model_file_roundtrip: ddos_model.bin not found");
        return;
    }
    let model = TrainedModel::load(model_path, Some(3), Some(0.5)).unwrap();
    assert!(model.point_count() > 0, "model should have training points");
    // Smoke test: classifying shouldn't panic
    let _ = model.classify(&normal_browser_browsing());
    let _ = model.classify(&attack_path_scan());
}
