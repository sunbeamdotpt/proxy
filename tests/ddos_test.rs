// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! DDoS detection tests.
//!
//! The detector uses ensemble inference (decision tree + MLP) with compiled-in
//! weights. These tests exercise the detector pipeline: event accumulation,
//! min_events gating, and ensemble classification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sunbeam_proxy::config::DDoSConfig;
use sunbeam_proxy::ddos::detector::DDoSDetector;
use sunbeam_proxy::ddos::features::{NormParams, NUM_FEATURES};
use sunbeam_proxy::ddos::model::DDoSAction;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_ddos_config() -> DDoSConfig {
    DDoSConfig {
        threshold: 0.6,
        window_secs: 60,
        window_capacity: 1000,
        min_events: 10,
        enabled: true,
        observe_only: false,
    }
}

fn make_detector(min_events: usize) -> DDoSDetector {
    let mut cfg = default_ddos_config();
    cfg.min_events = min_events;
    DDoSDetector::new(&cfg)
}

// ===========================================================================
// Normalization tests (feature-level, model-independent)
// ===========================================================================

#[test]
fn normalization_clamps_out_of_range() {
    let params = NormParams {
        mins: [0.0; NUM_FEATURES],
        maxs: [1.0; NUM_FEATURES],
    };
    let above = [2.0; NUM_FEATURES];
    let normed = params.normalize(&above);
    for &v in &normed {
        assert_eq!(v, 1.0);
    }
    let below = [-1.0; NUM_FEATURES];
    let normed = params.normalize(&below);
    for &v in &normed {
        assert_eq!(v, 0.0);
    }
}

#[test]
fn normalization_handles_zero_range() {
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
        [
            1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0,
        ],
        [
            10.0, 9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0, 0.5, 0.5, 0.5, 0.5,
        ],
    ];
    let params = NormParams::from_data(&data);
    for i in 0..NUM_FEATURES {
        assert!(params.mins[i] <= params.maxs[i]);
    }
    assert_eq!(params.mins[0], 1.0);
    assert_eq!(params.maxs[0], 10.0);
}

// ===========================================================================
// Detector integration tests (full check() pipeline)
// ===========================================================================

#[test]
fn detector_allows_below_min_events() {
    let detector = make_detector(10);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    for _ in 0..9 {
        let action = detector.check(
            ip,
            "GET",
            "/wp-admin",
            "evil.com",
            "bot",
            0,
            false,
            false,
            false,
        );
        assert_eq!(action, DDoSAction::Allow, "should allow below min_events");
    }
}

#[test]
fn detector_ipv4_and_ipv6_tracked_separately() {
    let detector = make_detector(3);
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    for _ in 0..5 {
        detector.check(
            v4,
            "GET",
            "/",
            "example.com",
            "Mozilla/5.0",
            0,
            true,
            false,
            true,
        );
    }

    // v6 should still have 0 events (below min_events)
    let action = detector.check(
        v6,
        "GET",
        "/",
        "example.com",
        "Mozilla/5.0",
        0,
        true,
        false,
        true,
    );
    assert_eq!(action, DDoSAction::Allow);
}

#[test]
fn detector_normal_browsing_pattern_is_allowed() {
    let detector = make_detector(5);
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
    let paths = [
        "/",
        "/about",
        "/products",
        "/products/1",
        "/contact",
        "/blog",
        "/blog/post-1",
        "/docs",
        "/pricing",
        "/login",
        "/dashboard",
        "/settings",
        "/api/me",
    ];
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";

    for (i, path) in paths.iter().enumerate() {
        let method = if i % 5 == 0 { "POST" } else { "GET" };
        let action = detector.check(ip, method, path, "mysite.com", ua, 0, true, true, true);
        assert_eq!(
            action,
            DDoSAction::Allow,
            "normal browsing blocked on request #{i} to {path}"
        );
    }
}

#[test]
fn detector_handles_concurrent_ips() {
    let detector = make_detector(5);
    for i in 0..50u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        let paths = [
            "/",
            "/about",
            "/products",
            "/contact",
            "/blog",
            "/docs",
            "/api/status",
        ];
        for path in &paths {
            // has_referer=true so referer_ratio stays above the tree threshold
            let action = detector.check(
                ip,
                "GET",
                path,
                "example.com",
                "Chrome",
                0,
                true,
                true,
                true,
            );
            assert_eq!(action, DDoSAction::Allow, "IP 10.0.0.{i} blocked on {path}");
        }
    }
}

#[test]
fn detector_ipv6_normal_traffic_is_allowed() {
    let detector = make_detector(5);
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42));
    let paths = [
        "/",
        "/about",
        "/products",
        "/blog",
        "/contact",
        "/login",
        "/dashboard",
    ];
    for path in &paths {
        // has_referer=true so referer_ratio stays above the tree threshold
        let action = detector.check(
            ip,
            "GET",
            path,
            "example.com",
            "Mozilla/5.0",
            0,
            true,
            true,
            true,
        );
        assert_eq!(
            action,
            DDoSAction::Allow,
            "IPv6 normal traffic blocked on {path}"
        );
    }
}
