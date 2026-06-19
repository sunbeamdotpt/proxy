// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::DDoSConfig;
use crate::ddos::features::{IpState, RequestEvent, method_to_u8};
use crate::ddos::model::DDoSAction;
use rustc_hash::FxHashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Instant;

const NUM_SHARDS: usize = 256;

/// Ddosdetector.
pub struct DDoSDetector {
    shards: Vec<RwLock<FxHashMap<IpAddr, IpState>>>,
    window_secs: u64,
    window_capacity: usize,
    min_events: usize,
}

fn shard_index(ip: &IpAddr) -> usize {
    let mut h = rustc_hash::FxHasher::default();
    ip.hash(&mut h);
    h.finish() as usize % NUM_SHARDS
}

impl DDoSDetector {
    pub fn new(config: &DDoSConfig) -> Self {
        let shards = (0..NUM_SHARDS)
            .map(|_| RwLock::new(FxHashMap::default()))
            .collect();
        Self {
            shards,
            window_secs: config.window_secs,
            window_capacity: config.window_capacity,
            min_events: config.min_events,
        }
    }

    /// Record an incoming request and classify the IP.
    /// Called from request_filter (before upstream).
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        ip: IpAddr,
        method: &str,
        path: &str,
        host: &str,
        user_agent: &str,
        content_length: u64,
        has_cookies: bool,
        has_referer: bool,
        has_accept_language: bool,
    ) -> DDoSAction {
        let event = RequestEvent {
            timestamp: Instant::now(),
            method: method_to_u8(method),
            path_hash: fx_hash(path),
            host_hash: fx_hash(host),
            user_agent_hash: fx_hash(user_agent),
            status: 0,
            duration_ms: 0,
            content_length: content_length.min(u32::MAX as u64) as u32,
            has_cookies,
            has_referer,
            has_accept_language,
            suspicious_path: crate::ddos::features::is_suspicious_path(path),
        };

        let idx = shard_index(&ip);
        let mut shard = self.shards[idx].write().unwrap_or_else(|e| e.into_inner());
        let state = shard
            .entry(ip)
            .or_insert_with(|| IpState::new(self.window_capacity));
        state.push(event);

        if state.len() < self.min_events {
            return DDoSAction::Allow;
        }

        let features = state.extract_features(self.window_secs);

        // Cast f64 features to f32 array for ensemble inference.
        let mut f32_features = [0.0f32; 14];
        for (i, &v) in features.iter().enumerate().take(14) {
            f32_features[i] = v as f32;
        }
        let ev = crate::ensemble::ddos::ddos_ensemble_predict(&f32_features);
        crate::metrics::DDOS_ENSEMBLE_PATH
            .with_label_values(&[match ev.path {
                crate::ensemble::ddos::DDoSEnsemblePath::TreeBlock => "tree_block",
                crate::ensemble::ddos::DDoSEnsemblePath::TreeAllow => "tree_allow",
                crate::ensemble::ddos::DDoSEnsemblePath::Mlp => "mlp",
            }])
            .inc();
        ev.action
    }

    /// Feed response data back into the IP's event history.
    /// Called from logging() after the response is sent.
    pub fn record_response(&self, _ip: IpAddr, _status: u16, _duration_ms: u32) {
        // Status/duration from check() are 0-initialized; the next request
        // will have fresh data. This is intentionally a no-op for now.
    }
}

fn fx_hash(s: &str) -> u64 {
    let mut h = rustc_hash::FxHasher::default();
    s.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn cfg(min_events: usize) -> DDoSConfig {
        DDoSConfig {
            threshold: 0.6,
            window_secs: 60,
            window_capacity: 100,
            min_events,
            enabled: true,
            observe_only: false,
        }
    }

    #[test]
    fn shard_index_is_in_range_and_deterministic() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let idx1 = shard_index(&ip);
        let idx2 = shard_index(&ip);
        assert_eq!(idx1, idx2);
        assert!(idx1 < NUM_SHARDS);

        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        let idx6 = shard_index(&ip6);
        assert!(idx6 < NUM_SHARDS);
    }

    #[test]
    fn detector_new_uses_config_values() {
        let detector = DDoSDetector::new(&cfg(5));
        assert_eq!(detector.window_secs, 60);
        assert_eq!(detector.window_capacity, 100);
        assert_eq!(detector.min_events, 5);
        assert_eq!(detector.shards.len(), NUM_SHARDS);
    }

    #[test]
    fn check_allows_until_min_events_reached() {
        let detector = DDoSDetector::new(&cfg(3));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(
            detector.check(ip, "GET", "/", "example.com", "ua", 0, false, false, false),
            DDoSAction::Allow
        );
        assert_eq!(
            detector.check(ip, "GET", "/", "example.com", "ua", 0, false, false, false),
            DDoSAction::Allow
        );
        // Third event reaches min_events; all cookies false → tree block.
        let action = detector.check(ip, "GET", "/", "example.com", "ua", 0, false, false, false);
        assert_eq!(action, DDoSAction::Block);
    }

    #[test]
    fn check_allows_when_cookie_ratio_high() {
        let detector = DDoSDetector::new(&cfg(3));
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..2 {
            detector.check(ip, "GET", "/", "example.com", "ua", 0, true, true, true);
        }
        let action = detector.check(ip, "GET", "/", "example.com", "ua", 0, true, true, true);
        assert_eq!(action, DDoSAction::Allow);
    }

    #[test]
    fn record_response_is_no_op() {
        let detector = DDoSDetector::new(&cfg(1));
        let ip: IpAddr = "192.0.2.3".parse().unwrap();
        // Should not panic or mutate state in a visible way.
        detector.record_response(ip, 200, 10);
    }

    #[test]
    fn fx_hash_deterministic() {
        assert_eq!(fx_hash("hello"), fx_hash("hello"));
        assert_ne!(fx_hash("hello"), fx_hash("world"));
    }
}
