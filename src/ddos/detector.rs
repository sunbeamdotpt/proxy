// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use crate::config::DDoSConfig;
use crate::ddos::features::{method_to_u8, IpState, RequestEvent};
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
