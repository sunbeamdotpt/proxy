// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Num features.
pub const NUM_FEATURES: usize = 14;
/// Featurevector.
pub type FeatureVector = [f64; NUM_FEATURES];

#[derive(Clone)]
/// Requestevent.
pub struct RequestEvent {
    /// Timestamp.
    pub timestamp: Instant,
    /// GET=0, POST=1, PUT=2, DELETE=3, HEAD=4, PATCH=5, OPTIONS=6, other=7
    pub method: u8,
    /// Path hash.
    pub path_hash: u64,
    /// Host hash.
    pub host_hash: u64,
    /// User agent hash.
    pub user_agent_hash: u64,
    /// Status.
    pub status: u16,
    /// Duration ms.
    pub duration_ms: u32,
    /// Content length.
    pub content_length: u32,
    /// Has cookies.
    pub has_cookies: bool,
    /// Has referer.
    pub has_referer: bool,
    /// Has accept language.
    pub has_accept_language: bool,
    /// Suspicious path.
    pub suspicious_path: bool,
}

/// Known-bad path fragments that scanners/bots probe for.
const SUSPICIOUS_FRAGMENTS: &[&str] = &[
    ".env",
    ".git/",
    ".git\\",
    ".bak",
    ".sql",
    ".tar",
    ".zip",
    "wp-admin",
    "wp-login",
    "wp-includes",
    "wp-content",
    "xmlrpc",
    "phpinfo",
    "phpmyadmin",
    "php-info",
    ".php",
    "cgi-bin",
    "shell",
    "eval-stdin",
    "/vendor/",
    "/telescope/",
    "/actuator/",
    "/.htaccess",
    "/.htpasswd",
    "/debug/",
    "/config.",
    "/admin/",
    "yarn.lock",
    "yarn-debug",
    "package.json",
    "composer.json",
];

/// Is suspicious path.
pub fn is_suspicious_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    SUSPICIOUS_FRAGMENTS.iter().any(|f| lower.contains(f))
}

/// Ipstate.
pub struct IpState {
    events: Vec<RequestEvent>,
    cursor: usize,
    count: usize,
    capacity: usize,
}

impl IpState {
    pub fn new(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            cursor: 0,
            count: 0,
            capacity,
        }
    }

    pub fn push(&mut self, event: RequestEvent) {
        if self.events.len() < self.capacity {
            self.events.push(event);
        } else {
            self.events[self.cursor] = event;
        }
        self.cursor = (self.cursor + 1) % self.capacity;
        self.count += 1;
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Prune events older than `window` from the logical view.
    /// Returns a slice of active events (not necessarily contiguous in ring buffer,
    /// so we collect into a Vec).
    fn active_events(&self, window_secs: u64) -> Vec<&RequestEvent> {
        let now = Instant::now();
        let cutoff = std::time::Duration::from_secs(window_secs);
        self.events
            .iter()
            .filter(|e| now.duration_since(e.timestamp) <= cutoff)
            .collect()
    }

    /// Extract features.
    pub fn extract_features(&self, window_secs: u64) -> FeatureVector {
        let events = self.active_events(window_secs);
        let n = events.len() as f64;
        if n < 1.0 {
            return [0.0; NUM_FEATURES];
        }

        // 0: request_rate (requests / window_secs)
        let request_rate = n / window_secs as f64;

        // 1: unique_paths
        let unique_paths = {
            let mut set = FxHashSet::default();
            for e in &events {
                set.insert(e.path_hash);
            }
            set.len() as f64
        };

        // 2: unique_hosts
        let unique_hosts = {
            let mut set = FxHashSet::default();
            for e in &events {
                set.insert(e.host_hash);
            }
            set.len() as f64
        };

        // 3: error_rate (fraction of 4xx/5xx)
        let errors = events.iter().filter(|e| e.status >= 400).count() as f64;
        let error_rate = errors / n;

        // 4: avg_duration_ms
        let avg_duration_ms = events.iter().map(|e| e.duration_ms as f64).sum::<f64>() / n;

        // 5: method_entropy (Shannon entropy of method distribution)
        let method_entropy = {
            let mut counts = [0u32; 8];
            for e in &events {
                counts[e.method as usize % 8] += 1;
            }
            let mut entropy = 0.0f64;
            for &c in &counts {
                if c > 0 {
                    let p = c as f64 / n;
                    entropy -= p * p.ln();
                }
            }
            entropy
        };

        // 6: burst_score (inverse mean inter-arrival time)
        let burst_score = if events.len() >= 2 {
            let mut timestamps: Vec<Instant> = events.iter().map(|e| e.timestamp).collect();
            timestamps.sort();
            let total_span = timestamps
                .last()
                .unwrap()
                .duration_since(*timestamps.first().unwrap())
                .as_secs_f64();
            if total_span > 0.0 {
                (events.len() - 1) as f64 / total_span
            } else {
                n // all events at same instant = maximum burstiness
            }
        } else {
            0.0
        };

        // 7: path_repetition (ratio of most-repeated path to total)
        let path_repetition = {
            let mut counts = rustc_hash::FxHashMap::default();
            for e in &events {
                *counts.entry(e.path_hash).or_insert(0u32) += 1;
            }
            let max_count = counts.values().copied().max().unwrap_or(0) as f64;
            max_count / n
        };

        // 8: avg_content_length
        let avg_content_length = events.iter().map(|e| e.content_length as f64).sum::<f64>() / n;

        // 9: unique_user_agents
        let unique_user_agents = {
            let mut set = FxHashSet::default();
            for e in &events {
                set.insert(e.user_agent_hash);
            }
            set.len() as f64
        };

        // 10: cookie_ratio (fraction of requests that have cookies)
        let cookie_ratio = events.iter().filter(|e| e.has_cookies).count() as f64 / n;

        // 11: referer_ratio (fraction of requests with a referer)
        let referer_ratio = events.iter().filter(|e| e.has_referer).count() as f64 / n;

        // 12: accept_language_ratio (fraction with accept-language)
        let accept_language_ratio =
            events.iter().filter(|e| e.has_accept_language).count() as f64 / n;

        // 13: suspicious_path_ratio (fraction hitting known-bad paths)
        let suspicious_path_ratio = events.iter().filter(|e| e.suspicious_path).count() as f64 / n;

        [
            request_rate,
            unique_paths,
            unique_hosts,
            error_rate,
            avg_duration_ms,
            method_entropy,
            burst_score,
            path_repetition,
            avg_content_length,
            unique_user_agents,
            cookie_ratio,
            referer_ratio,
            accept_language_ratio,
            suspicious_path_ratio,
        ]
    }
}

/// Method to u8.
pub fn method_to_u8(method: &str) -> u8 {
    match method {
        "GET" => 0,
        "POST" => 1,
        "PUT" => 2,
        "DELETE" => 3,
        "HEAD" => 4,
        "PATCH" => 5,
        "OPTIONS" => 6,
        _ => 7,
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
/// Normparams.
pub struct NormParams {
    /// Mins.
    pub mins: [f64; NUM_FEATURES],
    /// Maxs.
    pub maxs: [f64; NUM_FEATURES],
}

impl NormParams {
    pub fn from_data(vectors: &[FeatureVector]) -> Self {
        let mut mins = [f64::MAX; NUM_FEATURES];
        let mut maxs = [f64::MIN; NUM_FEATURES];
        for v in vectors {
            for i in 0..NUM_FEATURES {
                mins[i] = mins[i].min(v[i]);
                maxs[i] = maxs[i].max(v[i]);
            }
        }
        Self { mins, maxs }
    }

    pub fn normalize(&self, v: &FeatureVector) -> FeatureVector {
        let mut out = [0.0; NUM_FEATURES];
        for i in 0..NUM_FEATURES {
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

/// Feature extraction from parsed log entries (used by training pipeline).
/// Unlike IpState which uses Instant, this uses f64 timestamps from log parsing.
pub struct LogIpState {
    /// Timestamps.
    pub timestamps: Vec<f64>,
    /// Methods.
    pub methods: Vec<u8>,
    /// Path hashes.
    pub path_hashes: Vec<u64>,
    /// Host hashes.
    pub host_hashes: Vec<u64>,
    /// User agent hashes.
    pub user_agent_hashes: Vec<u64>,
    /// Statuses.
    pub statuses: Vec<u16>,
    /// Durations.
    pub durations: Vec<u32>,
    /// Content lengths.
    pub content_lengths: Vec<u32>,
    /// Has cookies.
    pub has_cookies: Vec<bool>,
    /// Has referer.
    pub has_referer: Vec<bool>,
    /// Has accept language.
    pub has_accept_language: Vec<bool>,
    /// Suspicious paths.
    pub suspicious_paths: Vec<bool>,
}

impl Default for LogIpState {
    fn default() -> Self {
        Self::new()
    }
}

impl LogIpState {
    pub fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            methods: Vec::new(),
            path_hashes: Vec::new(),
            host_hashes: Vec::new(),
            user_agent_hashes: Vec::new(),
            statuses: Vec::new(),
            durations: Vec::new(),
            content_lengths: Vec::new(),
            has_cookies: Vec::new(),
            has_referer: Vec::new(),
            has_accept_language: Vec::new(),
            suspicious_paths: Vec::new(),
        }
    }

    pub fn extract_features_for_window(
        &self,
        start: usize,
        end: usize,
        window_secs: f64,
    ) -> FeatureVector {
        let n = (end - start) as f64;
        if n < 1.0 {
            return [0.0; NUM_FEATURES];
        }

        let request_rate = n / window_secs;

        let unique_paths = {
            let mut set = FxHashSet::default();
            for i in start..end {
                set.insert(self.path_hashes[i]);
            }
            set.len() as f64
        };

        let unique_hosts = {
            let mut set = FxHashSet::default();
            for i in start..end {
                set.insert(self.host_hashes[i]);
            }
            set.len() as f64
        };

        let errors = self.statuses[start..end]
            .iter()
            .filter(|&&s| s >= 400)
            .count() as f64;
        let error_rate = errors / n;

        let avg_duration_ms = self.durations[start..end]
            .iter()
            .map(|&d| d as f64)
            .sum::<f64>()
            / n;

        let method_entropy = {
            let mut counts = [0u32; 8];
            for i in start..end {
                counts[self.methods[i] as usize % 8] += 1;
            }
            let mut entropy = 0.0f64;
            for &c in &counts {
                if c > 0 {
                    let p = c as f64 / n;
                    entropy -= p * p.ln();
                }
            }
            entropy
        };

        let burst_score = if (end - start) >= 2 {
            let total_span = self.timestamps[end - 1] - self.timestamps[start];
            if total_span > 0.0 {
                (end - start - 1) as f64 / total_span
            } else {
                n
            }
        } else {
            0.0
        };

        let path_repetition = {
            let mut counts = rustc_hash::FxHashMap::default();
            for i in start..end {
                *counts.entry(self.path_hashes[i]).or_insert(0u32) += 1;
            }
            let max_count = counts.values().copied().max().unwrap_or(0) as f64;
            max_count / n
        };

        let avg_content_length = self.content_lengths[start..end]
            .iter()
            .map(|&c| c as f64)
            .sum::<f64>()
            / n;

        let unique_user_agents = {
            let mut set = FxHashSet::default();
            for i in start..end {
                set.insert(self.user_agent_hashes[i]);
            }
            set.len() as f64
        };

        let cookie_ratio = self.has_cookies[start..end].iter().filter(|&&v| v).count() as f64 / n;
        let referer_ratio = self.has_referer[start..end].iter().filter(|&&v| v).count() as f64 / n;
        let accept_language_ratio = self.has_accept_language[start..end]
            .iter()
            .filter(|&&v| v)
            .count() as f64
            / n;
        let suspicious_path_ratio = self.suspicious_paths[start..end]
            .iter()
            .filter(|&&v| v)
            .count() as f64
            / n;

        [
            request_rate,
            unique_paths,
            unique_hosts,
            error_rate,
            avg_duration_ms,
            method_entropy,
            burst_score,
            path_repetition,
            avg_content_length,
            unique_user_agents,
            cookie_ratio,
            referer_ratio,
            accept_language_ratio,
            suspicious_path_ratio,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hash::FxHasher;
    use std::hash::{Hash, Hasher};

    fn fx(s: &str) -> u64 {
        let mut h = FxHasher::default();
        s.hash(&mut h);
        h.finish()
    }

    #[test]
    fn test_single_event_features() {
        let mut state = IpState::new(100);
        state.push(RequestEvent {
            timestamp: Instant::now(),
            method: 0,
            path_hash: fx("/"),
            host_hash: fx("example.com"),
            user_agent_hash: fx("curl/7.0"),
            status: 200,
            duration_ms: 10,
            content_length: 0,
            has_cookies: true,
            has_referer: false,
            has_accept_language: true,
            suspicious_path: false,
        });
        let features = state.extract_features(60);
        // request_rate = 1/60
        assert!(features[0] > 0.0);
        // error_rate = 0
        assert_eq!(features[3], 0.0);
        // path_repetition = 1.0 (only one path)
        assert_eq!(features[7], 1.0);
        // cookie_ratio = 1.0 (single event with cookies)
        assert_eq!(features[10], 1.0);
        // referer_ratio = 0.0
        assert_eq!(features[11], 0.0);
        // accept_language_ratio = 1.0
        assert_eq!(features[12], 1.0);
        // suspicious_path_ratio = 0.0
        assert_eq!(features[13], 0.0);
    }

    #[test]
    fn test_norm_params() {
        let data = vec![
            [
                0.0, 10.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            ],
            [
                1.0, 20.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
            ],
        ];
        let params = NormParams::from_data(&data);
        let normalized = params.normalize(&[
            0.5, 15.0, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5,
        ]);
        for &v in &normalized {
            assert!((v - 0.5).abs() < 1e-10);
        }
    }
}
