// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Per-node atomic bandwidth counters. Zero contention on the hot path
/// (single `fetch_add` per counter per request).
pub struct BandwidthTracker {
    /// Bytes received since last broadcast (reset each cycle).
    bytes_in: AtomicU64,
    /// Bytes sent since last broadcast (reset each cycle).
    bytes_out: AtomicU64,
    /// Requests since last broadcast (reset each cycle).
    request_count: AtomicU64,
    /// Monotonic total bytes received (never reset).
    cumulative_in: AtomicU64,
    /// Monotonic total bytes sent (never reset).
    cumulative_out: AtomicU64,
}

impl BandwidthTracker {
    pub fn new() -> Self {
        Self {
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            request_count: AtomicU64::new(0),
            cumulative_in: AtomicU64::new(0),
            cumulative_out: AtomicU64::new(0),
        }
    }

    /// Record a completed request's byte counts.
    #[inline]
    pub fn record(&self, bytes_in: u64, bytes_out: u64) {
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        self.request_count.fetch_add(1, Ordering::Relaxed);
        self.cumulative_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.cumulative_out.fetch_add(bytes_out, Ordering::Relaxed);
    }

    /// Take a snapshot and reset the per-interval counters.
    pub fn snapshot_and_reset(&self) -> BandwidthSnapshot {
        BandwidthSnapshot {
            bytes_in: self.bytes_in.swap(0, Ordering::Relaxed),
            bytes_out: self.bytes_out.swap(0, Ordering::Relaxed),
            request_count: self.request_count.swap(0, Ordering::Relaxed),
            cumulative_in: self.cumulative_in.load(Ordering::Relaxed),
            cumulative_out: self.cumulative_out.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BandwidthSnapshot {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub request_count: u64,
    pub cumulative_in: u64,
    pub cumulative_out: u64,
}

/// Aggregated bandwidth state from all cluster peers.
pub struct ClusterBandwidthState {
    peers: RwLock<FxHashMap<[u8; 32], PeerEntry>>,
    /// Sum of all peers' cumulative bytes in (updated on each report).
    pub total_bytes_in: AtomicU64,
    /// Sum of all peers' cumulative bytes out.
    pub total_bytes_out: AtomicU64,
    /// Number of active (non-stale) peers.
    pub peer_count: AtomicU64,
    /// Stale peer timeout.
    stale_timeout_secs: u64,
}

struct PeerEntry {
    cumulative_in: u64,
    cumulative_out: u64,
    last_seen: Instant,
}

impl ClusterBandwidthState {
    pub fn new(stale_timeout_secs: u64) -> Self {
        Self {
            peers: RwLock::new(FxHashMap::default()),
            total_bytes_in: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
            peer_count: AtomicU64::new(0),
            stale_timeout_secs,
        }
    }

    /// Update a peer's bandwidth state from a received report.
    pub fn update_peer(&self, peer_id: [u8; 32], cumulative_in: u64, cumulative_out: u64) {
        let mut peers = self.peers.write().unwrap();
        peers.insert(
            peer_id,
            PeerEntry {
                cumulative_in,
                cumulative_out,
                last_seen: Instant::now(),
            },
        );
        self.recalculate(&peers);
    }

    /// Remove peers that haven't reported within the stale timeout.
    pub fn evict_stale(&self) {
        let mut peers = self.peers.write().unwrap();
        let cutoff = Instant::now() - std::time::Duration::from_secs(self.stale_timeout_secs);
        peers.retain(|_, entry| entry.last_seen > cutoff);
        self.recalculate(&peers);
    }

    fn recalculate(&self, peers: &FxHashMap<[u8; 32], PeerEntry>) {
        let mut total_in = 0u64;
        let mut total_out = 0u64;
        for entry in peers.values() {
            total_in = total_in.saturating_add(entry.cumulative_in);
            total_out = total_out.saturating_add(entry.cumulative_out);
        }
        self.total_bytes_in.store(total_in, Ordering::Relaxed);
        self.total_bytes_out.store(total_out, Ordering::Relaxed);
        self.peer_count.store(peers.len() as u64, Ordering::Relaxed);
    }
}

/// Aggregate bandwidth rate across the entire cluster, computed from a
/// sliding window of samples from all nodes (local + remote).
///
/// Each broadcast cycle produces one sample per node. With a 5s broadcast
/// interval and 30s window, the deque holds ~6 × node_count entries — tiny.
pub struct BandwidthMeter {
    samples: RwLock<VecDeque<Sample>>,
    window: Duration,
}

struct Sample {
    time: Instant,
    bytes_in: u64,
    bytes_out: u64,
}

/// Snapshot of the aggregate cluster-wide bandwidth rate.
/// All rates are in bytes/sec. Use the `*_mib_per_sec` methods for MiB/s (power-of-2).
#[derive(Debug, Clone, Copy)]
pub struct AggregateRate {
    /// Inbound bytes/sec across all nodes.
    pub bytes_in_per_sec: f64,
    /// Outbound bytes/sec across all nodes.
    pub bytes_out_per_sec: f64,
    /// Total (in + out) bytes/sec.
    pub total_per_sec: f64,
    /// Number of samples in the window.
    pub sample_count: usize,
}

const BYTES_PER_MIB: f64 = 1_048_576.0; // 1024 * 1024

impl AggregateRate {
    /// Inbound rate in MiB/s (power-of-2).
    pub fn in_mib_per_sec(&self) -> f64 {
        self.bytes_in_per_sec / BYTES_PER_MIB
    }

    /// Outbound rate in MiB/s (power-of-2).
    pub fn out_mib_per_sec(&self) -> f64 {
        self.bytes_out_per_sec / BYTES_PER_MIB
    }

    /// Total rate in MiB/s (power-of-2).
    pub fn total_mib_per_sec(&self) -> f64 {
        self.total_per_sec / BYTES_PER_MIB
    }
}

impl BandwidthMeter {
    pub fn new(window_secs: u64) -> Self {
        Self {
            samples: RwLock::new(VecDeque::new()),
            window: Duration::from_secs(window_secs),
        }
    }

    /// Record a bandwidth sample (from local broadcast or remote peer report).
    pub fn record_sample(&self, bytes_in: u64, bytes_out: u64) {
        let now = Instant::now();
        let mut samples = self.samples.write().unwrap();
        samples.push_back(Sample {
            time: now,
            bytes_in,
            bytes_out,
        });
        // Evict samples outside the window.
        let cutoff = now - self.window;
        while samples.front().is_some_and(|s| s.time < cutoff) {
            samples.pop_front();
        }
    }

    /// Compute the aggregate bandwidth rate over the sliding window.
    pub fn aggregate_rate(&self) -> AggregateRate {
        let now = Instant::now();
        let samples = self.samples.read().unwrap();
        let cutoff = now - self.window;

        let mut total_in = 0u64;
        let mut total_out = 0u64;
        let mut count = 0usize;

        for s in samples.iter() {
            if s.time >= cutoff {
                total_in = total_in.saturating_add(s.bytes_in);
                total_out = total_out.saturating_add(s.bytes_out);
                count += 1;
            }
        }

        let window_secs = self.window.as_secs_f64();
        let bytes_in_per_sec = total_in as f64 / window_secs;
        let bytes_out_per_sec = total_out as f64 / window_secs;

        AggregateRate {
            bytes_in_per_sec,
            bytes_out_per_sec,
            total_per_sec: bytes_in_per_sec + bytes_out_per_sec,
            sample_count: count,
        }
    }
}

/// Cluster-wide bandwidth limiter. Compares the aggregate rate from the
/// `BandwidthMeter` against a configurable cap (bytes/sec). The limit is
/// stored as an `AtomicU64` so it can be updated at runtime (e.g. when a
/// license quota changes via gossip).
pub struct BandwidthLimiter {
    /// Max total (in + out) bytes/sec across the cluster. 0 = unlimited.
    limit_bytes_per_sec: AtomicU64,
    meter: std::sync::Arc<BandwidthMeter>,
}

/// Result of a bandwidth limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthLimitResult {
    Allow,
    Reject,
}

impl BandwidthLimiter {
    pub fn new(meter: std::sync::Arc<BandwidthMeter>, limit_bytes_per_sec: u64) -> Self {
        Self {
            limit_bytes_per_sec: AtomicU64::new(limit_bytes_per_sec),
            meter,
        }
    }

    /// Check whether the cluster is currently over its bandwidth cap.
    #[inline]
    pub fn check(&self) -> BandwidthLimitResult {
        let limit = self.limit_bytes_per_sec.load(Ordering::Relaxed);
        if limit == 0 {
            return BandwidthLimitResult::Allow;
        }
        let rate = self.meter.aggregate_rate();
        if rate.total_per_sec > limit as f64 {
            BandwidthLimitResult::Reject
        } else {
            BandwidthLimitResult::Allow
        }
    }

    /// Update the bandwidth cap at runtime (e.g. from a license update).
    pub fn set_limit(&self, bytes_per_sec: u64) {
        self.limit_bytes_per_sec.store(bytes_per_sec, Ordering::Relaxed);
    }

    /// Current limit in bytes/sec (0 = unlimited).
    pub fn limit(&self) -> u64 {
        self.limit_bytes_per_sec.load(Ordering::Relaxed)
    }

    /// Current aggregate rate snapshot.
    pub fn current_rate(&self) -> AggregateRate {
        self.meter.aggregate_rate()
    }
}

/// Convert Gbps (base-10, as used in networking/billing) to bytes/sec.
/// 1 Gbps = 1_000_000_000 bits/sec = 125_000_000 bytes/sec.
pub fn gbps_to_bytes_per_sec(gbps: f64) -> u64 {
    (gbps * 125_000_000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_record_and_snapshot() {
        let tracker = BandwidthTracker::new();
        tracker.record(100, 200);
        tracker.record(50, 75);

        let snap = tracker.snapshot_and_reset();
        assert_eq!(snap.bytes_in, 150);
        assert_eq!(snap.bytes_out, 275);
        assert_eq!(snap.request_count, 2);
        assert_eq!(snap.cumulative_in, 150);
        assert_eq!(snap.cumulative_out, 275);

        // After reset, interval counters are zero but cumulative persists.
        tracker.record(10, 20);
        let snap2 = tracker.snapshot_and_reset();
        assert_eq!(snap2.bytes_in, 10);
        assert_eq!(snap2.bytes_out, 20);
        assert_eq!(snap2.request_count, 1);
        assert_eq!(snap2.cumulative_in, 160);
        assert_eq!(snap2.cumulative_out, 295);
    }

    #[test]
    fn meter_aggregate_rate() {
        let meter = BandwidthMeter::new(30);
        // Simulate 6 samples over the window (one every 5s).
        // In reality they come from multiple nodes; we don't care about source.
        meter.record_sample(500_000_000, 100_000_000); // 500MB in, 100MB out
        meter.record_sample(50_000_000, 10_000_000); // 50MB in, 10MB out

        let rate = meter.aggregate_rate();
        assert_eq!(rate.sample_count, 2);
        // total_in = 550MB over 30s window = ~18.3 MB/s
        let expected_in = 550_000_000.0 / 30.0;
        assert!(
            (rate.bytes_in_per_sec - expected_in).abs() < 1.0,
            "expected ~{expected_in}, got {}",
            rate.bytes_in_per_sec
        );
        let expected_out = 110_000_000.0 / 30.0;
        assert!(
            (rate.bytes_out_per_sec - expected_out).abs() < 1.0,
            "expected ~{expected_out}, got {}",
            rate.bytes_out_per_sec
        );
        assert!(
            (rate.total_per_sec - (expected_in + expected_out)).abs() < 1.0,
        );
    }

    #[test]
    fn meter_evicts_old_samples() {
        // Use a 1-second window so we can test eviction quickly.
        let meter = BandwidthMeter::new(1);
        meter.record_sample(1000, 2000);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // Sample should be evicted.
        meter.record_sample(500, 600);

        let rate = meter.aggregate_rate();
        assert_eq!(rate.sample_count, 1, "old sample should be evicted");
        // Only the second sample should be counted.
        assert!((rate.bytes_in_per_sec - 500.0).abs() < 1.0);
    }

    #[test]
    fn meter_empty_returns_zero() {
        let meter = BandwidthMeter::new(30);
        let rate = meter.aggregate_rate();
        assert_eq!(rate.sample_count, 0);
        assert_eq!(rate.bytes_in_per_sec, 0.0);
        assert_eq!(rate.bytes_out_per_sec, 0.0);
        assert_eq!(rate.total_per_sec, 0.0);
    }

    #[test]
    fn cluster_state_aggregation() {
        let state = ClusterBandwidthState::new(30);
        state.update_peer([1u8; 32], 1000, 2000);
        state.update_peer([2u8; 32], 3000, 4000);

        assert_eq!(state.total_bytes_in.load(Ordering::Relaxed), 4000);
        assert_eq!(state.total_bytes_out.load(Ordering::Relaxed), 6000);
        assert_eq!(state.peer_count.load(Ordering::Relaxed), 2);

        // Update existing peer.
        state.update_peer([1u8; 32], 1500, 2500);
        assert_eq!(state.total_bytes_in.load(Ordering::Relaxed), 4500);
        assert_eq!(state.total_bytes_out.load(Ordering::Relaxed), 6500);
        assert_eq!(state.peer_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn limiter_allows_when_unlimited() {
        let meter = std::sync::Arc::new(BandwidthMeter::new(30));
        meter.record_sample(999_999_999, 999_999_999);
        let limiter = BandwidthLimiter::new(meter, 0); // 0 = unlimited
        assert_eq!(limiter.check(), BandwidthLimitResult::Allow);
    }

    #[test]
    fn limiter_allows_under_cap() {
        let meter = std::sync::Arc::new(BandwidthMeter::new(30));
        // 1 GiB total over 30s = ~33 MiB/s ≈ ~35 MB/s — well under 1 Gbps
        meter.record_sample(500_000_000, 500_000_000);
        let limiter = BandwidthLimiter::new(meter, gbps_to_bytes_per_sec(1.0));
        assert_eq!(limiter.check(), BandwidthLimitResult::Allow);
    }

    #[test]
    fn limiter_rejects_over_cap() {
        let meter = std::sync::Arc::new(BandwidthMeter::new(1)); // 1s window
        // 200 MB total in 1s window = 200 MB/s > 125 MB/s (1 Gbps)
        meter.record_sample(100_000_000, 100_000_000);
        let limiter = BandwidthLimiter::new(meter, gbps_to_bytes_per_sec(1.0));
        assert_eq!(limiter.check(), BandwidthLimitResult::Reject);
    }

    #[test]
    fn limiter_set_limit_runtime() {
        let meter = std::sync::Arc::new(BandwidthMeter::new(1));
        meter.record_sample(100_000_000, 100_000_000); // 200 MB/s
        let limiter = BandwidthLimiter::new(meter, gbps_to_bytes_per_sec(1.0));
        assert_eq!(limiter.check(), BandwidthLimitResult::Reject);

        // Raise the limit to 10 Gbps → should now allow.
        limiter.set_limit(gbps_to_bytes_per_sec(10.0));
        assert_eq!(limiter.check(), BandwidthLimitResult::Allow);
        assert_eq!(limiter.limit(), gbps_to_bytes_per_sec(10.0));
    }

    #[test]
    fn gbps_conversion() {
        assert_eq!(gbps_to_bytes_per_sec(1.0), 125_000_000);
        assert_eq!(gbps_to_bytes_per_sec(10.0), 1_250_000_000);
        assert_eq!(gbps_to_bytes_per_sec(0.0), 0);
    }
}
