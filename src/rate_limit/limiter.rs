// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::{BucketConfig, RateLimitConfig};
use crate::rate_limit::cidr::{self, CidrBlock};
use crate::rate_limit::key::RateLimitKey;
use rustc_hash::FxHashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Instant;

const NUM_SHARDS: usize = 256;

/// Result of a rate limit check.
#[derive(Debug, PartialEq)]
pub enum RateLimitResult {
    /// Allow.
    Allow,
    /// Reject.
    Reject { retry_after: u64 },
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    authenticated: bool,
}

/// Ratelimiter.
pub struct RateLimiter {
    shards: Vec<RwLock<FxHashMap<RateLimitKey, Bucket>>>,
    bypass_cidrs: Vec<CidrBlock>,
    authenticated: BucketConfig,
    unauthenticated: BucketConfig,
    stale_after_secs: u64,
}

fn shard_index(key: &RateLimitKey) -> usize {
    let mut h = rustc_hash::FxHasher::default();
    key.hash(&mut h);
    h.finish() as usize % NUM_SHARDS
}

impl RateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        let shards = (0..NUM_SHARDS)
            .map(|_| RwLock::new(FxHashMap::default()))
            .collect();
        let bypass_cidrs = cidr::parse_cidrs(&config.bypass_cidrs);
        Self {
            shards,
            bypass_cidrs,
            authenticated: config.authenticated.clone(),
            unauthenticated: config.unauthenticated.clone(),
            stale_after_secs: config.stale_after_secs,
        }
    }

    /// Check whether a request should be allowed or rejected.
    pub fn check(&self, ip: IpAddr, key: RateLimitKey) -> RateLimitResult {
        // CIDR bypass
        if cidr::is_bypassed(ip, &self.bypass_cidrs) {
            return RateLimitResult::Allow;
        }

        let cfg = if key.is_authenticated() {
            &self.authenticated
        } else {
            &self.unauthenticated
        };

        let now = Instant::now();
        let idx = shard_index(&key);
        let mut shard = self.shards[idx].write().unwrap_or_else(|e| e.into_inner());

        let bucket = shard.entry(key).or_insert_with(|| Bucket {
            tokens: cfg.burst as f64,
            last_refill: now,
            authenticated: key.is_authenticated(),
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let tier = if bucket.authenticated {
            &self.authenticated
        } else {
            &self.unauthenticated
        };
        bucket.tokens = (bucket.tokens + elapsed * tier.rate).min(tier.burst as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateLimitResult::Allow
        } else {
            let retry_after = ((1.0 - bucket.tokens) / tier.rate).ceil() as u64;
            RateLimitResult::Reject {
                retry_after: retry_after.max(1),
            }
        }
    }

    /// Remove buckets that haven't been used for `stale_after_secs`.
    pub fn evict_stale(&self) {
        let now = Instant::now();
        let stale = std::time::Duration::from_secs(self.stale_after_secs);
        for shard in &self.shards {
            let mut map = shard.write().unwrap_or_else(|e| e.into_inner());
            map.retain(|_, bucket| now.duration_since(bucket.last_refill) < stale);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BucketConfig, RateLimitConfig};

    fn test_config() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            bypass_cidrs: vec!["10.0.0.0/8".into()],
            eviction_interval_secs: 60,
            stale_after_secs: 120,
            authenticated: BucketConfig {
                burst: 10,
                rate: 5.0,
            },
            unauthenticated: BucketConfig {
                burst: 3,
                rate: 1.0,
            },
        }
    }

    #[test]
    fn test_burst_exhaustion_then_reject() {
        let limiter = RateLimiter::new(&test_config());
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let key = RateLimitKey::Ip(ip);

        // Burst of 3 for unauthenticated
        for _ in 0..3 {
            assert_eq!(limiter.check(ip, key), RateLimitResult::Allow);
        }
        // 4th request should be rejected
        match limiter.check(ip, key) {
            RateLimitResult::Reject { retry_after } => {
                assert!(retry_after >= 1);
            }
            _ => panic!("expected reject"),
        }
    }

    #[test]
    fn test_refill_allows_again() {
        let limiter = RateLimiter::new(&test_config());
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let key = RateLimitKey::Ip(ip);

        // Exhaust burst
        for _ in 0..3 {
            limiter.check(ip, key);
        }
        assert!(matches!(
            limiter.check(ip, key),
            RateLimitResult::Reject { .. }
        ));

        // Manually simulate time passing by manipulating the bucket
        {
            let idx = shard_index(&key);
            let mut shard = limiter.shards[idx].write().unwrap();
            let bucket = shard.get_mut(&key).unwrap();
            // Pretend 2 seconds passed (rate=1.0/s → 2 tokens refill)
            bucket.last_refill -= std::time::Duration::from_secs(2);
        }

        assert_eq!(limiter.check(ip, key), RateLimitResult::Allow);
    }

    #[test]
    fn test_cidr_bypass() {
        let limiter = RateLimiter::new(&test_config());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let key = RateLimitKey::Ip(ip);

        // Should always allow for bypassed CIDRs, even after many requests
        for _ in 0..100 {
            assert_eq!(limiter.check(ip, key), RateLimitResult::Allow);
        }
    }

    #[test]
    fn test_authenticated_higher_burst() {
        let limiter = RateLimiter::new(&test_config());
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let key = RateLimitKey::Identity(12345);

        // Authenticated burst is 10
        for _ in 0..10 {
            assert_eq!(limiter.check(ip, key), RateLimitResult::Allow);
        }
        assert!(matches!(
            limiter.check(ip, key),
            RateLimitResult::Reject { .. }
        ));
    }

    #[test]
    fn test_independent_keys() {
        let limiter = RateLimiter::new(&test_config());
        let ip1: IpAddr = "203.0.113.1".parse().unwrap();
        let ip2: IpAddr = "203.0.113.2".parse().unwrap();

        // Exhaust ip1's burst
        for _ in 0..3 {
            limiter.check(ip1, RateLimitKey::Ip(ip1));
        }
        assert!(matches!(
            limiter.check(ip1, RateLimitKey::Ip(ip1)),
            RateLimitResult::Reject { .. }
        ));

        // ip2 should still be allowed
        assert_eq!(
            limiter.check(ip2, RateLimitKey::Ip(ip2)),
            RateLimitResult::Allow
        );
    }

    #[test]
    fn test_eviction() {
        let mut cfg = test_config();
        cfg.stale_after_secs = 0; // everything is stale immediately
        let limiter = RateLimiter::new(&cfg);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let key = RateLimitKey::Ip(ip);

        limiter.check(ip, key);
        // Buckets should be populated
        let idx = shard_index(&key);
        assert!(!limiter.shards[idx].read().unwrap().is_empty());

        // After eviction, buckets should be gone (stale_after_secs=0)
        std::thread::sleep(std::time::Duration::from_millis(10));
        limiter.evict_stale();
        assert!(limiter.shards[idx].read().unwrap().is_empty());
    }

    #[test]
    fn test_retry_after_value() {
        let limiter = RateLimiter::new(&test_config());
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let key = RateLimitKey::Ip(ip);

        // Exhaust burst (rate=1.0/s for unauth)
        for _ in 0..3 {
            limiter.check(ip, key);
        }
        match limiter.check(ip, key) {
            RateLimitResult::Reject { retry_after } => {
                // With rate=1.0, need ~1 token, so retry_after should be 1
                assert_eq!(retry_after, 1);
            }
            _ => panic!("expected reject"),
        }
    }
}
