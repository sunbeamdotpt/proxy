// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::BotAllowlistRule;
use crate::rate_limit::cidr::CidrBlock;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// A compiled bot allowlist rule (ready for hot-path matching).
struct CompiledRule {
    ua_prefix_lower: String,
    reason: String,
    dns_suffixes: Vec<String>,
    cidrs: Vec<CidrBlock>,
}

#[derive(Clone)]
struct CacheEntry {
    rule_idx: usize,
    verified: bool,
    created: Instant,
}

/// Bot allowlist with CIDR verification (instant) and DNS verification (cached).
///
/// Safe to share via `Arc<BotAllowlist>`. Interior mutability is limited to:
/// - `verified_cache`: RwLock around the IP→verified map (write-rare, read-often)
/// - `pending_tx`: mpsc sender to queue background DNS verification
pub struct BotAllowlist {
    rules: Vec<CompiledRule>,
    verified_cache: RwLock<FxHashMap<IpAddr, CacheEntry>>,
    pending_tx: std::sync::mpsc::Sender<PendingVerification>,
    cache_ttl: Duration,
}

struct PendingVerification {
    ip: IpAddr,
    rule_idx: usize,
    dns_suffixes: Vec<String>,
}

impl BotAllowlist {
    /// Create the allowlist and spawn the background DNS verification worker.
    /// Returns the allowlist wrapped in Arc (needed for cache sharing with worker).
    pub fn spawn(rules: &[BotAllowlistRule], cache_ttl_secs: u64) -> std::sync::Arc<Self> {
        let compiled: Vec<CompiledRule> = rules
            .iter()
            .map(|r| CompiledRule {
                ua_prefix_lower: r.ua_prefix.to_ascii_lowercase(),
                reason: r.reason.clone(),
                dns_suffixes: r
                    .dns_suffixes
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                cidrs: r.cidrs.iter().filter_map(|s| CidrBlock::parse(s)).collect(),
            })
            .collect();

        let (tx, rx) = std::sync::mpsc::channel();
        let cache_ttl = Duration::from_secs(cache_ttl_secs);

        let allowlist = std::sync::Arc::new(Self {
            rules: compiled,
            verified_cache: RwLock::new(FxHashMap::default()),
            pending_tx: tx,
            cache_ttl,
        });

        // Spawn background DNS verification worker.
        let worker_cache = allowlist.clone();
        std::thread::spawn(move || dns_verification_worker(rx, worker_cache));

        allowlist
    }

    /// Check if a request from `ip` with `user_agent` matches a verified bot.
    /// Returns the allowlist reason if verified, None otherwise.
    ///
    /// Hot path: one lowercase + prefix scan + hash lookup or CIDR check.
    pub fn check(&self, user_agent: &str, ip: IpAddr) -> Option<&str> {
        let ua_lower = user_agent.to_ascii_lowercase();

        for (idx, rule) in self.rules.iter().enumerate() {
            if !ua_lower.starts_with(&rule.ua_prefix_lower) {
                continue;
            }

            // UA matches. Now verify the IP.

            // 1. No verification configured → UA match alone is sufficient.
            if rule.cidrs.is_empty() && rule.dns_suffixes.is_empty() {
                return Some(&rule.reason);
            }

            // 2. CIDR verification (instant).
            if !rule.cidrs.is_empty() {
                if rule.cidrs.iter().any(|c| c.contains(ip)) {
                    return Some(&rule.reason);
                }
                // CIDR didn't match. If no DNS suffixes configured, this is a
                // spoofed UA — fall through to scanner model.
                if rule.dns_suffixes.is_empty() {
                    return None;
                }
            }

            // 3. DNS verification (cached).
            if !rule.dns_suffixes.is_empty() {
                // Check cache first.
                let cache = self
                    .verified_cache
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(entry) = cache.get(&ip)
                    && entry.created.elapsed() < self.cache_ttl
                {
                    if entry.verified && entry.rule_idx == idx {
                        return Some(&rule.reason);
                    }
                    // Cached as NOT verified → spoofed UA.
                    return None;
                }
                // Expired — fall through to re-queue.
                drop(cache);

                // Cache miss or expired → queue for background verification.
                let _ = self.pending_tx.send(PendingVerification {
                    ip,
                    rule_idx: idx,
                    dns_suffixes: rule.dns_suffixes.clone(),
                });

                // First request from this IP → don't allowlist yet.
                // The scanner model decides. Once DNS verifies, future
                // requests get the allowlist.
                return None;
            }
        }

        None
    }

    /// Evict expired entries from the verified cache.
    pub fn evict_stale(&self) {
        let mut cache = self
            .verified_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, entry| entry.created.elapsed() < self.cache_ttl);
    }
}

/// Background worker that processes DNS verification requests.
fn dns_verification_worker(
    rx: std::sync::mpsc::Receiver<PendingVerification>,
    allowlist: std::sync::Arc<BotAllowlist>,
) {
    while let Ok(req) = rx.recv() {
        // Skip if already cached and not expired.
        {
            let cache = allowlist
                .verified_cache
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = cache.get(&req.ip)
                && entry.created.elapsed() < allowlist.cache_ttl
            {
                continue;
            }
        }

        let verified = verify_dns(req.ip, &req.dns_suffixes);
        let entry = CacheEntry {
            rule_idx: req.rule_idx,
            verified,
            created: Instant::now(),
        };

        let mut cache = allowlist
            .verified_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        cache.insert(req.ip, entry);

        if verified {
            tracing::info!(
                ip = %req.ip,
                rule_idx = req.rule_idx,
                "bot IP verified via reverse DNS"
            );
        } else {
            tracing::debug!(
                ip = %req.ip,
                rule_idx = req.rule_idx,
                "bot IP failed DNS verification (possible UA spoofing)"
            );
        }
    }
}

/// Reverse DNS → check suffix → forward DNS → confirm IP.
fn verify_dns(ip: IpAddr, suffixes: &[String]) -> bool {
    // Step 1: reverse DNS lookup.
    let hostname = match dns_lookup::lookup_addr(&ip) {
        Ok(name) => name.to_ascii_lowercase(),
        Err(_) => return false,
    };

    // Step 2: hostname must end with one of the allowed suffixes.
    let suffix_match = suffixes
        .iter()
        .any(|s| hostname.ends_with(s) || hostname.ends_with(&format!(".{s}")));
    if !suffix_match {
        return false;
    }

    // Step 3: forward DNS — the hostname must resolve back to our IP.
    match dns_lookup::lookup_host(&hostname) {
        Ok(mut addrs) => addrs.any(|a| a == ip),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BotAllowlistRule;

    #[test]
    fn test_ua_only_rule_matches() {
        let rules = vec![BotAllowlistRule {
            ua_prefix: "CCBot".into(),
            reason: "commoncrawl".into(),
            dns_suffixes: vec![],
            cidrs: vec![],
        }];
        let al = BotAllowlist::spawn(&rules, 3600);
        assert_eq!(
            al.check(
                "CCBot/2.0 (https://commoncrawl.org)",
                "1.2.3.4".parse().unwrap()
            ),
            Some("commoncrawl"),
        );
        assert_eq!(al.check("Mozilla/5.0", "1.2.3.4".parse().unwrap()), None,);
    }

    #[test]
    fn test_cidr_verification_matches() {
        let rules = vec![BotAllowlistRule {
            ua_prefix: "GPTBot".into(),
            reason: "openai".into(),
            dns_suffixes: vec![],
            cidrs: vec!["23.98.0.0/16".into()],
        }];
        let al = BotAllowlist::spawn(&rules, 3600);
        assert_eq!(
            al.check("GPTBot/1.0", "23.98.1.2".parse().unwrap()),
            Some("openai"),
        );
        // Wrong IP → spoofed UA
        assert_eq!(al.check("GPTBot/1.0", "1.2.3.4".parse().unwrap()), None,);
    }

    #[test]
    fn test_cidr_verification_case_insensitive_ua() {
        let rules = vec![BotAllowlistRule {
            ua_prefix: "GPTBot".into(),
            reason: "openai".into(),
            dns_suffixes: vec![],
            cidrs: vec!["23.98.0.0/16".into()],
        }];
        let al = BotAllowlist::spawn(&rules, 3600);
        assert_eq!(
            al.check("gptbot/1.0", "23.98.1.2".parse().unwrap()),
            Some("openai"),
        );
    }

    #[test]
    fn test_dns_rule_returns_none_on_cache_miss() {
        let rules = vec![BotAllowlistRule {
            ua_prefix: "Googlebot".into(),
            reason: "google".into(),
            dns_suffixes: vec!["googlebot.com".into()],
            cidrs: vec![],
        }];
        let al = BotAllowlist::spawn(&rules, 3600);
        // First check → cache miss → queues DNS → returns None
        assert_eq!(
            al.check("Googlebot/2.1", "66.249.64.1".parse().unwrap()),
            None,
        );
    }

    #[test]
    fn test_no_ua_match_returns_none() {
        let rules = vec![BotAllowlistRule {
            ua_prefix: "GPTBot".into(),
            reason: "openai".into(),
            dns_suffixes: vec![],
            cidrs: vec!["23.98.0.0/16".into()],
        }];
        let al = BotAllowlist::spawn(&rules, 3600);
        assert_eq!(
            al.check("Mozilla/5.0 Chrome/120", "23.98.1.2".parse().unwrap()),
            None,
        );
    }

    #[test]
    fn test_verify_dns_with_bad_ip() {
        // This IP almost certainly won't reverse-resolve to googlebot.com
        assert!(!verify_dns(
            "127.0.0.1".parse().unwrap(),
            &["googlebot.com".into()]
        ));
    }
}
