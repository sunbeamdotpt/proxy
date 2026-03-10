use crate::config::{DDoSConfig, RateLimitConfig};
use crate::ddos::audit_log::{self, AuditLog};
use crate::ddos::detector::DDoSDetector;
use crate::ddos::model::{DDoSAction, TrainedModel};
use crate::rate_limit::key::RateLimitKey;
use crate::rate_limit::limiter::{RateLimitResult, RateLimiter};
use anyhow::{Context, Result};
use rustc_hash::FxHashMap;
use std::io::BufRead;
use std::net::IpAddr;
use std::sync::Arc;

pub struct ReplayArgs {
    pub input: String,
    pub model_path: String,
    pub config_path: Option<String>,
    pub k: usize,
    pub threshold: f64,
    pub window_secs: u64,
    pub min_events: usize,
    pub rate_limit: bool,
}

struct ReplayStats {
    total: u64,
    skipped: u64,
    ddos_blocked: u64,
    rate_limited: u64,
    allowed: u64,
    ddos_blocked_ips: FxHashMap<String, u64>,
    rate_limited_ips: FxHashMap<String, u64>,
}

pub fn run(args: ReplayArgs) -> Result<()> {
    eprintln!("Loading model from {}...", args.model_path);
    let model = TrainedModel::load(
        std::path::Path::new(&args.model_path),
        Some(args.k),
        Some(args.threshold),
    )
    .with_context(|| format!("loading model from {}", args.model_path))?;
    eprintln!("  {} training points, k={}, threshold={}", model.point_count(), args.k, args.threshold);

    let ddos_cfg = DDoSConfig {
        model_path: args.model_path.clone(),
        k: args.k,
        threshold: args.threshold,
        window_secs: args.window_secs,
        window_capacity: 1000,
        min_events: args.min_events,
        enabled: true,
    };
    let detector = Arc::new(DDoSDetector::new(model, &ddos_cfg));

    // Optionally set up rate limiter
    let rate_limiter = if args.rate_limit {
        let rl_cfg = if let Some(cfg_path) = &args.config_path {
            let cfg = crate::config::Config::load(cfg_path)?;
            cfg.rate_limit.unwrap_or_else(default_rate_limit_config)
        } else {
            default_rate_limit_config()
        };
        eprintln!(
            "  Rate limiter: auth burst={} rate={}/s, unauth burst={} rate={}/s",
            rl_cfg.authenticated.burst,
            rl_cfg.authenticated.rate,
            rl_cfg.unauthenticated.burst,
            rl_cfg.unauthenticated.rate,
        );
        Some(RateLimiter::new(&rl_cfg))
    } else {
        None
    };

    eprintln!("Replaying {}...\n", args.input);

    let file = std::fs::File::open(&args.input)
        .with_context(|| format!("opening {}", args.input))?;
    let reader = std::io::BufReader::new(file);

    let mut stats = ReplayStats {
        total: 0,
        skipped: 0,
        ddos_blocked: 0,
        rate_limited: 0,
        allowed: 0,
        ddos_blocked_ips: FxHashMap::default(),
        rate_limited_ips: FxHashMap::default(),
    };

    for line in reader.lines() {
        let line = line?;
        let entry: AuditLog = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => {
                stats.skipped += 1;
                continue;
            }
        };

        if entry.fields.method.is_empty() {
            stats.skipped += 1;
            continue;
        }

        stats.total += 1;

        let ip_str = audit_log::strip_port(&entry.fields.client_ip).to_string();
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                stats.skipped += 1;
                continue;
            }
        };

        // DDoS check
        let has_cookies = entry.fields.has_cookies.unwrap_or(false);
        let has_referer = entry.fields.referer.as_deref().map(|r| r != "-").unwrap_or(false);
        let has_accept_language = entry.fields.accept_language.as_deref().map(|a| a != "-").unwrap_or(false);
        let ddos_action = detector.check(
            ip,
            &entry.fields.method,
            &entry.fields.path,
            &entry.fields.host,
            &entry.fields.user_agent,
            entry.fields.content_length,
            has_cookies,
            has_referer,
            has_accept_language,
        );

        if ddos_action == DDoSAction::Block {
            stats.ddos_blocked += 1;
            *stats.ddos_blocked_ips.entry(ip_str.clone()).or_insert(0) += 1;
            continue;
        }

        // Rate limit check
        if let Some(limiter) = &rate_limiter {
            // Audit logs don't have auth headers, so all traffic is keyed by IP
            let rl_key = RateLimitKey::Ip(ip);
            if let RateLimitResult::Reject { .. } = limiter.check(ip, rl_key) {
                stats.rate_limited += 1;
                *stats.rate_limited_ips.entry(ip_str.clone()).or_insert(0) += 1;
                continue;
            }
        }

        stats.allowed += 1;
    }

    // Report
    let total = stats.total;
    eprintln!("═══ Replay Results ═══════════════════════════════════════");
    eprintln!("  Total requests:    {total}");
    eprintln!("  Skipped (parse):   {}", stats.skipped);
    eprintln!("  Allowed:           {} ({:.1}%)", stats.allowed, pct(stats.allowed, total));
    eprintln!("  DDoS blocked:      {} ({:.1}%)", stats.ddos_blocked, pct(stats.ddos_blocked, total));
    if rate_limiter.is_some() {
        eprintln!("  Rate limited:      {} ({:.1}%)", stats.rate_limited, pct(stats.rate_limited, total));
    }

    if !stats.ddos_blocked_ips.is_empty() {
        eprintln!("\n── DDoS-blocked IPs (top 20) ─────────────────────────────");
        let mut sorted: Vec<_> = stats.ddos_blocked_ips.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (ip, count) in sorted.iter().take(20) {
            eprintln!("  {:<40} {} reqs blocked", ip, count);
        }
    }

    if !stats.rate_limited_ips.is_empty() {
        eprintln!("\n── Rate-limited IPs (top 20) ─────────────────────────────");
        let mut sorted: Vec<_> = stats.rate_limited_ips.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (ip, count) in sorted.iter().take(20) {
            eprintln!("  {:<40} {} reqs limited", ip, count);
        }
    }

    // Check for false positives: IPs that were blocked but had 2xx statuses in the original logs
    eprintln!("\n── False positive check ──────────────────────────────────");
    check_false_positives(&args.input, &stats)?;

    eprintln!("══════════════════════════════════════════════════════════");
    Ok(())
}

/// Re-scan the log to find blocked IPs that had mostly 2xx responses originally
/// (i.e. they were legitimate traffic that the model would incorrectly block).
fn check_false_positives(input: &str, stats: &ReplayStats) -> Result<()> {
    let blocked_ips: rustc_hash::FxHashSet<&str> = stats
        .ddos_blocked_ips
        .keys()
        .chain(stats.rate_limited_ips.keys())
        .map(|s| s.as_str())
        .collect();

    if blocked_ips.is_empty() {
        eprintln!("  No blocked IPs — nothing to check.");
        return Ok(());
    }

    // Collect original status codes for blocked IPs
    let file = std::fs::File::open(input)?;
    let reader = std::io::BufReader::new(file);
    let mut ip_statuses: FxHashMap<String, Vec<u16>> = FxHashMap::default();

    for line in reader.lines() {
        let line = line?;
        let entry: AuditLog = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let ip_str = audit_log::strip_port(&entry.fields.client_ip).to_string();
        if blocked_ips.contains(ip_str.as_str()) {
            ip_statuses
                .entry(ip_str)
                .or_default()
                .push(entry.fields.status);
        }
    }

    let mut suspects = Vec::new();
    for (ip, statuses) in &ip_statuses {
        let total = statuses.len();
        let ok_count = statuses.iter().filter(|&&s| (200..400).contains(&s)).count();
        let ok_pct = (ok_count as f64 / total as f64) * 100.0;
        // If >60% of original responses were 2xx/3xx, this might be a false positive
        if ok_pct > 60.0 {
            let blocked = stats
                .ddos_blocked_ips
                .get(ip)
                .copied()
                .unwrap_or(0)
                + stats
                    .rate_limited_ips
                    .get(ip)
                    .copied()
                    .unwrap_or(0);
            suspects.push((ip.clone(), total, ok_pct, blocked));
        }
    }

    if suspects.is_empty() {
        eprintln!("  No likely false positives found.");
    } else {
        suspects.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
        eprintln!("  ⚠ {} IPs were blocked but had mostly successful responses:", suspects.len());
        for (ip, total, ok_pct, blocked) in suspects.iter().take(15) {
            eprintln!(
                "    {:<40} {}/{} reqs were 2xx/3xx ({:.0}%), {} blocked",
                ip, ((*ok_pct / 100.0) * *total as f64) as u64, total, ok_pct, blocked,
            );
        }
    }

    Ok(())
}

fn default_rate_limit_config() -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        bypass_cidrs: vec![
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
            "100.64.0.0/10".into(),
            "fd00::/8".into(),
        ],
        eviction_interval_secs: 300,
        stale_after_secs: 600,
        authenticated: crate::config::BucketConfig {
            burst: 200,
            rate: 50.0,
        },
        unauthenticated: crate::config::BucketConfig {
            burst: 60,
            rate: 15.0,
        },
    }
}

fn pct(n: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (n as f64 / total as f64) * 100.0
    }
}
