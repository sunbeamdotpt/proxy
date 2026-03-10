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

pub struct ReplayResult {
    pub total: u64,
    pub skipped: u64,
    pub ddos_blocked: u64,
    pub rate_limited: u64,
    pub allowed: u64,
    pub ddos_blocked_ips: FxHashMap<String, u64>,
    pub rate_limited_ips: FxHashMap<String, u64>,
    pub false_positive_ips: usize,
    pub true_positive_ips: usize,
}

/// Core replay pipeline: load model, replay logs, compute stats including false positive analysis.
pub fn replay_and_evaluate(args: &ReplayArgs) -> Result<ReplayResult> {
    let model = TrainedModel::load(
        std::path::Path::new(&args.model_path),
        Some(args.k),
        Some(args.threshold),
    )
    .with_context(|| format!("loading model from {}", args.model_path))?;

    let ddos_cfg = DDoSConfig {
        model_path: Some(args.model_path.clone()),
        k: args.k,
        threshold: args.threshold,
        window_secs: args.window_secs,
        window_capacity: 1000,
        min_events: args.min_events,
        enabled: true,
        use_ensemble: false,
    };
    let detector = Arc::new(DDoSDetector::new(model, &ddos_cfg));

    let rate_limiter = if args.rate_limit {
        let rl_cfg = if let Some(cfg_path) = &args.config_path {
            let cfg = crate::config::Config::load(cfg_path)?;
            cfg.rate_limit.unwrap_or_else(default_rate_limit_config)
        } else {
            default_rate_limit_config()
        };
        Some(RateLimiter::new(&rl_cfg))
    } else {
        None
    };

    let file = std::fs::File::open(&args.input)
        .with_context(|| format!("opening {}", args.input))?;
    let reader = std::io::BufReader::new(file);

    let mut total = 0u64;
    let mut skipped = 0u64;
    let mut ddos_blocked = 0u64;
    let mut rate_limited = 0u64;
    let mut allowed = 0u64;
    let mut ddos_blocked_ips: FxHashMap<String, u64> = FxHashMap::default();
    let mut rate_limited_ips: FxHashMap<String, u64> = FxHashMap::default();

    for line in reader.lines() {
        let line = line?;
        let entry: AuditLog = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        if entry.fields.method.is_empty() {
            skipped += 1;
            continue;
        }

        total += 1;

        let ip_str = audit_log::strip_port(&entry.fields.client_ip).to_string();
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

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
            ddos_blocked += 1;
            *ddos_blocked_ips.entry(ip_str.clone()).or_insert(0) += 1;
            continue;
        }

        if let Some(limiter) = &rate_limiter {
            let rl_key = RateLimitKey::Ip(ip);
            if let RateLimitResult::Reject { .. } = limiter.check(ip, rl_key) {
                rate_limited += 1;
                *rate_limited_ips.entry(ip_str.clone()).or_insert(0) += 1;
                continue;
            }
        }

        allowed += 1;
    }

    // Compute false positive / true positive counts
    let (false_positive_ips, true_positive_ips) =
        count_fp_tp(&args.input, &ddos_blocked_ips, &rate_limited_ips)?;

    Ok(ReplayResult {
        total,
        skipped,
        ddos_blocked,
        rate_limited,
        allowed,
        ddos_blocked_ips,
        rate_limited_ips,
        false_positive_ips,
        true_positive_ips,
    })
}

/// Count false-positive and true-positive IPs from blocked set.
/// FP = blocked IP where >60% of original responses were 2xx/3xx.
fn count_fp_tp(
    input: &str,
    ddos_blocked_ips: &FxHashMap<String, u64>,
    rate_limited_ips: &FxHashMap<String, u64>,
) -> Result<(usize, usize)> {
    let blocked_ips: rustc_hash::FxHashSet<&str> = ddos_blocked_ips
        .keys()
        .chain(rate_limited_ips.keys())
        .map(|s| s.as_str())
        .collect();

    if blocked_ips.is_empty() {
        return Ok((0, 0));
    }

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
            ip_statuses.entry(ip_str).or_default().push(entry.fields.status);
        }
    }

    let mut fp = 0usize;
    let mut tp = 0usize;
    for (_ip, statuses) in &ip_statuses {
        let total = statuses.len();
        let ok_count = statuses.iter().filter(|&&s| (200..400).contains(&s)).count();
        let ok_pct = ok_count as f64 / total as f64 * 100.0;
        if ok_pct > 60.0 {
            fp += 1;
        } else {
            tp += 1;
        }
    }

    Ok((fp, tp))
}

pub fn run(args: ReplayArgs) -> Result<()> {
    eprintln!("Loading model from {}...", args.model_path);
    eprintln!("Replaying {}...\n", args.input);

    let result = replay_and_evaluate(&args)?;

    let total = result.total;
    eprintln!("═══ Replay Results ═══════════════════════════════════════");
    eprintln!("  Total requests:    {total}");
    eprintln!("  Skipped (parse):   {}", result.skipped);
    eprintln!("  Allowed:           {} ({:.1}%)", result.allowed, pct(result.allowed, total));
    eprintln!("  DDoS blocked:      {} ({:.1}%)", result.ddos_blocked, pct(result.ddos_blocked, total));
    if args.rate_limit {
        eprintln!("  Rate limited:      {} ({:.1}%)", result.rate_limited, pct(result.rate_limited, total));
    }

    if !result.ddos_blocked_ips.is_empty() {
        eprintln!("\n── DDoS-blocked IPs (top 20) ─────────────────────────────");
        let mut sorted: Vec<_> = result.ddos_blocked_ips.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (ip, count) in sorted.iter().take(20) {
            eprintln!("  {:<40} {} reqs blocked", ip, count);
        }
    }

    if !result.rate_limited_ips.is_empty() {
        eprintln!("\n── Rate-limited IPs (top 20) ─────────────────────────────");
        let mut sorted: Vec<_> = result.rate_limited_ips.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (ip, count) in sorted.iter().take(20) {
            eprintln!("  {:<40} {} reqs limited", ip, count);
        }
    }

    eprintln!("\n── False positive check ──────────────────────────────────");
    if result.false_positive_ips == 0 {
        eprintln!("  No likely false positives found.");
    } else {
        eprintln!("  ⚠ {} IPs were blocked but had mostly successful responses", result.false_positive_ips);
    }
    eprintln!("  True positive IPs: {}", result.true_positive_ips);

    eprintln!("══════════════════════════════════════════════════════════");
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
