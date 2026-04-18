// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Replay audit logs through the ensemble models (scanner + DDoS).

use crate::audit::AuditLogLine;
use crate::ddos::audit_log;
use crate::ddos::features::{method_to_u8, LogIpState};
use crate::ddos::model::DDoSAction;
use crate::ensemble::ddos::{ddos_ensemble_predict, DDoSEnsemblePath};
use crate::ensemble::scanner::{scanner_ensemble_predict, EnsemblePath};
use crate::scanner::features::{self, fx_hash_bytes};
use crate::scanner::model::ScannerAction;

use anyhow::{Context, Result};
use rustc_hash::{FxHashMap, FxHashSet};
use std::hash::{Hash, Hasher};
use std::io::BufRead;

pub struct ReplayEnsembleArgs {
    pub input: String,
    pub window_secs: u64,
    pub min_events: usize,
}

pub fn run(args: ReplayEnsembleArgs) -> Result<()> {
    eprintln!("replaying {} through ensemble models...\n", args.input);

    let file =
        std::fs::File::open(&args.input).with_context(|| format!("opening {}", args.input))?;
    let reader = std::io::BufReader::new(file);

    // --- Parse all entries, filtering for audit logs only ---
    let mut entries: Vec<AuditLogLine> = Vec::new();
    let mut skipped_non_audit = 0u64;
    let mut schema_errors = 0u64;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match AuditLogLine::try_parse(&line) {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => skipped_non_audit += 1,
            Err(e) => {
                schema_errors += 1;
                if schema_errors <= 3 {
                    eprintln!("  schema error: {e}");
                }
            }
        }
    }
    let total = entries.len() as u64;
    eprintln!(
        "parsed {} audit entries ({} non-audit skipped, {} schema errors)\n",
        total, skipped_non_audit, schema_errors,
    );

    // --- Scanner replay ---
    eprintln!("═══ Scanner Ensemble ═════════════════════════════════════");
    replay_scanner(&entries);

    // --- DDoS replay ---
    eprintln!("\n═══ DDoS Ensemble ═══════════════════════════════════════");
    replay_ddos(&entries, args.window_secs as f64, args.min_events);

    eprintln!("\n══════════════════════════════════════════════════════════");
    Ok(())
}

fn replay_scanner(entries: &[AuditLogLine]) {
    let fragment_hashes: FxHashSet<u64> = crate::scanner::train::DEFAULT_FRAGMENTS
        .iter()
        .map(|f| fx_hash_bytes(f.to_ascii_lowercase().as_bytes()))
        .collect();
    let extension_hashes: FxHashSet<u64> = features::SUSPICIOUS_EXTENSIONS_LIST
        .iter()
        .map(|e| fx_hash_bytes(e.as_bytes()))
        .collect();
    let mut log_hosts: FxHashSet<u64> = FxHashSet::default();
    for e in entries {
        let prefix = e.fields.host.split('.').next().unwrap_or("");
        log_hosts.insert(fx_hash_bytes(prefix.as_bytes()));
    }

    let mut total = 0u64;
    let mut blocked = 0u64;
    let mut allowed = 0u64;
    let mut path_counts = [0u64; 3]; // TreeBlock, TreeAllow, Mlp
    let mut blocked_examples: Vec<(String, String, String, f64)> = Vec::new(); // (path, ua, reason, score)
    let mut fp_candidates: Vec<(String, String, u16, f64)> = Vec::new(); // blocked but had 2xx status

    for e in entries {
        let f = &e.fields;
        let host_prefix = f.host.split('.').next().unwrap_or("");
        let has_cookies = f.has_cookies;
        let has_referer = !f.referer.is_empty() && f.referer != "-";
        let has_accept_language = !f.accept_language.is_empty() && f.accept_language != "-";

        let feats = features::extract_features_f32(
            &f.method,
            &f.path,
            host_prefix,
            has_cookies,
            has_referer,
            has_accept_language,
            &f.accept,
            &f.user_agent,
            f.content_length,
            &fragment_hashes,
            &extension_hashes,
            &log_hosts,
        );

        let verdict = scanner_ensemble_predict(&feats);
        total += 1;

        match verdict.path {
            EnsemblePath::TreeBlock => path_counts[0] += 1,
            EnsemblePath::TreeAllow => path_counts[1] += 1,
            EnsemblePath::Mlp => path_counts[2] += 1,
        }

        match verdict.action {
            ScannerAction::Block => {
                blocked += 1;
                if blocked_examples.len() < 20 {
                    blocked_examples.push((
                        f.path.clone(),
                        f.user_agent.clone(),
                        verdict.reason.to_string(),
                        verdict.score,
                    ));
                }
                if (200..400).contains(&f.status) {
                    fp_candidates.push((f.path.clone(), f.user_agent.clone(), f.status, verdict.score));
                }
            }
            ScannerAction::Allow => allowed += 1,
        }
    }

    let pct = |n: u64| {
        if total == 0 {
            0.0
        } else {
            n as f64 / total as f64 * 100.0
        }
    };

    eprintln!("  total:       {total}");
    eprintln!(
        "  blocked:     {} ({:.1}%)",
        blocked,
        pct(blocked)
    );
    eprintln!(
        "  allowed:     {} ({:.1}%)",
        allowed,
        pct(allowed)
    );
    eprintln!(
        "  paths:       tree_block={} tree_allow={} mlp={}",
        path_counts[0], path_counts[1], path_counts[2]
    );

    if !blocked_examples.is_empty() {
        eprintln!("\n  blocked examples (first 20):");
        for (path, ua, reason, score) in &blocked_examples {
            eprintln!("    {:<50} {reason} (score={score:.3})", truncate(path, 50));
            eprintln!("      ua: {}", truncate(ua, 72));
        }
    }

    let fp_count = fp_candidates.len();
    if fp_count > 0 {
        eprintln!(
            "\n  potential false positives (blocked but had 2xx/3xx): {}",
            fp_count
        );
        for (path, ua, status, score) in fp_candidates.iter().take(10) {
            eprintln!(
                "    {:<50} status={status} score={score:.3}",
                truncate(path, 50)
            );
            eprintln!("      ua: {}", truncate(ua, 72));
        }
    }
}

fn replay_ddos(entries: &[AuditLogLine], window_secs: f64, min_events: usize) {
    fn fx_hash(s: &str) -> u64 {
        let mut h = rustc_hash::FxHasher::default();
        s.hash(&mut h);
        h.finish()
    }

    // Aggregate per-IP state.
    let mut ip_states: FxHashMap<String, LogIpState> = FxHashMap::default();

    for e in entries {
        let f = &e.fields;
        let ip = audit_log::strip_port(&f.client_ip).to_string();
        let state = ip_states.entry(ip).or_default();
        let ts = state.timestamps.len() as f64;
        state.timestamps.push(ts);
        state.methods.push(method_to_u8(&f.method));
        state.path_hashes.push(fx_hash(&f.path));
        state.host_hashes.push(fx_hash(&f.host));
        state.user_agent_hashes.push(fx_hash(&f.user_agent));
        state.statuses.push(f.status);
        state
            .durations
            .push(f.duration_ms.min(u32::MAX as u64) as u32);
        state
            .content_lengths
            .push(f.content_length.min(u32::MAX as u64) as u32);
        state
            .has_cookies
            .push(f.has_cookies);
        state.has_referer.push(
            !f.referer.is_empty() && f.referer != "-",
        );
        state.has_accept_language.push(
            !f.accept_language.is_empty() && f.accept_language != "-",
        );
        state
            .suspicious_paths
            .push(crate::ddos::features::is_suspicious_path(&f.path));
    }

    let mut total_ips = 0u64;
    let mut blocked_ips = 0u64;
    let mut allowed_ips = 0u64;
    let mut skipped_ips = 0u64;
    let mut path_counts = [0u64; 3]; // TreeBlock, TreeAllow, Mlp
    let mut blocked_details: Vec<(String, usize, f64, &'static str)> = Vec::new();

    for (ip, state) in &ip_states {
        let n = state.timestamps.len();
        if n < min_events {
            skipped_ips += 1;
            continue;
        }
        total_ips += 1;

        let fv = state.extract_features_for_window(0, n, window_secs);
        let fv_f32: [f32; 14] = {
            let mut arr = [0.0f32; 14];
            for i in 0..14 {
                arr[i] = fv[i] as f32;
            }
            arr
        };

        let verdict = ddos_ensemble_predict(&fv_f32);

        match verdict.path {
            DDoSEnsemblePath::TreeBlock => path_counts[0] += 1,
            DDoSEnsemblePath::TreeAllow => path_counts[1] += 1,
            DDoSEnsemblePath::Mlp => path_counts[2] += 1,
        }

        match verdict.action {
            DDoSAction::Block => {
                blocked_ips += 1;
                if blocked_details.len() < 30 {
                    blocked_details.push((ip.clone(), n, verdict.score, verdict.reason));
                }
            }
            DDoSAction::Allow => allowed_ips += 1,
        }
    }

    let pct = |n: u64, d: u64| {
        if d == 0 {
            0.0
        } else {
            n as f64 / d as f64 * 100.0
        }
    };

    eprintln!("  unique IPs:  {} ({} skipped < {} events)", ip_states.len(), skipped_ips, min_events);
    eprintln!("  evaluated:   {total_ips}");
    eprintln!(
        "  blocked:     {} ({:.1}%)",
        blocked_ips,
        pct(blocked_ips, total_ips)
    );
    eprintln!(
        "  allowed:     {} ({:.1}%)",
        allowed_ips,
        pct(allowed_ips, total_ips)
    );
    eprintln!(
        "  paths:       tree_block={} tree_allow={} mlp={}",
        path_counts[0], path_counts[1], path_counts[2]
    );

    if !blocked_details.is_empty() {
        eprintln!("\n  blocked IPs (up to 30):");
        let mut sorted = blocked_details;
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (ip, reqs, score, reason) in &sorted {
            eprintln!(
                "    {:<40} {} reqs  score={:.3}  {reason}",
                ip, reqs, score
            );
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}
