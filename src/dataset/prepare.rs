// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dataset preparation orchestrator.
//!
//! Combines production logs, external datasets (CSIC, OWASP ModSec), and
//! synthetic data (CIC-IDS2017 timing profiles + wordlists) into a single
//! `DatasetManifest` serialized as rkyv.

use crate::dataset::sample::{DataSource, DatasetManifest, DatasetStats, TrainingSample};
use crate::ddos::audit_log::{AuditFields, AuditLog};
use crate::ddos::features::{LogIpState, method_to_u8};
use crate::ddos::train::HeuristicThresholds;
use crate::scanner::features::{self, fx_hash_bytes};

use anyhow::{Context, Result};
use rustc_hash::FxHashSet;
use std::collections::HashMap;
use std::io::BufRead;
use std::path::Path;

/// Arguments for the `prepare-dataset` command.
pub struct PrepareDatasetArgs {
    /// Path to production audit log JSONL file.
    pub input: String,
    /// Path to OWASP ModSecurity audit log file (optional extra data).
    pub owasp: Option<String>,
    /// Path to wordlist directory (optional, enhances synthetic scanner).
    pub wordlists: Option<String>,
    /// Output path for the rkyv dataset file.
    pub output: String,
    /// RNG seed for synthetic generation.
    pub seed: u64,
    /// Path to heuristics.toml for auto-labeling production logs.
    pub heuristics: Option<String>,
    /// Inject CSIC 2010 entries as labeled audit logs into production stream.
    pub inject_csic: bool,
    /// Inject OWASP ModSec entries as labeled audit logs (path to .log file).
    pub inject_modsec: Option<String>,
}

impl Default for PrepareDatasetArgs {
    fn default() -> Self {
        Self {
            input: String::new(),
            owasp: None,
            wordlists: None,
            output: "dataset.bin".to_string(),
            seed: 42,
            heuristics: None,
            inject_csic: false,
            inject_modsec: None,
        }
    }
}

/// Run.
pub fn run(args: PrepareDatasetArgs) -> Result<()> {
    let mut scanner_samples: Vec<TrainingSample> = Vec::new();
    let mut ddos_samples: Vec<TrainingSample> = Vec::new();

    // --- 0. Download upstream datasets if not cached ---
    crate::dataset::download::download_all()?;

    // --- 1. Parse production logs ---
    let heuristics = if let Some(h_path) = &args.heuristics {
        let content = std::fs::read_to_string(h_path)
            .with_context(|| format!("reading heuristics from {h_path}"))?;
        toml::from_str::<HeuristicThresholds>(&content)
            .with_context(|| format!("parsing heuristics from {h_path}"))?
    } else {
        HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 10)
    };
    eprintln!("parsing production logs from {}...", args.input);
    let (prod_scanner, prod_ddos) = parse_production_logs(&args.input, &heuristics)?;
    eprintln!(
        "  production: {} scanner, {} ddos samples",
        prod_scanner.len(),
        prod_ddos.len()
    );
    scanner_samples.extend(prod_scanner);
    ddos_samples.extend(prod_ddos);

    // --- 2. Inject external datasets as labeled audit log entries ---
    // These go through the same feature extraction as production logs,
    // with ground-truth labels (no heuristic labeling needed).
    if args.inject_csic {
        eprintln!("injecting CSIC 2010 as labeled audit entries...");
        let csic_entries = crate::scanner::csic::fetch_csic_dataset()?;
        let csic_scanner = entries_to_scanner_samples(&csic_entries, DataSource::Csic2010, 0.8)?;
        eprintln!("  CSIC injected: {} scanner samples", csic_scanner.len());
        scanner_samples.extend(csic_scanner);
    }

    if let Some(modsec_path) = &args.inject_modsec {
        eprintln!("injecting ModSec audit log from {modsec_path}...");
        let modsec_entries =
            crate::dataset::modsec::parse_modsec_audit_log(Path::new(modsec_path))?;
        let entries_with_host: Vec<(AuditFields, String)> = modsec_entries
            .into_iter()
            .map(|(fields, _label)| {
                let host_prefix = fields.host.split('.').next().unwrap_or("").to_string();
                (fields, host_prefix)
            })
            .collect();
        let modsec_scanner =
            entries_to_scanner_samples(&entries_with_host, DataSource::OwaspModSec, 0.8)?;
        eprintln!(
            "  ModSec injected: {} scanner samples",
            modsec_scanner.len()
        );
        scanner_samples.extend(modsec_scanner);
    }

    // --- 3. Legacy OWASP path (kept for backwards compat) ---
    if let Some(owasp_path) = &args.owasp
        && args.inject_modsec.as_deref() != Some(owasp_path.as_str())
    {
        eprintln!("parsing OWASP ModSec audit log from {owasp_path}...");
        let modsec_entries = crate::dataset::modsec::parse_modsec_audit_log(Path::new(owasp_path))?;
        let entries_with_host: Vec<(AuditFields, String)> = modsec_entries
            .into_iter()
            .map(|(fields, _label)| {
                let host_prefix = fields.host.split('.').next().unwrap_or("").to_string();
                (fields, host_prefix)
            })
            .collect();
        let modsec_samples =
            entries_to_scanner_samples(&entries_with_host, DataSource::OwaspModSec, 0.8)?;
        eprintln!("  OWASP: {} scanner samples", modsec_samples.len());
        scanner_samples.extend(modsec_samples);
    }

    // --- 4. CIC-IDS2017 (direct DDoS samples + timing profiles for synthetic) ---
    let cicids_profiles = if let Some(cached_path) = crate::dataset::download::cicids_cached_path()
    {
        // Direct conversion: CIC-IDS2017 flows → DDoS training samples
        eprintln!("extracting CIC-IDS2017 DDoS samples from cache...");
        let cicids_ddos = crate::dataset::cicids::extract_ddos_samples(&cached_path)?;
        let attack_count = cicids_ddos.iter().filter(|s| s.label > 0.5).count();
        eprintln!(
            "  CIC-IDS2017 direct: {} DDoS samples ({} attack, {} normal)",
            cicids_ddos.len(),
            attack_count,
            cicids_ddos.len() - attack_count
        );
        ddos_samples.extend(cicids_ddos);

        // Also extract timing profiles for synthetic generation
        eprintln!("extracting CIC-IDS2017 timing profiles...");
        let profiles = crate::dataset::cicids::extract_timing_profiles(&cached_path)?;
        eprintln!("  extracted {} attack-type profiles", profiles.len());
        profiles
    } else {
        eprintln!("  CIC-IDS2017 not cached; using built-in DDoS distributions");
        eprintln!("  (run `download-datasets` first for real timing profiles)");
        Vec::new()
    };

    // --- 5. Synthetic data (both models, always generated) ---
    eprintln!("generating synthetic samples...");
    let config = crate::dataset::synthetic::SyntheticConfig {
        num_ddos_attack: 50000,
        num_ddos_normal: 50000,
        num_scanner_attack: 25000,
        num_scanner_normal: 25000,
        seed: args.seed,
    };

    // Synthetic DDoS (uses CIC-IDS2017 profiles if cached, fallback defaults otherwise).
    let synthetic_ddos =
        crate::dataset::synthetic::generate_ddos_samples(&cicids_profiles, &config);
    eprintln!("  synthetic DDoS: {} samples", synthetic_ddos.len());
    ddos_samples.extend(synthetic_ddos);

    // Synthetic scanner (uses wordlists if provided, built-in patterns otherwise).
    let synthetic_scanner = crate::dataset::synthetic::generate_scanner_samples(
        args.wordlists.as_deref().map(Path::new),
        None,
        &config,
    )?;
    eprintln!("  synthetic scanner: {} samples", synthetic_scanner.len());
    scanner_samples.extend(synthetic_scanner);

    // --- 6. Compute stats ---
    let mut samples_by_source: HashMap<DataSource, usize> = HashMap::new();
    for s in scanner_samples.iter().chain(ddos_samples.iter()) {
        *samples_by_source.entry(s.source.clone()).or_insert(0) += 1;
    }

    let scanner_attack_count = scanner_samples.iter().filter(|s| s.label > 0.5).count();
    let ddos_attack_count = ddos_samples.iter().filter(|s| s.label > 0.5).count();

    let stats = DatasetStats {
        total_samples: scanner_samples.len() + ddos_samples.len(),
        scanner_samples: scanner_samples.len(),
        ddos_samples: ddos_samples.len(),
        samples_by_source,
        attack_ratio_scanner: if scanner_samples.is_empty() {
            0.0
        } else {
            scanner_attack_count as f64 / scanner_samples.len() as f64
        },
        attack_ratio_ddos: if ddos_samples.is_empty() {
            0.0
        } else {
            ddos_attack_count as f64 / ddos_samples.len() as f64
        },
    };

    eprintln!("\n--- dataset stats ---");
    eprintln!("total samples: {}", stats.total_samples);
    eprintln!(
        "scanner: {} ({} attack, {:.1}% attack ratio)",
        stats.scanner_samples,
        scanner_attack_count,
        stats.attack_ratio_scanner * 100.0
    );
    eprintln!(
        "ddos: {} ({} attack, {:.1}% attack ratio)",
        stats.ddos_samples,
        ddos_attack_count,
        stats.attack_ratio_ddos * 100.0
    );
    for (source, count) in &stats.samples_by_source {
        eprintln!("  {source}: {count}");
    }

    let manifest = DatasetManifest {
        scanner_samples,
        ddos_samples,
        stats,
    };

    crate::dataset::sample::save_dataset(&manifest, Path::new(&args.output))?;
    eprintln!("\ndataset saved to {}", args.output);

    Ok(())
}

/// Parse production JSONL logs and produce both scanner and DDoS training samples.
///
/// When logs lack explicit labels, heuristic auto-labeling is applied:
/// - Scanner: attack if status >= 400 AND path matches scanner patterns; normal if
///   status < 400 AND has browser indicators (cookies + referer + accept-language).
/// - DDoS: per-IP feature thresholds from `HeuristicThresholds` (same logic as `ddos/train.rs`).
fn parse_production_logs(
    input: &str,
    heuristics: &HeuristicThresholds,
) -> Result<(Vec<TrainingSample>, Vec<TrainingSample>)> {
    let file = std::fs::File::open(input).with_context(|| format!("opening {input}"))?;
    let reader = std::io::BufReader::new(file);

    let mut scanner_samples = Vec::new();
    let mut parsed_entries: Vec<(AuditFields, String)> = Vec::new();
    let mut log_hosts: FxHashSet<u64> = FxHashSet::default();

    // Build hashes for scanner feature extraction.
    let fragment_hashes: FxHashSet<u64> = crate::scanner::train::DEFAULT_FRAGMENTS
        .iter()
        .map(|f| fx_hash_bytes(f.to_ascii_lowercase().as_bytes()))
        .collect();
    let extension_hashes: FxHashSet<u64> = features::SUSPICIOUS_EXTENSIONS_LIST
        .iter()
        .map(|e| fx_hash_bytes(e.as_bytes()))
        .collect();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditLog = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let host_prefix = entry
            .fields
            .host
            .split('.')
            .next()
            .unwrap_or("")
            .to_string();
        log_hosts.insert(fx_hash_bytes(host_prefix.as_bytes()));
        parsed_entries.push((entry.fields, host_prefix));
    }

    // --- Scanner samples from production logs ---
    for (fields, host_prefix) in &parsed_entries {
        let has_cookies = fields.has_cookies;
        let has_referer = !fields.referer.is_empty() && fields.referer != "-";
        let has_accept_language =
            !fields.accept_language.is_empty() && fields.accept_language != "-";

        let feats = features::extract_features(
            &fields.method,
            &fields.path,
            host_prefix,
            has_cookies,
            has_referer,
            has_accept_language,
            &fields.accept,
            &fields.user_agent,
            fields.content_length,
            &fragment_hashes,
            &extension_hashes,
            &log_hosts,
        );

        // Use ground-truth label if present, otherwise heuristic auto-label.
        let label = match fields.label.as_deref() {
            Some("attack" | "anomalous") => Some(1.0f32),
            Some("normal") => Some(0.0f32),
            _ => {
                // Heuristic scanner labeling:
                // Attack: 404+ AND suspicious path (excluding .git which is valid on Gitea hosts).
                // Normal: success status AND browser indicators (cookies + referer + accept-language).
                // Note: 401 is excluded since it's expected for private repos.
                let status = fields.status;
                let path_lower = fields.path.to_ascii_lowercase();
                let is_suspicious_path = path_lower.contains(".env")
                    || path_lower.contains("wp-login")
                    || path_lower.contains("wp-admin")
                    || path_lower.contains("phpmyadmin")
                    || path_lower.contains("cgi-bin")
                    || path_lower.contains("phpinfo")
                    || path_lower.contains("/shell")
                    || path_lower.contains("..%2f")
                    || path_lower.contains("../");
                if status >= 404 && is_suspicious_path {
                    Some(1.0f32)
                } else if status < 400 && has_cookies && has_referer && has_accept_language {
                    Some(0.0f32)
                } else {
                    None // ambiguous — skip
                }
            }
        };

        if let Some(l) = label {
            scanner_samples.push(TrainingSample {
                features: feats.iter().map(|&v| v as f32).collect(),
                label: l,
                source: DataSource::ProductionLogs,
                weight: 1.0,
            });
        }
    }

    // --- DDoS samples from production logs ---
    let ddos_samples = extract_ddos_samples_from_entries(&parsed_entries, heuristics)?;

    Ok((scanner_samples, ddos_samples))
}

/// Extract DDoS feature vectors from parsed log entries using sliding windows.
fn extract_ddos_samples_from_entries(
    entries: &[(AuditFields, String)],
    heuristics: &HeuristicThresholds,
) -> Result<Vec<TrainingSample>> {
    use rustc_hash::FxHashMap;
    use std::hash::{Hash, Hasher};

    fn fx_hash(s: &str) -> u64 {
        let mut h = rustc_hash::FxHasher::default();
        s.hash(&mut h);
        h.finish()
    }

    let mut ip_states: FxHashMap<String, LogIpState> = FxHashMap::default();
    let mut ip_labels: FxHashMap<String, Option<f32>> = FxHashMap::default();

    for (fields, _host_prefix) in entries {
        let ip = crate::ddos::audit_log::strip_port(&fields.client_ip).to_string();

        let state = ip_states.entry(ip.clone()).or_default();
        // Use a simple counter as "timestamp" since we don't have parsed timestamps here.
        let ts = state.timestamps.len() as f64;
        state.timestamps.push(ts);
        state.methods.push(method_to_u8(&fields.method));
        state.path_hashes.push(fx_hash(&fields.path));
        state.host_hashes.push(fx_hash(&fields.host));
        state.user_agent_hashes.push(fx_hash(&fields.user_agent));
        state.statuses.push(fields.status);
        state
            .durations
            .push(fields.duration_ms.min(u32::MAX as u64) as u32);
        state
            .content_lengths
            .push(fields.content_length.min(u32::MAX as u64) as u32);
        state.has_cookies.push(fields.has_cookies);
        state
            .has_referer
            .push(!fields.referer.is_empty() && fields.referer != "-");
        state
            .has_accept_language
            .push(!fields.accept_language.is_empty() && fields.accept_language != "-");
        state
            .suspicious_paths
            .push(crate::ddos::features::is_suspicious_path(&fields.path));

        // Track label per IP if available.
        if let Some(ref label_str) = fields.label {
            let label_val = match label_str.as_str() {
                "attack" | "anomalous" => Some(1.0f32),
                "normal" => Some(0.0f32),
                _ => None,
            };
            ip_labels.insert(ip, label_val);
        }
    }

    let min_events = heuristics.min_events.max(3);
    let window_size = 50; // events per sliding window
    let window_step = 25; // step size (50% overlap)
    let window_secs = 60.0;
    let mut samples = Vec::new();

    for (ip, state) in &ip_states {
        let n = state.timestamps.len();
        if n < min_events {
            continue;
        }

        // Ground-truth label if available.
        let gt_label = match ip_labels.get(ip) {
            Some(Some(l)) => Some(*l),
            _ => None,
        };

        // Sliding windows: extract multiple feature vectors per IP.
        // For IPs with fewer events than window_size, use a single window over all events.
        let mut start = 0;
        loop {
            let end = (start + window_size).min(n);
            if end - start < min_events {
                break;
            }

            let fv = state.extract_features_for_window(start, end, window_secs);

            let label = gt_label.unwrap_or_else(|| {
                // Heuristic DDoS labeling (mirrors ddos/train.rs logic):
                let is_attack = fv[0] > heuristics.request_rate
                    || fv[7] > heuristics.path_repetition
                    || fv[3] > heuristics.error_rate
                    || fv[13] > heuristics.suspicious_path_ratio
                    || (fv[10] < heuristics.no_cookies_threshold
                        && fv[1] > heuristics.no_cookies_path_count);
                if is_attack { 1.0f32 } else { 0.0f32 }
            });

            samples.push(TrainingSample {
                features: fv.iter().map(|&v| v as f32).collect(),
                label,
                source: DataSource::ProductionLogs,
                weight: 1.0,
            });

            if end >= n {
                break;
            }
            start += window_step;
        }
    }

    Ok(samples)
}

/// Convert external dataset entries (CSIC, OWASP) into scanner TrainingSamples.
fn entries_to_scanner_samples(
    entries: &[(AuditFields, String)],
    source: DataSource,
    weight: f32,
) -> Result<Vec<TrainingSample>> {
    let fragment_hashes: FxHashSet<u64> = crate::scanner::train::DEFAULT_FRAGMENTS
        .iter()
        .map(|f| fx_hash_bytes(f.to_ascii_lowercase().as_bytes()))
        .collect();
    let extension_hashes: FxHashSet<u64> = features::SUSPICIOUS_EXTENSIONS_LIST
        .iter()
        .map(|e| fx_hash_bytes(e.as_bytes()))
        .collect();

    let mut log_hosts: FxHashSet<u64> = FxHashSet::default();
    for (_, host_prefix) in entries {
        log_hosts.insert(fx_hash_bytes(host_prefix.as_bytes()));
    }

    let mut samples = Vec::new();

    for (fields, host_prefix) in entries {
        let has_cookies = fields.has_cookies;
        let has_referer = !fields.referer.is_empty() && fields.referer != "-";
        let has_accept_language =
            !fields.accept_language.is_empty() && fields.accept_language != "-";

        let feats = features::extract_features(
            &fields.method,
            &fields.path,
            host_prefix,
            has_cookies,
            has_referer,
            has_accept_language,
            &fields.accept,
            &fields.user_agent,
            fields.content_length,
            &fragment_hashes,
            &extension_hashes,
            &log_hosts,
        );

        let label = match fields.label.as_deref() {
            Some("attack" | "anomalous") => 1.0f32,
            Some("normal") => 0.0f32,
            _ => continue,
        };

        samples.push(TrainingSample {
            features: feats.iter().map(|&v| v as f32).collect(),
            label,
            source: source.clone(),
            weight,
        });
    }

    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddos::features::NUM_FEATURES;
    use crate::scanner::features::NUM_SCANNER_FEATURES;

    #[test]
    fn test_ddos_sample_feature_count() {
        // Verify that DDoS samples from sliding windows produce 14 features.
        let entries = vec![
            make_test_entry("GET", "/", "1.2.3.4", 200, "normal"),
            make_test_entry("GET", "/about", "1.2.3.4", 200, "normal"),
            make_test_entry("GET", "/contact", "1.2.3.4", 200, "normal"),
            make_test_entry("GET", "/blog", "1.2.3.4", 200, "normal"),
            make_test_entry("GET", "/faq", "1.2.3.4", 200, "normal"),
        ];
        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 5);
        let samples = extract_ddos_samples_from_entries(&entries, &heuristics).unwrap();
        // With only 5 entries at min_events=5, we should get 1 sample.
        assert!(!samples.is_empty(), "should produce DDoS samples");
        for s in &samples {
            assert_eq!(
                s.features.len(),
                NUM_FEATURES,
                "DDoS sample should have {NUM_FEATURES} features"
            );
        }
    }

    #[test]
    fn test_scanner_sample_feature_count() {
        let entries = vec![
            make_test_entry("GET", "/.env", "1.2.3.4", 404, "attack"),
            make_test_entry("GET", "/index.html", "5.6.7.8", 200, "normal"),
        ];
        let samples =
            entries_to_scanner_samples(&entries, DataSource::ProductionLogs, 1.0).unwrap();
        assert_eq!(samples.len(), 2);
        for s in &samples {
            assert_eq!(
                s.features.len(),
                NUM_SCANNER_FEATURES,
                "scanner sample should have {NUM_SCANNER_FEATURES} features"
            );
        }
    }

    #[test]
    fn test_entries_to_scanner_samples_labels() {
        let entries = vec![
            make_test_entry("GET", "/.env", "1.2.3.4", 404, "attack"),
            make_test_entry("GET", "/", "5.6.7.8", 200, "normal"),
            make_test_entry("GET", "/page", "9.10.11.12", 200, "unknown_label"),
        ];
        let samples = entries_to_scanner_samples(&entries, DataSource::Csic2010, 0.8).unwrap();
        // "unknown_label" should be skipped.
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].label, 1.0);
        assert_eq!(samples[1].label, 0.0);
        assert_eq!(samples[0].weight, 0.8);
        assert_eq!(samples[0].source, DataSource::Csic2010);
    }

    fn make_test_entry(
        method: &str,
        path: &str,
        client_ip: &str,
        status: u16,
        label: &str,
    ) -> (AuditFields, String) {
        let fields = AuditFields {
            method: method.to_string(),
            host: "test.sunbeam.pt".to_string(),
            path: path.to_string(),
            query: String::new(),
            client_ip: client_ip.to_string(),
            status,
            duration_ms: 10,
            content_length: 0,
            user_agent: "Mozilla/5.0".to_string(),
            has_cookies: true,
            referer: "https://test.sunbeam.pt".to_string(),
            accept_language: "en-US".to_string(),
            backend: "test-svc:8080".to_string(),
            label: Some(label.to_string()),
            ..AuditFields::default()
        };
        (fields, "test".to_string())
    }

    fn make_audit_log_json(fields: &AuditFields) -> String {
        let line = crate::audit::AuditLogLine {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            level: "INFO".to_string(),
            fields: fields.clone(),
            span: None,
            spans: None,
        };
        serde_json::to_string(&line).unwrap()
    }

    #[test]
    fn test_parse_production_logs_scanner_attack() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs.jsonl");
        let attack = AuditFields {
            method: "GET".to_string(),
            host: "test.sunbeam.pt".to_string(),
            path: "/.env".to_string(),
            client_ip: "1.2.3.4".to_string(),
            status: 404,
            user_agent: "curl/7.0".to_string(),
            has_cookies: false,
            referer: "-".to_string(),
            accept_language: "-".to_string(),
            ..AuditFields::default()
        };
        std::fs::write(&path, make_audit_log_json(&attack)).unwrap();

        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 10);
        let (scanner_samples, ddos_samples) =
            parse_production_logs(path.to_str().unwrap(), &heuristics).unwrap();
        assert_eq!(scanner_samples.len(), 1);
        assert_eq!(scanner_samples[0].label, 1.0);
        assert_eq!(scanner_samples[0].source, DataSource::ProductionLogs);
        assert!(ddos_samples.is_empty());
    }

    #[test]
    fn test_parse_production_logs_scanner_normal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs.jsonl");
        let normal = AuditFields {
            method: "GET".to_string(),
            host: "test.sunbeam.pt".to_string(),
            path: "/index.html".to_string(),
            client_ip: "1.2.3.4".to_string(),
            status: 200,
            user_agent: "Mozilla/5.0".to_string(),
            has_cookies: true,
            referer: "https://test.sunbeam.pt".to_string(),
            accept_language: "en-US".to_string(),
            ..AuditFields::default()
        };
        std::fs::write(&path, make_audit_log_json(&normal)).unwrap();

        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 10);
        let (scanner_samples, _ddos) =
            parse_production_logs(path.to_str().unwrap(), &heuristics).unwrap();
        assert_eq!(scanner_samples.len(), 1);
        assert_eq!(scanner_samples[0].label, 0.0);
    }

    #[test]
    fn test_parse_production_logs_ignores_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs.jsonl");
        // Status 200 but missing browser indicators => ambiguous.
        let ambiguous = AuditFields {
            method: "GET".to_string(),
            host: "test.sunbeam.pt".to_string(),
            path: "/api/health".to_string(),
            client_ip: "1.2.3.4".to_string(),
            status: 200,
            user_agent: "bot/1.0".to_string(),
            has_cookies: false,
            referer: "-".to_string(),
            accept_language: "-".to_string(),
            ..AuditFields::default()
        };
        std::fs::write(&path, make_audit_log_json(&ambiguous)).unwrap();

        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 10);
        let (scanner, _ddos) = parse_production_logs(path.to_str().unwrap(), &heuristics).unwrap();
        assert!(scanner.is_empty());
    }

    #[test]
    fn test_parse_production_logs_ddos_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs.jsonl");
        let mut lines = String::new();
        for i in 0..10 {
            let fields = AuditFields {
                method: "GET".to_string(),
                host: "test.sunbeam.pt".to_string(),
                path: format!("/page{i}"),
                client_ip: "1.2.3.4".to_string(),
                status: 200,
                user_agent: "Mozilla/5.0".to_string(),
                has_cookies: true,
                referer: "https://test.sunbeam.pt".to_string(),
                accept_language: "en-US".to_string(),
                ..AuditFields::default()
            };
            lines.push_str(&make_audit_log_json(&fields));
            lines.push('\n');
        }
        std::fs::write(&path, lines).unwrap();

        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 5);
        let (_scanner, ddos) = parse_production_logs(path.to_str().unwrap(), &heuristics).unwrap();
        assert!(!ddos.is_empty());
        for s in &ddos {
            assert_eq!(s.features.len(), NUM_FEATURES);
        }
    }

    #[test]
    fn test_extract_ddos_samples_from_entries_gt_label() {
        let mut entries = Vec::new();
        for _ in 0..10 {
            entries.push(make_test_entry("GET", "/", "1.2.3.4", 200, "attack"));
        }
        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 5);
        let samples = extract_ddos_samples_from_entries(&entries, &heuristics).unwrap();
        assert!(!samples.is_empty());
        assert!(samples.iter().all(|s| s.label > 0.5));
    }

    #[test]
    fn test_extract_ddos_samples_from_entries_below_min_events() {
        let entries = vec![make_test_entry("GET", "/", "1.2.3.4", 200, "normal")];
        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 10);
        let samples = extract_ddos_samples_from_entries(&entries, &heuristics).unwrap();
        assert!(samples.is_empty());
    }

    #[test]
    fn test_extract_ddos_samples_from_entries_empty() {
        let entries: Vec<(AuditFields, String)> = Vec::new();
        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 5);
        let samples = extract_ddos_samples_from_entries(&entries, &heuristics).unwrap();
        assert!(samples.is_empty());
    }

    #[test]
    fn test_entries_to_scanner_samples_empty() {
        let entries: Vec<(AuditFields, String)> = Vec::new();
        let samples = entries_to_scanner_samples(&entries, DataSource::OwaspModSec, 0.8).unwrap();
        assert!(samples.is_empty());
    }

    #[test]
    fn test_parse_production_logs_explicit_labels() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs.jsonl");
        let attack = make_test_entry("GET", "/.env", "1.2.3.4", 200, "attack");
        let normal = make_test_entry("GET", "/", "5.6.7.8", 500, "normal");
        // 401 with browser indicators is ambiguous, so "unknown" label should be skipped.
        let unknown = make_test_entry("GET", "/", "9.10.11.12", 401, "unknown");
        let lines = format!(
            "{}\n{}\n{}\n",
            make_audit_log_json(&attack.0),
            make_audit_log_json(&normal.0),
            make_audit_log_json(&unknown.0)
        );
        std::fs::write(&path, lines).unwrap();

        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 10);
        let (scanner, _ddos) = parse_production_logs(path.to_str().unwrap(), &heuristics).unwrap();
        assert_eq!(scanner.len(), 2);
        assert!(scanner.iter().any(|s| s.label > 0.5));
        assert!(scanner.iter().any(|s| s.label < 0.5));
    }

    #[test]
    fn test_extract_ddos_samples_from_entries_heuristic_attack() {
        // Many requests to the same path from one IP with high rate heuristic thresholds.
        let mut entries = Vec::new();
        for _ in 0..20 {
            entries.push(make_test_entry("GET", "/api", "1.2.3.4", 500, ""));
        }
        let heuristics = HeuristicThresholds::new(0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 5);
        let samples = extract_ddos_samples_from_entries(&entries, &heuristics).unwrap();
        assert!(!samples.is_empty());
    }

    #[test]
    fn test_extract_ddos_samples_from_entries_heuristic_normal() {
        // Few requests with high thresholds → heuristic labels as normal.
        let mut entries = Vec::new();
        for i in 0..5 {
            entries.push(make_test_entry(
                "GET",
                &format!("/page{i}"),
                "1.2.3.4",
                200,
                "",
            ));
        }
        let heuristics = HeuristicThresholds::new(1000.0, 1.0, 1.0, 1.0, 0.0, 1000.0, 5);
        let samples = extract_ddos_samples_from_entries(&entries, &heuristics).unwrap();
        assert!(!samples.is_empty());
        assert!(samples.iter().all(|s| s.label < 0.5));
    }

    #[test]
    fn test_parse_production_logs_mixed_scanner_and_ddos() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs.jsonl");
        let mut lines = String::new();
        // One scanner attack.
        let attack = AuditFields {
            method: "GET".to_string(),
            host: "test.sunbeam.pt".to_string(),
            path: "/.env".to_string(),
            client_ip: "1.2.3.4".to_string(),
            status: 404,
            user_agent: "curl/7.0".to_string(),
            has_cookies: false,
            referer: "-".to_string(),
            accept_language: "-".to_string(),
            ..AuditFields::default()
        };
        lines.push_str(&make_audit_log_json(&attack));
        lines.push('\n');
        // Several DDoS-like requests from another IP without browser indicators
        // so they are not picked up as scanner normal samples.
        for i in 0..10 {
            let fields = AuditFields {
                method: "GET".to_string(),
                host: "test.sunbeam.pt".to_string(),
                path: format!("/api/{i}"),
                client_ip: "5.6.7.8".to_string(),
                status: 200,
                user_agent: "bot/1.0".to_string(),
                has_cookies: false,
                referer: "-".to_string(),
                accept_language: "-".to_string(),
                ..AuditFields::default()
            };
            lines.push_str(&make_audit_log_json(&fields));
            lines.push('\n');
        }
        std::fs::write(&path, lines).unwrap();

        let heuristics = HeuristicThresholds::new(10.0, 0.85, 0.7, 0.3, 0.05, 20.0, 5);
        let (scanner, ddos) = parse_production_logs(path.to_str().unwrap(), &heuristics).unwrap();
        assert_eq!(scanner.len(), 1);
        assert!(!ddos.is_empty());
    }
}
