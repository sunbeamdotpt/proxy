use crate::ddos::audit_log::AuditLog;
use crate::ddos::audit_log;
use crate::ddos::features::{method_to_u8, FeatureVector, LogIpState, NormParams, NUM_FEATURES};
use crate::ddos::model::{SerializedModel, TrafficLabel};
use anyhow::{bail, Context, Result};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::Deserialize;
use std::hash::{Hash, Hasher};
use std::io::BufRead;

#[derive(Deserialize)]
pub struct HeuristicThresholds {
    /// Requests/second above which an IP is labeled attack
    #[serde(default = "default_rate_threshold")]
    pub request_rate: f64,
    /// Path repetition ratio above which an IP is labeled attack
    #[serde(default = "default_repetition_threshold")]
    pub path_repetition: f64,
    /// Error rate above which an IP is labeled attack
    #[serde(default = "default_error_threshold")]
    pub error_rate: f64,
    /// Suspicious path ratio above which an IP is labeled attack
    #[serde(default = "default_suspicious_path_threshold")]
    pub suspicious_path_ratio: f64,
    /// Cookie ratio below which (combined with high unique paths) labels attack
    #[serde(default = "default_no_cookies_threshold")]
    pub no_cookies_threshold: f64,
    /// Unique path count above which no-cookie traffic is labeled attack
    #[serde(default = "default_no_cookies_path_count")]
    pub no_cookies_path_count: f64,
    /// Minimum events to consider an IP for labeling
    #[serde(default = "default_min_events")]
    pub min_events: usize,
}

fn default_rate_threshold() -> f64 { 10.0 }
fn default_repetition_threshold() -> f64 { 0.9 }
fn default_error_threshold() -> f64 { 0.7 }
fn default_suspicious_path_threshold() -> f64 { 0.3 }
fn default_no_cookies_threshold() -> f64 { 0.05 }
fn default_no_cookies_path_count() -> f64 { 20.0 }
fn default_min_events() -> usize { 10 }

pub struct TrainArgs {
    pub input: String,
    pub output: String,
    pub attack_ips: Option<String>,
    pub normal_ips: Option<String>,
    pub heuristics: Option<String>,
    pub k: usize,
    pub threshold: f64,
    pub window_secs: u64,
    pub min_events: usize,
}

fn fx_hash(s: &str) -> u64 {
    let mut h = rustc_hash::FxHasher::default();
    s.hash(&mut h);
    h.finish()
}

fn parse_timestamp(ts: &str) -> f64 {
    // Parse ISO 8601 timestamp to seconds since epoch (approximate).
    // We only need relative ordering within a log file.
    // Format: "2026-03-07T17:41:40.705326Z"
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return 0.0;
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_str = parts[1].trim_end_matches('Z');
    let time_parts: Vec<&str> = time_str.split(':').collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return 0.0;
    }
    let day: f64 = date_parts[2].parse().unwrap_or(0.0);
    let hour: f64 = time_parts[0].parse().unwrap_or(0.0);
    let min: f64 = time_parts[1].parse().unwrap_or(0.0);
    let sec: f64 = time_parts[2].parse().unwrap_or(0.0);
    // Relative seconds (day * 86400 + time)
    day * 86400.0 + hour * 3600.0 + min * 60.0 + sec
}


pub fn run(args: TrainArgs) -> Result<()> {
    eprintln!("Parsing logs from {}...", args.input);

    // Parse logs into per-IP state
    let mut ip_states: FxHashMap<String, LogIpState> = FxHashMap::default();
    let file = std::fs::File::open(&args.input)
        .with_context(|| format!("opening {}", args.input))?;
    let reader = std::io::BufReader::new(file);

    let mut total_lines = 0u64;
    let mut parse_errors = 0u64;

    for line in reader.lines() {
        let line = line?;
        total_lines += 1;
        let entry: AuditLog = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => {
                parse_errors += 1;
                continue;
            }
        };

        // Skip non-audit entries
        if entry.fields.method.is_empty() {
            continue;
        }

        let ip = audit_log::strip_port(&entry.fields.client_ip).to_string();
        let ts = parse_timestamp(&entry.timestamp);

        let state = ip_states.entry(ip).or_default();
        state.timestamps.push(ts);
        state.methods.push(method_to_u8(&entry.fields.method));
        state.path_hashes.push(fx_hash(&entry.fields.path));
        state.host_hashes.push(fx_hash(&entry.fields.host));
        state
            .user_agent_hashes
            .push(fx_hash(&entry.fields.user_agent));
        state.statuses.push(entry.fields.status);
        state.durations.push(entry.fields.duration_ms.min(u32::MAX as u64) as u32);
        state
            .content_lengths
            .push(entry.fields.content_length.min(u32::MAX as u64) as u32);
        state.has_cookies.push(entry.fields.has_cookies.unwrap_or(false));
        state.has_referer.push(
            entry.fields.referer.as_deref().map(|r| r != "-").unwrap_or(false),
        );
        state.has_accept_language.push(
            entry.fields.accept_language.as_deref().map(|a| a != "-").unwrap_or(false),
        );
        state.suspicious_paths.push(
            crate::ddos::features::is_suspicious_path(&entry.fields.path),
        );
    }

    eprintln!(
        "Parsed {} lines ({} errors), {} unique IPs",
        total_lines,
        parse_errors,
        ip_states.len()
    );

    // Extract feature vectors per IP (using sliding windows)
    let window_secs = args.window_secs as f64;
    let mut ip_features: FxHashMap<String, Vec<FeatureVector>> = FxHashMap::default();

    for (ip, state) in &ip_states {
        let n = state.timestamps.len();
        if n < args.min_events {
            continue;
        }
        // Extract one feature vector per window
        let mut features = Vec::new();
        let mut start = 0;
        for end in 1..n {
            let span = state.timestamps[end] - state.timestamps[start];
            if span >= window_secs || end == n - 1 {
                let fv = state.extract_features_for_window(start, end + 1, window_secs);
                features.push(fv);
                start = end + 1;
            }
        }
        if !features.is_empty() {
            ip_features.insert(ip.clone(), features);
        }
    }

    // Label IPs
    let mut ip_labels: FxHashMap<String, TrafficLabel> = FxHashMap::default();

    if let (Some(attack_file), Some(normal_file)) = (&args.attack_ips, &args.normal_ips) {
        // IP list mode
        let attack_ips: FxHashSet<String> = std::fs::read_to_string(attack_file)
            .context("reading attack IPs file")?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let normal_ips: FxHashSet<String> = std::fs::read_to_string(normal_file)
            .context("reading normal IPs file")?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        for ip in ip_features.keys() {
            if attack_ips.contains(ip) {
                ip_labels.insert(ip.clone(), TrafficLabel::Attack);
            } else if normal_ips.contains(ip) {
                ip_labels.insert(ip.clone(), TrafficLabel::Normal);
            }
        }
    } else if let Some(heuristics_file) = &args.heuristics {
        // Heuristic auto-labeling
        let heuristics_str = std::fs::read_to_string(heuristics_file)
            .context("reading heuristics file")?;
        let thresholds: HeuristicThresholds =
            toml::from_str(&heuristics_str).context("parsing heuristics TOML")?;

        for (ip, features) in &ip_features {
            // Use the aggregate (last/max) feature vector for labeling
            let avg = average_features(features);
            let is_attack = avg[0] > thresholds.request_rate   // request_rate
                || avg[7] > thresholds.path_repetition          // path_repetition
                || avg[3] > thresholds.error_rate               // error_rate
                || avg[13] > thresholds.suspicious_path_ratio   // suspicious_path_ratio
                || (avg[10] < thresholds.no_cookies_threshold   // no cookies + high unique paths
                    && avg[1] > thresholds.no_cookies_path_count);
            ip_labels.insert(
                ip.clone(),
                if is_attack {
                    TrafficLabel::Attack
                } else {
                    TrafficLabel::Normal
                },
            );
        }
    } else {
        bail!("Must provide either --attack-ips + --normal-ips, or --heuristics for labeling");
    }

    // Build training dataset
    let mut all_points: Vec<FeatureVector> = Vec::new();
    let mut all_labels: Vec<TrafficLabel> = Vec::new();

    for (ip, features) in &ip_features {
        if let Some(&label) = ip_labels.get(ip) {
            for fv in features {
                all_points.push(*fv);
                all_labels.push(label);
            }
        }
    }

    if all_points.is_empty() {
        bail!("No labeled data points found. Check your IP lists or heuristic thresholds.");
    }

    let attack_count = all_labels
        .iter()
        .filter(|&&l| l == TrafficLabel::Attack)
        .count();
    let normal_count = all_labels.len() - attack_count;
    eprintln!(
        "Training with {} points ({} attack, {} normal)",
        all_points.len(),
        attack_count,
        normal_count
    );

    // Normalize
    let norm_params = NormParams::from_data(&all_points);
    let normalized: Vec<FeatureVector> = all_points
        .iter()
        .map(|v| norm_params.normalize(v))
        .collect();

    // Serialize
    let model = SerializedModel {
        points: normalized,
        labels: all_labels,
        norm_params,
        k: args.k,
        threshold: args.threshold,
    };

    let encoded = bincode::serialize(&model).context("serializing model")?;
    std::fs::write(&args.output, &encoded)
        .with_context(|| format!("writing model to {}", args.output))?;

    eprintln!(
        "Model saved to {} ({} bytes, {} points)",
        args.output,
        encoded.len(),
        model.points.len()
    );

    Ok(())
}

fn average_features(features: &[FeatureVector]) -> FeatureVector {
    let n = features.len() as f64;
    let mut avg = [0.0; NUM_FEATURES];
    for fv in features {
        for i in 0..NUM_FEATURES {
            avg[i] += fv[i];
        }
    }
    for v in &mut avg {
        *v /= n;
    }
    avg
}
