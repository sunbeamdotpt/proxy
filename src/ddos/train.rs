// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use crate::ddos::audit_log::AuditLog;
use crate::ddos::audit_log;
use crate::ddos::features::{method_to_u8, FeatureVector, LogIpState, NormParams, NUM_FEATURES};
use anyhow::{bail, Context, Result};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::io::BufRead;

/// Legacy KNN training types — kept for the `train-ddos` CLI command
/// which produces bincode model files for offline evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficLabel {
    /// Normal.
    Normal,
    /// Attack.
    Attack,
}

#[derive(Serialize, Deserialize)]
/// Serializedmodel.
pub struct SerializedModel {
    /// Points.
    pub points: Vec<FeatureVector>,
    /// Labels.
    pub labels: Vec<TrafficLabel>,
    /// Norm params.
    pub norm_params: NormParams,
    /// K.
    pub k: usize,
    /// Threshold.
    pub threshold: f64,
}

#[derive(Deserialize)]
/// Heuristicthresholds.
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

impl HeuristicThresholds {
    pub fn new(
        request_rate: f64,
        path_repetition: f64,
        error_rate: f64,
        suspicious_path_ratio: f64,
        no_cookies_threshold: f64,
        no_cookies_path_count: f64,
        min_events: usize,
    ) -> Self {
        Self {
            request_rate,
            path_repetition,
            error_rate,
            suspicious_path_ratio,
            no_cookies_threshold,
            no_cookies_path_count,
            min_events,
        }
    }
}

pub struct DdosTrainResult {
    pub model: SerializedModel,
    pub attack_count: usize,
    pub normal_count: usize,
}

pub struct TrainArgs {
    /// Input.
    pub input: String,
    /// Output.
    pub output: String,
    /// Attack ips.
    pub attack_ips: Option<String>,
    /// Normal ips.
    pub normal_ips: Option<String>,
    /// Heuristics.
    pub heuristics: Option<String>,
    /// K.
    pub k: usize,
    /// Threshold.
    pub threshold: f64,
    /// Window secs.
    pub window_secs: u64,
    /// Min events.
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


/// Core training pipeline: parse logs, extract features, label IPs, build KNN model.
pub fn train_model(args: &TrainArgs) -> Result<DdosTrainResult> {
    let ip_states = parse_logs(&args.input)?;

    let window_secs = args.window_secs as f64;
    let ip_features = extract_ip_features(&ip_states, args.min_events, window_secs);

    // Label IPs
    let ip_labels = label_ips(args, &ip_features)?;

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

    // Normalize
    let norm_params = NormParams::from_data(&all_points);
    let normalized: Vec<FeatureVector> = all_points
        .iter()
        .map(|v| norm_params.normalize(v))
        .collect();

    let model = SerializedModel {
        points: normalized,
        labels: all_labels,
        norm_params,
        k: args.k,
        threshold: args.threshold,
    };

    Ok(DdosTrainResult {
        model,
        attack_count,
        normal_count,
    })
}

/// Train a DDoS model from pre-parsed IP states with programmatic heuristic thresholds.
/// Used by the autotune pipeline to avoid re-parsing logs on each trial.
pub fn train_model_from_states(
    ip_states: &FxHashMap<String, LogIpState>,
    thresholds: &HeuristicThresholds,
    k: usize,
    threshold: f64,
    window_secs: u64,
    min_events: usize,
) -> Result<DdosTrainResult> {
    let window_secs_f64 = window_secs as f64;
    let ip_features = extract_ip_features(ip_states, min_events, window_secs_f64);

    let mut ip_labels: FxHashMap<String, TrafficLabel> = FxHashMap::default();
    for (ip, features) in &ip_features {
        let avg = average_features(features);
        let is_attack = avg[0] > thresholds.request_rate
            || avg[7] > thresholds.path_repetition
            || avg[3] > thresholds.error_rate
            || avg[13] > thresholds.suspicious_path_ratio
            || (avg[10] < thresholds.no_cookies_threshold
                && avg[1] > thresholds.no_cookies_path_count);
        ip_labels.insert(
            ip.clone(),
            if is_attack { TrafficLabel::Attack } else { TrafficLabel::Normal },
        );
    }

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
        bail!("No labeled data points found with these heuristic thresholds.");
    }

    let attack_count = all_labels.iter().filter(|&&l| l == TrafficLabel::Attack).count();
    let normal_count = all_labels.len() - attack_count;

    let norm_params = NormParams::from_data(&all_points);
    let normalized: Vec<FeatureVector> = all_points.iter().map(|v| norm_params.normalize(v)).collect();

    let model = SerializedModel {
        points: normalized,
        labels: all_labels,
        norm_params,
        k,
        threshold,
    };

    Ok(DdosTrainResult { model, attack_count, normal_count })
}

/// Parse audit logs into per-IP state maps.
pub fn parse_logs(input: &str) -> Result<FxHashMap<String, LogIpState>> {
    let mut ip_states: FxHashMap<String, LogIpState> = FxHashMap::default();
    let file = std::fs::File::open(input)
        .with_context(|| format!("opening {}", input))?;
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let entry: AuditLog = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };
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
        state.user_agent_hashes.push(fx_hash(&entry.fields.user_agent));
        state.statuses.push(entry.fields.status);
        state.durations.push(entry.fields.duration_ms.min(u32::MAX as u64) as u32);
        state.content_lengths.push(entry.fields.content_length.min(u32::MAX as u64) as u32);
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

    Ok(ip_states)
}

/// Extract feature vectors per IP using sliding windows.
pub fn extract_ip_features(
    ip_states: &FxHashMap<String, LogIpState>,
    min_events: usize,
    window_secs: f64,
) -> FxHashMap<String, Vec<FeatureVector>> {
    let mut ip_features: FxHashMap<String, Vec<FeatureVector>> = FxHashMap::default();

    for (ip, state) in ip_states {
        let n = state.timestamps.len();
        if n < min_events {
            continue;
        }
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

    ip_features
}

fn label_ips(
    args: &TrainArgs,
    ip_features: &FxHashMap<String, Vec<FeatureVector>>,
) -> Result<FxHashMap<String, TrafficLabel>> {
    let mut ip_labels: FxHashMap<String, TrafficLabel> = FxHashMap::default();

    if let (Some(attack_file), Some(normal_file)) = (&args.attack_ips, &args.normal_ips) {
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
        let heuristics_str = std::fs::read_to_string(heuristics_file)
            .context("reading heuristics file")?;
        let thresholds: HeuristicThresholds =
            toml::from_str(&heuristics_str).context("parsing heuristics TOML")?;

        for (ip, features) in ip_features {
            let avg = average_features(features);
            let is_attack = avg[0] > thresholds.request_rate
                || avg[7] > thresholds.path_repetition
                || avg[3] > thresholds.error_rate
                || avg[13] > thresholds.suspicious_path_ratio
                || (avg[10] < thresholds.no_cookies_threshold
                    && avg[1] > thresholds.no_cookies_path_count);
            ip_labels.insert(
                ip.clone(),
                if is_attack { TrafficLabel::Attack } else { TrafficLabel::Normal },
            );
        }
    } else {
        bail!("Must provide either --attack-ips + --normal-ips, or --heuristics for labeling");
    }

    Ok(ip_labels)
}

pub fn run(args: TrainArgs) -> Result<()> {
    eprintln!("Parsing logs from {}...", args.input);

    let result = train_model(&args)?;

    eprintln!(
        "Training with {} points ({} attack, {} normal)",
        result.model.points.len(),
        result.attack_count,
        result.normal_count
    );

    let encoded = bincode::serialize(&result.model).context("serializing model")?;
    std::fs::write(&args.output, &encoded)
        .with_context(|| format!("writing model to {}", args.output))?;

    eprintln!(
        "Model saved to {} ({} bytes, {} points)",
        args.output,
        encoded.len(),
        result.model.points.len()
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
