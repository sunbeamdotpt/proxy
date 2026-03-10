use crate::autotune::optimizer::BayesianOptimizer;
use crate::autotune::params::{ParamDef, ParamSpace, ParamType};
use crate::ddos::replay::{ReplayArgs, replay_and_evaluate};
use crate::ddos::train::{HeuristicThresholds, train_model_from_states, parse_logs};
use anyhow::{Context, Result};
use std::io::Write;
use std::time::Instant;

pub struct AutotuneDdosArgs {
    pub input: String,
    pub output: String,
    pub trials: usize,
    pub beta: f64,
    pub trial_log: Option<String>,
}

fn ddos_param_space() -> ParamSpace {
    ParamSpace::new(vec![
        ParamDef { name: "k".into(), param_type: ParamType::Integer { min: 1, max: 20 } },
        ParamDef { name: "threshold".into(), param_type: ParamType::Continuous { min: 0.1, max: 0.95 } },
        ParamDef { name: "window_secs".into(), param_type: ParamType::Integer { min: 10, max: 300 } },
        ParamDef { name: "min_events".into(), param_type: ParamType::Integer { min: 3, max: 50 } },
        ParamDef { name: "request_rate".into(), param_type: ParamType::Continuous { min: 1.0, max: 100.0 } },
        ParamDef { name: "path_repetition".into(), param_type: ParamType::Continuous { min: 0.3, max: 0.99 } },
        ParamDef { name: "error_rate".into(), param_type: ParamType::Continuous { min: 0.2, max: 0.95 } },
        ParamDef { name: "suspicious_path_ratio".into(), param_type: ParamType::Continuous { min: 0.05, max: 0.8 } },
        ParamDef { name: "no_cookies_threshold".into(), param_type: ParamType::Continuous { min: 0.01, max: 0.3 } },
        ParamDef { name: "no_cookies_path_count".into(), param_type: ParamType::Continuous { min: 5.0, max: 100.0 } },
    ])
}

pub fn run_autotune(args: AutotuneDdosArgs) -> Result<()> {
    let space = ddos_param_space();
    let mut optimizer = BayesianOptimizer::new(space);

    let mut trial_log_file = if let Some(ref path) = args.trial_log {
        Some(std::fs::File::create(path)?)
    } else {
        None
    };

    // Parse logs once upfront
    eprintln!("Parsing logs from {}...", args.input);
    let ip_states = parse_logs(&args.input)?;
    eprintln!("  {} unique IPs", ip_states.len());

    let mut best_objective = f64::NEG_INFINITY;
    let mut best_model_bytes: Option<Vec<u8>> = None;

    // Create a temporary directory for intermediate models
    let tmp_dir = tempfile::tempdir().context("creating temp dir")?;

    eprintln!("Starting DDoS autotune: {} trials, beta={}", args.trials, args.beta);

    for trial_num in 1..=args.trials {
        let params = optimizer.suggest();
        let k = params[0] as usize;
        let threshold = params[1];
        let window_secs = params[2] as u64;
        let min_events = params[3] as usize;
        let request_rate = params[4];
        let path_repetition = params[5];
        let error_rate = params[6];
        let suspicious_path_ratio = params[7];
        let no_cookies_threshold = params[8];
        let no_cookies_path_count = params[9];

        let heuristics = HeuristicThresholds::new(
            request_rate,
            path_repetition,
            error_rate,
            suspicious_path_ratio,
            no_cookies_threshold,
            no_cookies_path_count,
            min_events,
        );

        let start = Instant::now();

        // Train model with these parameters
        let train_result = match train_model_from_states(
            &ip_states, &heuristics, k, threshold, window_secs, min_events,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  trial {trial_num}: TRAIN FAILED ({e})");
                optimizer.observe(params, 0.0, start.elapsed());
                continue;
            }
        };

        // Save temporary model for replay
        let tmp_model_path = tmp_dir.path().join(format!("trial_{trial_num}.bin"));
        let encoded = match bincode::serialize(&train_result.model) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("  trial {trial_num}: SERIALIZE FAILED ({e})");
                optimizer.observe(params, 0.0, start.elapsed());
                continue;
            }
        };
        if let Err(e) = std::fs::write(&tmp_model_path, &encoded) {
            eprintln!("  trial {trial_num}: WRITE FAILED ({e})");
            optimizer.observe(params, 0.0, start.elapsed());
            continue;
        }

        // Replay to evaluate
        let replay_args = ReplayArgs {
            input: args.input.clone(),
            model_path: tmp_model_path.to_string_lossy().into_owned(),
            config_path: None,
            k,
            threshold,
            window_secs,
            min_events,
            rate_limit: false,
        };

        let replay_result = match replay_and_evaluate(&replay_args) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  trial {trial_num}: REPLAY FAILED ({e})");
                optimizer.observe(params, 0.0, start.elapsed());
                continue;
            }
        };
        let duration = start.elapsed();

        // Compute F-beta from replay false-positive analysis
        let tp = replay_result.true_positive_ips as f64;
        let fp = replay_result.false_positive_ips as f64;
        let total_blocked = replay_result.ddos_blocked_ips.len() as f64;
        let fn_ = if total_blocked > 0.0 { 0.0 } else { 1.0 }; // We don't know true FN without ground truth

        let objective = if tp + fp > 0.0 {
            let precision = tp / (tp + fp);
            let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
            let b2 = args.beta * args.beta;
            if precision + recall > 0.0 {
                (1.0 + b2) * precision * recall / (b2 * precision + recall)
            } else {
                0.0
            }
        } else {
            0.0
        };

        eprintln!(
            "  trial {trial_num}/{}: fbeta={objective:.4} (k={k}, thr={threshold:.3}, win={window_secs}s, tp={}, fp={}) [{:.1}s]",
            args.trials,
            replay_result.true_positive_ips,
            replay_result.false_positive_ips,
            duration.as_secs_f64(),
        );

        // Log trial as JSONL
        if let Some(ref mut f) = trial_log_file {
            let trial_json = serde_json::json!({
                "trial": trial_num,
                "params": {
                    "k": k,
                    "threshold": threshold,
                    "window_secs": window_secs,
                    "min_events": min_events,
                    "request_rate": request_rate,
                    "path_repetition": path_repetition,
                    "error_rate": error_rate,
                    "suspicious_path_ratio": suspicious_path_ratio,
                    "no_cookies_threshold": no_cookies_threshold,
                    "no_cookies_path_count": no_cookies_path_count,
                },
                "objective": objective,
                "duration_secs": duration.as_secs_f64(),
                "true_positive_ips": replay_result.true_positive_ips,
                "false_positive_ips": replay_result.false_positive_ips,
                "ddos_blocked": replay_result.ddos_blocked,
                "allowed": replay_result.allowed,
                "attack_count": train_result.attack_count,
                "normal_count": train_result.normal_count,
            });
            writeln!(f, "{}", trial_json)?;
        }

        if objective > best_objective {
            best_objective = objective;
            best_model_bytes = Some(encoded);
        }

        // Clean up temporary model
        let _ = std::fs::remove_file(&tmp_model_path);

        optimizer.observe(params, objective, duration);
    }

    // Save best model
    if let Some(bytes) = best_model_bytes {
        std::fs::write(&args.output, &bytes)?;
        eprintln!("\nBest model saved to {}", args.output);
    }

    // Print summary
    if let Some(best) = optimizer.best() {
        eprintln!("\n═══ Autotune Results ═══════════════════════════════════════");
        eprintln!("  Best trial:        #{}", best.trial_num);
        eprintln!("  Best F-beta:       {:.4}", best.objective);
        eprintln!("  Parameters:");
        for (name, val) in best.param_names.iter().zip(best.params.iter()) {
            eprintln!("    {:<30} = {:.6}", name, val);
        }
        eprintln!("\n  Heuristics TOML snippet:");
        eprintln!("    request_rate = {:.2}", best.params[4]);
        eprintln!("    path_repetition = {:.4}", best.params[5]);
        eprintln!("    error_rate = {:.4}", best.params[6]);
        eprintln!("    suspicious_path_ratio = {:.4}", best.params[7]);
        eprintln!("    no_cookies_threshold = {:.4}", best.params[8]);
        eprintln!("    no_cookies_path_count = {:.1}", best.params[9]);
        eprintln!("    min_events = {}", best.params[3] as usize);
        eprintln!("\n  Reproduce:");
        eprintln!(
            "    cargo run -- train-ddos --input {} --output {} --k {} --threshold {:.4} --window-secs {} --min-events {} --heuristics <toml>",
            args.input, args.output,
            best.params[0] as usize, best.params[1],
            best.params[2] as u64, best.params[3] as usize,
        );
        eprintln!("══════════════════════════════════════════════════════════");
    }

    Ok(())
}
