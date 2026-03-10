use crate::autotune::optimizer::BayesianOptimizer;
use crate::autotune::params::{ParamDef, ParamSpace, ParamType};
use crate::scanner::train::{TrainScannerArgs, train_and_evaluate};
use anyhow::Result;
use std::io::Write;
use std::time::Instant;

pub struct AutotuneScannerArgs {
    pub input: String,
    pub output: String,
    pub wordlists: Option<String>,
    pub csic: bool,
    pub trials: usize,
    pub beta: f64,
    pub trial_log: Option<String>,
}

fn scanner_param_space() -> ParamSpace {
    ParamSpace::new(vec![
        ParamDef { name: "threshold".into(), param_type: ParamType::Continuous { min: 0.1, max: 0.95 } },
        ParamDef { name: "learning_rate".into(), param_type: ParamType::LogScale { min: 0.001, max: 0.1 } },
        ParamDef { name: "epochs".into(), param_type: ParamType::Integer { min: 100, max: 5000 } },
        ParamDef { name: "class_weight_multiplier".into(), param_type: ParamType::Continuous { min: 0.5, max: 5.0 } },
    ])
}

pub fn run_autotune(args: AutotuneScannerArgs) -> Result<()> {
    let space = scanner_param_space();
    let mut optimizer = BayesianOptimizer::new(space);

    let mut trial_log_file = if let Some(ref path) = args.trial_log {
        Some(std::fs::File::create(path)?)
    } else {
        None
    };

    let mut best_objective = f64::NEG_INFINITY;
    let mut best_model_bytes: Option<Vec<u8>> = None;

    eprintln!("Starting scanner autotune: {} trials, beta={}", args.trials, args.beta);

    for trial_num in 1..=args.trials {
        let params = optimizer.suggest();
        let threshold = params[0];
        let learning_rate = params[1];
        let epochs = params[2] as usize;
        let class_weight_multiplier = params[3];

        let train_args = TrainScannerArgs {
            input: args.input.clone(),
            output: String::new(), // don't save intermediate models
            wordlists: args.wordlists.clone(),
            threshold,
            csic: args.csic,
        };

        let start = Instant::now();
        let result = match train_and_evaluate(&train_args, learning_rate, epochs, class_weight_multiplier) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  trial {trial_num}: FAILED ({e})");
                optimizer.observe(params, 0.0, start.elapsed());
                continue;
            }
        };
        let duration = start.elapsed();

        let objective = result.test_metrics.fbeta(args.beta);

        eprintln!(
            "  trial {trial_num}/{}: fbeta={objective:.4} (threshold={threshold:.3}, lr={learning_rate:.5}, epochs={epochs}, cwm={class_weight_multiplier:.2}) [{:.1}s]",
            args.trials,
            duration.as_secs_f64(),
        );

        // Log trial as JSONL
        if let Some(ref mut f) = trial_log_file {
            let trial_json = serde_json::json!({
                "trial": trial_num,
                "params": {
                    "threshold": threshold,
                    "learning_rate": learning_rate,
                    "epochs": epochs,
                    "class_weight_multiplier": class_weight_multiplier,
                },
                "objective": objective,
                "duration_secs": duration.as_secs_f64(),
                "train_f1": result.train_metrics.f1(),
                "test_precision": result.test_metrics.precision(),
                "test_recall": result.test_metrics.recall(),
            });
            writeln!(f, "{}", trial_json)?;
        }

        if objective > best_objective {
            best_objective = objective;
            let encoded = bincode::serialize(&result.model)?;
            best_model_bytes = Some(encoded);
        }

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
        eprintln!("\n  Reproduce:");
        eprintln!(
            "    cargo run -- train-scanner --input {} --output {} --threshold {:.4}",
            args.input, args.output, best.params[0],
        );
        eprintln!("══════════════════════════════════════════════════════════");
    }

    Ok(())
}
