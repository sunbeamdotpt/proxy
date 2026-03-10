// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

mod cert;
mod telemetry;
mod watcher;

use sunbeam_proxy::{acme, autotune, config};
use sunbeam_proxy::proxy::SunbeamProxy;
use sunbeam_proxy::rate_limit;
use sunbeam_proxy::scanner;

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use clap::{Parser, Subcommand};
use kube::Client;
use pingora::server::{configuration::Opt, Server};
use pingora_proxy::http_proxy_service;
use std::sync::RwLock;

#[derive(Parser)]
#[command(name = "sunbeam-proxy")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the proxy server (default if no subcommand given)
    Serve {
        /// Pingora --upgrade flag for zero-downtime reload
        #[arg(long)]
        upgrade: bool,
    },
    /// Replay audit logs through detection models
    Replay {
        #[command(subcommand)]
        mode: ReplayMode,
    },
    /// Train a DDoS detection model from audit logs
    TrainDdos {
        /// Path to audit log JSONL file
        #[arg(short, long)]
        input: String,
        /// Output model file path
        #[arg(short, long)]
        output: String,
        /// File with known-attack IPs (one per line)
        #[arg(long)]
        attack_ips: Option<String>,
        /// File with known-normal IPs (one per line)
        #[arg(long)]
        normal_ips: Option<String>,
        /// TOML file with heuristic auto-labeling thresholds
        #[arg(long)]
        heuristics: Option<String>,
        /// KNN k parameter
        #[arg(long, default_value = "5")]
        min_events: usize,
    },
    /// Download and cache upstream datasets (CIC-IDS2017)
    DownloadDatasets,
    /// Prepare a unified training dataset from multiple sources
    PrepareDataset {
        /// Path to audit log JSONL file
        #[arg(short, long)]
        input: String,
        /// Path to OWASP ModSecurity audit log file (optional extra data)
        #[arg(long)]
        owasp: Option<String>,
        /// Directory containing .txt wordlists (optional, enhances synthetic scanner)
        #[arg(long)]
        wordlists: Option<String>,
        /// Output dataset file path
        #[arg(short, long, default_value = "dataset.bin")]
        output: String,
        /// Random seed
        #[arg(long, default_value = "42")]
        seed: u64,
        /// Path to heuristics.toml for auto-labeling production logs
        #[arg(long)]
        heuristics: Option<String>,
        /// Inject CSIC 2010 dataset as labeled audit log entries
        #[arg(long)]
        inject_csic: bool,
        /// Inject OWASP ModSec audit log entries (path to .log file)
        #[arg(long)]
        inject_modsec: Option<String>,
    },
    #[cfg(feature = "training")]
    /// Train scanner ensemble (decision tree + MLP) from prepared dataset
    TrainMlpScanner {
        /// Path to prepared dataset (.bin)
        #[arg(short = 'd', long)]
        dataset: String,
        /// Output directory for generated weight files
        #[arg(short, long, default_value = "src/ensemble/gen")]
        output_dir: String,
        /// Hidden layer dimension
        #[arg(long, default_value = "32")]
        hidden_dim: usize,
        /// Training epochs
        #[arg(long, default_value = "100")]
        epochs: usize,
        /// Learning rate
        #[arg(long, default_value = "0.0001")]
        learning_rate: f64,
        /// Batch size
        #[arg(long, default_value = "64")]
        batch_size: usize,
        /// Max tree depth
        #[arg(long, default_value = "6")]
        tree_max_depth: usize,
        /// Min purity for tree leaves (below -> Defer)
        #[arg(long, default_value = "0.90")]
        tree_min_purity: f32,
        /// Min samples required in a leaf node (higher = less overfitting)
        #[arg(long, default_value = "2")]
        min_samples_leaf: usize,
        /// Weight for cookie feature (0.0=ignore, 1.0=full). Controls has_cookies influence.
        #[arg(long, default_value = "1.0")]
        cookie_weight: f32,
        /// Feature indices the tree must not split on. Comma-separated.
        /// Default: has_cookies/has_referer/has_accept_language/accept_quality (3,4,5,6).
        #[arg(long, value_delimiter = ',', default_value = "3,4,5,6")]
        tree_excluded_features: Vec<usize>,
        /// Sign-constraint penalty coefficient (0.0 disables).
        #[arg(long, default_value = "0.0")]
        sign_constraint_lambda: f32,
    },
    #[cfg(feature = "training")]
    /// Train DDoS ensemble (decision tree + MLP) from prepared dataset
    TrainMlpDdos {
        #[arg(short = 'd', long)]
        dataset: String,
        #[arg(short, long, default_value = "src/ensemble/gen")]
        output_dir: String,
        #[arg(long, default_value = "32")]
        hidden_dim: usize,
        #[arg(long, default_value = "100")]
        epochs: usize,
        #[arg(long, default_value = "0.0001")]
        learning_rate: f64,
        #[arg(long, default_value = "64")]
        batch_size: usize,
        #[arg(long, default_value = "6")]
        tree_max_depth: usize,
        /// Min purity for tree leaves (below -> Defer)
        #[arg(long, default_value = "0.90")]
        tree_min_purity: f32,
        /// Min samples required in a leaf node (higher = less overfitting)
        #[arg(long, default_value = "2")]
        min_samples_leaf: usize,
        /// Weight for cookie feature (0.0=ignore, 1.0=full). Controls cookie_ratio influence.
        #[arg(long, default_value = "1.0")]
        cookie_weight: f32,
        /// Feature indices the tree must not split on. Comma-separated.
        /// Default: cookie/referer/accept-language ratios (10,11,12).
        #[arg(long, value_delimiter = ',', default_value = "10,11,12")]
        tree_excluded_features: Vec<usize>,
        /// Sign-constraint penalty coefficient (0.0 disables).
        #[arg(long, default_value = "0.0")]
        sign_constraint_lambda: f32,
    },
    #[cfg(feature = "training")]
    /// Sweep cookie_weight values and report tree structure + validation accuracy for each
    SweepCookieWeight {
        /// Path to prepared dataset (.bin)
        #[arg(short = 'd', long)]
        dataset: String,
        /// Which detector to sweep: "scanner" or "ddos"
        #[arg(long, default_value = "scanner")]
        detector: String,
        /// Comma-separated cookie_weight values to try (default: 0.0,0.1,0.2,...,1.0)
        #[arg(long)]
        weights: Option<String>,
        /// Max tree depth
        #[arg(long, default_value = "6")]
        tree_max_depth: usize,
        /// Min purity for tree leaves
        #[arg(long, default_value = "0.90")]
        tree_min_purity: f32,
        /// Min samples required in a leaf node
        #[arg(long, default_value = "2")]
        min_samples_leaf: usize,
    },
    /// Bayesian hyperparameter optimization for DDoS model
    AutotuneDdos {
        /// Path to audit log JSONL file
        #[arg(short, long)]
        input: String,
        /// Output best model file path
        #[arg(short, long, default_value = "ddos_model_best.bin")]
        output: String,
        /// Number of optimization trials
        #[arg(long, default_value = "200")]
        trials: usize,
        /// F-beta parameter (1.0 = F1, 2.0 = recall-weighted)
        #[arg(long, default_value = "1.0")]
        beta: f64,
        /// JSONL file to log each trial's parameters and results
        #[arg(long)]
        trial_log: Option<String>,
    },
    /// Download and cache upstream datasets (CIC-IDS2017)
    DownloadDatasets,
    /// Prepare a unified training dataset from multiple sources
    PrepareDataset {
        /// Path to audit log JSONL file
        #[arg(short, long)]
        input: String,
        /// Path to OWASP ModSecurity audit log file (optional extra data)
        #[arg(long)]
        owasp: Option<String>,
        /// Directory containing .txt wordlists (optional, enhances synthetic scanner)
        #[arg(long)]
        wordlists: Option<String>,
        /// Output dataset file path
        #[arg(short, long, default_value = "dataset.bin")]
        output: String,
        /// Random seed
        #[arg(long, default_value = "42")]
        seed: u64,
        /// Path to heuristics.toml for auto-labeling production logs
        #[arg(long)]
        heuristics: Option<String>,
    },
    #[cfg(feature = "training")]
    /// Train scanner ensemble (decision tree + MLP) from prepared dataset
    TrainMlpScanner {
        /// Path to prepared dataset (.bin)
        #[arg(short = 'd', long)]
        dataset: String,
        /// Output directory for generated weight files
        #[arg(short, long, default_value = "src/ensemble/gen")]
        output_dir: String,
        /// Hidden layer dimension
        #[arg(long, default_value = "32")]
        hidden_dim: usize,
        /// Training epochs
        #[arg(long, default_value = "100")]
        epochs: usize,
        /// Learning rate
        #[arg(long, default_value = "0.001")]
        learning_rate: f64,
        /// Batch size
        #[arg(long, default_value = "64")]
        batch_size: usize,
        /// Max tree depth
        #[arg(long, default_value = "6")]
        tree_max_depth: usize,
        /// Min purity for tree leaves (below -> Defer)
        #[arg(long, default_value = "0.90")]
        tree_min_purity: f32,
    },
    #[cfg(feature = "training")]
    /// Train DDoS ensemble (decision tree + MLP) from prepared dataset
    TrainMlpDdos {
        #[arg(short = 'd', long)]
        dataset: String,
        #[arg(short, long, default_value = "src/ensemble/gen")]
        output_dir: String,
        #[arg(long, default_value = "32")]
        hidden_dim: usize,
        #[arg(long, default_value = "100")]
        epochs: usize,
        #[arg(long, default_value = "0.001")]
        learning_rate: f64,
        #[arg(long, default_value = "64")]
        batch_size: usize,
        #[arg(long, default_value = "6")]
        tree_max_depth: usize,
        #[arg(long, default_value = "0.90")]
        tree_min_purity: f32,
    },
    /// Bayesian hyperparameter optimization for scanner model
    AutotuneScanner {
        /// Path to audit log JSONL file
        #[arg(short, long)]
        input: String,
        /// Output best model file path
        #[arg(short, long, default_value = "scanner_model_best.bin")]
        output: String,
        /// Directory (or file) containing .txt wordlists of scanner paths
        #[arg(long)]
        wordlists: Option<String>,
        /// Include CSIC 2010 dataset as base training data
        #[arg(long)]
        csic: bool,
        /// Number of optimization trials
        #[arg(long, default_value = "200")]
        trials: usize,
        /// F-beta parameter (1.0 = F1, 2.0 = recall-weighted)
        #[arg(long, default_value = "1.0")]
        beta: f64,
        /// JSONL file to log each trial's parameters and results
        #[arg(long)]
        trial_log: Option<String>,
    },
}

#[derive(Subcommand)]
enum ReplayMode {
    /// Replay through ensemble models (scanner + DDoS)
    Ensemble {
        /// Path to audit log JSONL file
        #[arg(short, long)]
        input: String,
        /// Sliding window size in seconds
        #[arg(long, default_value = "60")]
        window_secs: u64,
        /// Minimum events per IP before DDoS classification
        #[arg(long, default_value = "5")]
        min_events: usize,
    },
    /// Replay through legacy KNN DDoS detector
    Ddos {
        /// Path to audit log JSONL file
        #[arg(short, long)]
        input: String,
        /// Path to trained model file
        #[arg(short, long, default_value = "ddos_model.bin")]
        model: String,
        /// Optional config file (for rate limit settings)
        #[arg(short, long)]
        config: Option<String>,
        /// KNN k parameter
        #[arg(long, default_value = "5")]
        k: usize,
        /// Attack threshold
        #[arg(long, default_value = "0.6")]
        threshold: f64,
        /// Sliding window size in seconds
        #[arg(long, default_value = "60")]
        window_secs: u64,
        /// Minimum events per IP before classification
        #[arg(long, default_value = "10")]
        min_events: usize,
        /// Also run rate limiter during replay
        #[arg(long)]
        rate_limit: bool,
    },
}


fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Serve { upgrade: false }) {
        Commands::Serve { upgrade } => run_serve(upgrade),
        Commands::Replay { mode } => match mode {
            ReplayMode::Ensemble { input, window_secs, min_events } => {
                sunbeam_proxy::ensemble::replay::run(sunbeam_proxy::ensemble::replay::ReplayEnsembleArgs {
                    input, window_secs, min_events,
                })
            }
            ReplayMode::Ddos { input, model, config, k, threshold, window_secs, min_events, rate_limit } => {
                ddos::replay::run(ddos::replay::ReplayArgs {
                    input, model_path: model, config_path: config, k, threshold, window_secs, min_events, rate_limit,
                })
            }
        },
        Commands::TrainDdos {
            input,
            output,
            attack_ips,
            normal_ips,
            heuristics,
            k,
            threshold,
            window_secs,
            min_events,
        } => ddos::train::run(ddos::train::TrainArgs {
            input,
            output,
            attack_ips,
            normal_ips,
            heuristics,
            k,
            threshold,
            window_secs,
            min_events,
        }),
        Commands::TrainScanner {
            input,
            output,
            wordlists,
            threshold,
            csic,
        } => scanner::train::run(scanner::train::TrainScannerArgs {
            input,
            output,
            wordlists,
            threshold,
            csic,
        }),
        Commands::DownloadDatasets => {
            sunbeam_proxy::dataset::download::download_all()
        },
        Commands::PrepareDataset { input, owasp, wordlists, output, seed, heuristics } => {
            sunbeam_proxy::dataset::prepare::run(sunbeam_proxy::dataset::prepare::PrepareDatasetArgs {
                input, owasp, wordlists, output, seed, heuristics,
            })
        },
        #[cfg(feature = "training")]
        Commands::TrainMlpScanner { dataset, output_dir, hidden_dim, epochs, learning_rate, batch_size, tree_max_depth, tree_min_purity } => {
            sunbeam_proxy::training::train_scanner::run(sunbeam_proxy::training::train_scanner::TrainScannerMlpArgs {
                dataset_path: dataset, output_dir, hidden_dim, epochs, learning_rate, batch_size, tree_max_depth, tree_min_purity,
            })
        },
        #[cfg(feature = "training")]
        Commands::TrainMlpDdos { dataset, output_dir, hidden_dim, epochs, learning_rate, batch_size, tree_max_depth, tree_min_purity } => {
            sunbeam_proxy::training::train_ddos::run(sunbeam_proxy::training::train_ddos::TrainDdosMlpArgs {
                dataset_path: dataset, output_dir, hidden_dim, epochs, learning_rate, batch_size, tree_max_depth, tree_min_purity,
            })
        },
        Commands::AutotuneDdos {
            input,
            output,
            trials,
            beta,
            trial_log,
        } => autotune::ddos::run_autotune(autotune::ddos::AutotuneDdosArgs {
            input,
            output,
            trials,
            beta,
            trial_log,
        }),
        Commands::AutotuneScanner {
            input,
            output,
            wordlists,
            csic,
            trials,
            beta,
            trial_log,
        } => autotune::scanner::run_autotune(autotune::scanner::AutotuneScannerArgs {
            input,
            output,
            wordlists,
            csic,
            trials,
            beta,
            trial_log,
        }),
    }
}

fn run_serve(upgrade: bool) -> Result<()> {
    // Install the aws-lc-rs crypto provider for rustls before any TLS init.
    // Required because rustls 0.23 no longer auto-selects a provider at compile time.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("crypto provider already installed");

    let config_path = std::env::var("SUNBEAM_CONFIG")
        .unwrap_or_else(|_| "/etc/pingora/config.toml".to_string());
    let cfg = config::Config::load(&config_path)?;

    // 1. Init telemetry (JSON logs + optional OTEL traces).
    telemetry::init(&cfg.telemetry.otlp_endpoint);

    // 1b. Spawn metrics HTTP server (needs a tokio runtime for the TCP listener).
    let metrics_port = cfg.telemetry.metrics_port;

    // 2. Init DDoS detector if configured (ensemble: compiled-in weights).
    let ddos_detector = if let Some(ddos_cfg) = &cfg.ddos {
        if ddos_cfg.enabled {
            if ddos_cfg.use_ensemble {
                // Ensemble path: compiled-in weights, no model file needed.
                // We still need a TrainedModel for the struct, but it won't be used.
                let dummy_model = ddos::model::TrainedModel::empty(ddos_cfg.k, ddos_cfg.threshold);
                let detector = Arc::new(ddos::detector::DDoSDetector::new_ensemble(dummy_model, ddos_cfg));
                tracing::info!(
                    k = ddos_cfg.k,
                    threshold = ddos_cfg.threshold,
                    "DDoS ensemble detector enabled"
                );
                Some(detector)
            } else if let Some(ref model_path) = ddos_cfg.model_path {
                match ddos::model::TrainedModel::load(
                    std::path::Path::new(model_path),
                    Some(ddos_cfg.k),
                    Some(ddos_cfg.threshold),
                ) {
                    Ok(model) => {
                        let point_count = model.point_count();
                        let detector = Arc::new(ddos::detector::DDoSDetector::new(model, ddos_cfg));
                        tracing::info!(
                            points = point_count,
                            k = ddos_cfg.k,
                            threshold = ddos_cfg.threshold,
                            "DDoS detector loaded"
                        );
                        Some(detector)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to load DDoS model; detection disabled");
                        None
                    }
                }
            } else {
                tracing::warn!("DDoS enabled but no model_path and use_ensemble=false; detection disabled");
                None
            }
            Some(detector)
        } else {
            None
        }
    } else {
        None
    };

    // 2b. Init rate limiter if configured.
    let rate_limiter = if let Some(rl_cfg) = &cfg.rate_limit {
        if rl_cfg.enabled {
            let limiter = Arc::new(rate_limit::limiter::RateLimiter::new(rl_cfg));
            let evict_limiter = limiter.clone();
            let interval = rl_cfg.eviction_interval_secs;
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(interval));
                evict_limiter.evict_stale();
            });
            tracing::info!(
                auth_burst = rl_cfg.authenticated.burst,
                auth_rate = rl_cfg.authenticated.rate,
                unauth_burst = rl_cfg.unauthenticated.burst,
                unauth_rate = rl_cfg.unauthenticated.rate,
                "rate limiter enabled"
            );
            Some(limiter)
        } else {
            None
        }
    } else {
        None
    };

    // 2c. Init scanner detector if configured (ensemble: compiled-in weights).
    let (scanner_detector, bot_allowlist) = if let Some(scanner_cfg) = &cfg.scanner {
        if scanner_cfg.enabled {
            if scanner_cfg.use_ensemble {
                // Ensemble path: compiled-in weights, no model file needed.
                let detector = scanner::detector::ScannerDetector::new_ensemble(&cfg.routes);
                let handle = Arc::new(arc_swap::ArcSwap::from_pointee(detector));

                // Start bot allowlist if rules are configured.
                let bot_allowlist = if !scanner_cfg.allowlist.is_empty() {
                    let al = scanner::allowlist::BotAllowlist::spawn(
                        &scanner_cfg.allowlist,
                        scanner_cfg.bot_cache_ttl_secs,
                    );
                    tracing::info!(
                        rules = scanner_cfg.allowlist.len(),
                        "bot allowlist enabled"
                    );
                    Some(al)
                } else {
                    None
                };

                tracing::info!(
                    threshold = scanner_cfg.threshold,
                    "scanner ensemble detector enabled"
                );
                (Some(handle), bot_allowlist)
            } else if let Some(ref model_path) = scanner_cfg.model_path {
                match scanner::model::ScannerModel::load(std::path::Path::new(model_path)) {
                    Ok(mut model) => {
                        let fragment_count = model.fragments.len();
                        model.threshold = scanner_cfg.threshold;
                        let detector = scanner::detector::ScannerDetector::new(&model, &cfg.routes);
                        let handle = Arc::new(arc_swap::ArcSwap::from_pointee(detector));

                        // Start bot allowlist if rules are configured.
                        let bot_allowlist = if !scanner_cfg.allowlist.is_empty() {
                            let al = scanner::allowlist::BotAllowlist::spawn(
                                &scanner_cfg.allowlist,
                                scanner_cfg.bot_cache_ttl_secs,
                            );
                            tracing::info!(
                                rules = scanner_cfg.allowlist.len(),
                                "bot allowlist enabled"
                            );
                            Some(al)
                        } else {
                            None
                        };

                        // Start background file watcher for hot-reload.
                        if scanner_cfg.poll_interval_secs > 0 {
                            let watcher_handle = handle.clone();
                            let watcher_model_path = std::path::PathBuf::from(model_path);
                            let threshold = scanner_cfg.threshold;
                            let routes = cfg.routes.clone();
                            let interval = std::time::Duration::from_secs(scanner_cfg.poll_interval_secs);
                            std::thread::spawn(move || {
                                scanner::watcher::watch_scanner_model(
                                    watcher_handle, watcher_model_path, threshold, routes, interval,
                                );
                            });
                        }

                        tracing::info!(
                            fragments = fragment_count,
                            threshold = scanner_cfg.threshold,
                            poll_interval_secs = scanner_cfg.poll_interval_secs,
                            "scanner detector loaded"
                        );
                        (Some(handle), bot_allowlist)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to load scanner model; scanner detection disabled");
                        (None, None)
                    }
                }
            } else {
                tracing::warn!("scanner enabled but no model_path and use_ensemble=false; scanner detection disabled");
                (None, None)
            }
            (Some(handle), bot_allowlist)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    // 3. Fetch the TLS cert from K8s before Pingora binds the TLS port.
    //    The Client is created and dropped within this temp runtime — we do NOT
    //    carry it across runtime boundaries, which would kill its tower workers.
    //    The watcher thread creates its own fresh Client on its own runtime.
    let k8s_available = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            match Client::try_default().await {
                Ok(c) => {
                    if !upgrade {
                        if let Err(e) =
                            cert::fetch_and_write(
                                &c,
                                &cfg.kubernetes.namespace,
                                &cfg.kubernetes.tls_secret,
                                &cfg.tls.cert_path,
                                &cfg.tls.key_path,
                            ).await
                        {
                            tracing::warn!(error = %e, "cert fetch from K8s failed; using existing files");
                        }
                    }
                    true
                }
                Err(e) => {
                    tracing::warn!(error = %e, "no K8s client; cert auto-reload and ACME routing disabled");
                    false
                }
            }
        })
    };

    let opt = Opt {
        upgrade,
        daemon: false,
        nocapture: false,
        test: false,
        conf: None,
    };

    // 4. Create Pingora server and bootstrap (binds ports or inherits FDs).
    let mut server = Server::new(Some(opt))?;
    server.bootstrap();

    // 5. Shared ACME challenge route table.  Populated by the Ingress watcher;
    //    consulted by the proxy for every /.well-known/acme-challenge/ request.
    //    Uses std::sync::RwLock so reads are sync and lock-guard-safe across
    //    Pingora's async proxy calls without cross-runtime waker concerns.
    let acme_routes: acme::AcmeRoutes = Arc::new(RwLock::new(HashMap::new()));

    // 2d. Spawn cluster gossip if configured.
    let cluster_handle = if let Some(cc) = &cfg.cluster {
        if cc.enabled {
            match sunbeam_proxy::cluster::spawn_cluster(cc) {
                Ok(handle) => {
                    tracing::info!(
                        endpoint_id = %handle.endpoint_id,
                        tenant = %cc.tenant,
                        port = cc.gossip_port,
                        "cluster gossip started"
                    );
                    Some(Arc::new(handle))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to start cluster; running standalone");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let compiled_rewrites = SunbeamProxy::compile_rewrites(&cfg.routes);
    let http_client = reqwest::Client::new();

    let proxy = SunbeamProxy {
        routes: cfg.routes.clone(),
        acme_routes: acme_routes.clone(),
        ddos_detector,
        scanner_detector,
        bot_allowlist,
        rate_limiter,
        compiled_rewrites,
        http_client,
        pipeline_bypass_cidrs: crate::rate_limit::cidr::parse_cidrs(
            &cfg.rate_limit.as_ref().map(|rl| rl.bypass_cidrs.clone()).unwrap_or_default(),
        ),
        cluster: cluster_handle,
    };
    let mut svc = http_proxy_service(&server.configuration, proxy);

    // Port 80: always serve plain HTTP (ACME challenges + redirect to HTTPS).
    svc.add_tcp(&cfg.listen.http);

    // Port 443: only add the TLS listener if the cert files exist.
    // When tls_passthrough routes are configured, Pingora binds to an internal
    // loopback address and a dedicated SNI router takes the real HTTPS port.
    let cert_exists = std::path::Path::new(&cfg.tls.cert_path).exists();
    let has_passthrough = cfg.tls_passthrough.as_ref().is_some_and(|r| !r.is_empty());
    let pingora_internal_addr = "127.0.0.1:10443";

    if cert_exists {
        let tls_bind = if has_passthrough { pingora_internal_addr } else { &cfg.listen.https };
        let mut tls_settings = pingora_core::listeners::tls::TlsSettings::intermediate(
            &cfg.tls.cert_path,
            &cfg.tls.key_path,
        )?;
        tls_settings.enable_h2();
        svc.add_tls_with_settings(tls_bind, None, tls_settings);
        tracing::info!(addr = %tls_bind, passthrough = has_passthrough, "TLS listener added");
    } else {
        tracing::warn!(
            cert_path = %cfg.tls.cert_path,
            "cert not found — starting HTTP-only; ACME challenge will complete and trigger upgrade"
        );
    }

    server.add_service(svc);

    // 5b. Spawn metrics + health HTTP server on its own thread.
    if metrics_port > 0 {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("metrics runtime");
            rt.block_on(async {
                sunbeam_proxy::metrics::spawn_metrics_server(metrics_port);
                // Keep the runtime alive.
                std::future::pending::<()>().await;
            });
        });
    }

    // 5c. SSH TCP passthrough (port 22 → Gitea SSH), if configured.
    if let Some(ssh_cfg) = &cfg.ssh {
        let listen = ssh_cfg.listen.clone();
        let backend = ssh_cfg.backend.clone();
        tracing::info!(%listen, %backend, "SSH TCP proxy enabled");
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("ssh proxy runtime");
            rt.block_on(sunbeam_proxy::ssh::run_tcp_proxy(&listen, &backend));
        });
    }

    // 5d. TLS passthrough SNI router (port 443 → peek SNI → route or forward to Pingora).
    if let Some(passthrough_routes) = &cfg.tls_passthrough {
        if !passthrough_routes.is_empty() && cert_exists {
            let listen = cfg.listen.https.clone();
            let routes = passthrough_routes.clone();
            let internal = pingora_internal_addr.to_string();
            tracing::info!(
                %listen,
                routes = routes.len(),
                internal = %internal,
                "TLS passthrough SNI router enabled"
            );
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("tls passthrough runtime");
                rt.block_on(sunbeam_proxy::tls_passthrough::run(&listen, &routes, &internal));
            });
        }
    }

    // 6. Background K8s watchers on their own OS thread + tokio runtime.
    if k8s_available {
        let k8s_cfg = cfg.kubernetes.clone();
        let cert_path = cfg.tls.cert_path.clone();
        let key_path = cfg.tls.key_path.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("watcher runtime");
            rt.block_on(async move {
                let client = match Client::try_default().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(error = %e, "watcher: failed to create K8s client; watchers disabled");
                        return;
                    }
                };
                tokio::join!(
                    acme::watch_ingresses(
                        client.clone(),
                        k8s_cfg.namespace.clone(),
                        acme_routes,
                    ),
                    watcher::run_watcher(
                        client,
                        k8s_cfg.namespace,
                        k8s_cfg.tls_secret,
                        k8s_cfg.config_configmap,
                        cert_path,
                        key_path,
                    ),
                );
            });
        });
    }

    tracing::info!(upgrade, "sunbeam-proxy starting");
    server.run_forever();
}
