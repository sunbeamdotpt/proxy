// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

mod cert;
mod telemetry;
mod watcher;

use sunbeam_proxy::{acme, config};
use sunbeam_proxy::proxy::SunbeamProxy;
use sunbeam_proxy::rate_limit;
use sunbeam_proxy::scanner;

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use arc_swap::ArcSwap;
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
    /// Replay audit logs through ensemble models (scanner + DDoS)
    Replay {
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
}



fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Serve { upgrade: false }) {
        Commands::Serve { upgrade } => run_serve(upgrade),
        Commands::Replay { input, window_secs, min_events } => {
            sunbeam_proxy::ensemble::replay::run(sunbeam_proxy::ensemble::replay::ReplayEnsembleArgs {
                input, window_secs, min_events,
            })
        },
        Commands::DownloadDatasets => {
            sunbeam_proxy::dataset::download::download_all()
        },
        Commands::PrepareDataset { input, owasp, wordlists, output, seed, heuristics, inject_csic, inject_modsec } => {
            sunbeam_proxy::dataset::prepare::run(sunbeam_proxy::dataset::prepare::PrepareDatasetArgs {
                input, owasp, wordlists, output, seed, heuristics, inject_csic, inject_modsec,
            })
        },
        #[cfg(feature = "training")]
        Commands::TrainMlpScanner { dataset, output_dir, hidden_dim, epochs, learning_rate, batch_size, tree_max_depth, tree_min_purity, min_samples_leaf, cookie_weight } => {
            sunbeam_proxy::training::train_scanner::run(sunbeam_proxy::training::train_scanner::TrainScannerMlpArgs {
                dataset_path: dataset, output_dir, hidden_dim, epochs, learning_rate, batch_size, tree_max_depth, tree_min_purity, min_samples_leaf, cookie_weight,
            })
        },
        #[cfg(feature = "training")]
        Commands::TrainMlpDdos { dataset, output_dir, hidden_dim, epochs, learning_rate, batch_size, tree_max_depth, tree_min_purity, min_samples_leaf, cookie_weight } => {
            sunbeam_proxy::training::train_ddos::run(sunbeam_proxy::training::train_ddos::TrainDdosMlpArgs {
                dataset_path: dataset, output_dir, hidden_dim, epochs, learning_rate, batch_size, tree_max_depth, tree_min_purity, min_samples_leaf, cookie_weight,
            })
        },
        #[cfg(feature = "training")]
        Commands::SweepCookieWeight { dataset, detector, weights, tree_max_depth, tree_min_purity, min_samples_leaf } => {
            sunbeam_proxy::training::sweep::run_cookie_sweep(
                &dataset, &detector, weights.as_deref(), tree_max_depth, tree_min_purity, min_samples_leaf,
            )
        },
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
            let detector = Arc::new(sunbeam_proxy::ddos::detector::DDoSDetector::new(ddos_cfg));
            tracing::info!(
                threshold = ddos_cfg.threshold,
                observe_only = ddos_cfg.observe_only,
                "DDoS ensemble detector enabled"
            );
            if ddos_cfg.observe_only {
                tracing::warn!("DDoS detector in OBSERVE-ONLY mode — decisions are logged but traffic is never blocked");
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
            let detector = scanner::detector::ScannerDetector::new(&cfg.routes);
            let handle = Arc::new(arc_swap::ArcSwap::from_pointee(detector));

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
                observe_only = scanner_cfg.observe_only,
                "scanner ensemble detector enabled"
            );
            if scanner_cfg.observe_only {
                tracing::warn!("scanner detector in OBSERVE-ONLY mode — decisions are logged but traffic is never blocked");
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

    let routes = Arc::new(ArcSwap::from_pointee(cfg.routes.clone()));
    let compiled_rewrites = Arc::new(ArcSwap::from_pointee(compiled_rewrites));

    let proxy = SunbeamProxy {
        routes: routes.clone(),
        acme_routes: acme_routes.clone(),
        ddos_detector,
        scanner_detector,
        bot_allowlist,
        rate_limiter,
        compiled_rewrites: compiled_rewrites.clone(),
        http_client,
        pipeline_bypass_cidrs: crate::rate_limit::cidr::parse_cidrs(
            &cfg.rate_limit.as_ref().map(|rl| rl.bypass_cidrs.clone()).unwrap_or_default(),
        ),
        cluster: cluster_handle,
        ddos_observe_only: cfg.ddos.as_ref().map(|d| d.observe_only).unwrap_or(false),
        scanner_observe_only: cfg.scanner.as_ref().map(|s| s.observe_only).unwrap_or(false),
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
