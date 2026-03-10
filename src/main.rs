mod cert;
mod telemetry;
mod watcher;

use sunbeam_proxy::{acme, config};
use sunbeam_proxy::proxy::SunbeamProxy;
use sunbeam_proxy::ddos;
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
    /// Replay audit logs through the DDoS detector and rate limiter
    Replay {
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
    /// Train a DDoS detection model from audit logs
    Train {
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
        k: usize,
        /// Attack threshold (fraction of k neighbors)
        #[arg(long, default_value = "0.6")]
        threshold: f64,
        /// Sliding window size in seconds
        #[arg(long, default_value = "60")]
        window_secs: u64,
        /// Minimum events per IP to include in training
        #[arg(long, default_value = "10")]
        min_events: usize,
    },
    /// Train a per-request scanner detection model from audit logs
    TrainScanner {
        /// Path to audit log JSONL file
        #[arg(short, long)]
        input: String,
        /// Output model file path
        #[arg(short, long, default_value = "scanner_model.bin")]
        output: String,
        /// Directory (or file) containing .txt wordlists of scanner paths
        #[arg(long)]
        wordlists: Option<String>,
        /// Classification threshold
        #[arg(long, default_value = "0.5")]
        threshold: f64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Serve { upgrade: false }) {
        Commands::Serve { upgrade } => run_serve(upgrade),
        Commands::Replay {
            input,
            model,
            config,
            k,
            threshold,
            window_secs,
            min_events,
            rate_limit,
        } => ddos::replay::run(ddos::replay::ReplayArgs {
            input,
            model_path: model,
            config_path: config,
            k,
            threshold,
            window_secs,
            min_events,
            rate_limit,
        }),
        Commands::Train {
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
        } => scanner::train::run(scanner::train::TrainScannerArgs {
            input,
            output,
            wordlists,
            threshold,
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

    // 2. Load DDoS detection model if configured.
    let ddos_detector = if let Some(ddos_cfg) = &cfg.ddos {
        if ddos_cfg.enabled {
            match ddos::model::TrainedModel::load(
                std::path::Path::new(&ddos_cfg.model_path),
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

    // 2c. Load scanner model if configured.
    let (scanner_detector, bot_allowlist) = if let Some(scanner_cfg) = &cfg.scanner {
        if scanner_cfg.enabled {
            match scanner::model::ScannerModel::load(std::path::Path::new(&scanner_cfg.model_path)) {
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
                        let model_path = std::path::PathBuf::from(&scanner_cfg.model_path);
                        let threshold = scanner_cfg.threshold;
                        let routes = cfg.routes.clone();
                        let interval = std::time::Duration::from_secs(scanner_cfg.poll_interval_secs);
                        std::thread::spawn(move || {
                            scanner::watcher::watch_scanner_model(
                                watcher_handle, model_path, threshold, routes, interval,
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
                            cert::fetch_and_write(&c, &cfg.tls.cert_path, &cfg.tls.key_path).await
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

    let proxy = SunbeamProxy {
        routes: cfg.routes.clone(),
        acme_routes: acme_routes.clone(),
        ddos_detector,
        scanner_detector,
        bot_allowlist,
        rate_limiter,
    };
    let mut svc = http_proxy_service(&server.configuration, proxy);

    // Port 80: always serve plain HTTP (ACME challenges + redirect to HTTPS).
    svc.add_tcp(&cfg.listen.http);

    // Port 443: only add the TLS listener if the cert files exist.
    let cert_exists = std::path::Path::new(&cfg.tls.cert_path).exists();
    if cert_exists {
        svc.add_tls(&cfg.listen.https, &cfg.tls.cert_path, &cfg.tls.key_path)?;
        tracing::info!("TLS listener added on {}", cfg.listen.https);
    } else {
        tracing::warn!(
            cert_path = %cfg.tls.cert_path,
            "cert not found — starting HTTP-only; ACME challenge will complete and trigger upgrade"
        );
    }

    server.add_service(svc);

    // 5b. SSH TCP passthrough (port 22 → Gitea SSH), if configured.
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

    // 6. Background K8s watchers on their own OS thread + tokio runtime.
    if k8s_available {
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
                    acme::watch_ingresses(client.clone(), acme_routes),
                    watcher::run_watcher(client, cert_path, key_path),
                );
            });
        });
    }

    tracing::info!(upgrade, "sunbeam-proxy starting");
    server.run_forever();
}
