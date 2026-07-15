// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

mod watcher;

use sunbeam_proxy::proxy::SunbeamProxy;
use sunbeam_proxy::rate_limit;
use sunbeam_proxy::scanner;
use sunbeam_proxy::telemetry;
use sunbeam_proxy::tls::{
    CertSource, CertStore, DiskCertSource, GatewayCertSource, TlsRegistry, merge_cert_store,
};
use sunbeam_proxy::{acme, config, ir};

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use clap::{Parser, Subcommand};
use kube::Client;
use pingora::server::{Server, configuration::Opt};
use pingora_core::apps::HttpServerOptions;
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

        /// Path to a Caddyfile to load as a route source. Takes precedence over
        /// TOML [[routes]] but is overridden by Gateway API resources.
        #[arg(long, env = "SUNBEAM_CADDYFILE")]
        caddyfile: Option<String>,

        /// Directory containing Caddyfiles (`Caddyfile` or `*.caddyfile`) to
        /// load as route sources. Merged alphabetically; later files win for
        /// the same hostname.
        #[arg(long, env = "SUNBEAM_CADDYFILE_DIR")]
        caddyfile_dir: Option<String>,
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
    match cli.command.unwrap_or(Commands::Serve {
        upgrade: false,
        caddyfile: None,
        caddyfile_dir: None,
    }) {
        Commands::Serve {
            upgrade,
            caddyfile,
            caddyfile_dir,
        } => run_serve(upgrade, caddyfile.as_deref(), caddyfile_dir.as_deref()),
        Commands::Replay {
            input,
            window_secs,
            min_events,
        } => sunbeam_proxy::ensemble::replay::run(
            sunbeam_proxy::ensemble::replay::ReplayEnsembleArgs {
                input,
                window_secs,
                min_events,
            },
        ),
        Commands::DownloadDatasets => sunbeam_proxy::dataset::download::download_all(),
        Commands::PrepareDataset {
            input,
            owasp,
            wordlists,
            output,
            seed,
            heuristics,
            inject_csic,
            inject_modsec,
        } => sunbeam_proxy::dataset::prepare::run(
            sunbeam_proxy::dataset::prepare::PrepareDatasetArgs {
                input,
                owasp,
                wordlists,
                output,
                seed,
                heuristics,
                inject_csic,
                inject_modsec,
            },
        ),
        #[cfg(feature = "training")]
        Commands::TrainMlpScanner {
            dataset,
            output_dir,
            hidden_dim,
            epochs,
            learning_rate,
            batch_size,
            tree_max_depth,
            tree_min_purity,
            min_samples_leaf,
            cookie_weight,
        } => sunbeam_proxy::training::train_scanner::run(
            sunbeam_proxy::training::train_scanner::TrainScannerMlpArgs {
                dataset_path: dataset,
                output_dir,
                hidden_dim,
                epochs,
                learning_rate,
                batch_size,
                tree_max_depth,
                tree_min_purity,
                min_samples_leaf,
                cookie_weight,
            },
        ),
        #[cfg(feature = "training")]
        Commands::TrainMlpDdos {
            dataset,
            output_dir,
            hidden_dim,
            epochs,
            learning_rate,
            batch_size,
            tree_max_depth,
            tree_min_purity,
            min_samples_leaf,
            cookie_weight,
        } => sunbeam_proxy::training::train_ddos::run(
            sunbeam_proxy::training::train_ddos::TrainDdosMlpArgs {
                dataset_path: dataset,
                output_dir,
                hidden_dim,
                epochs,
                learning_rate,
                batch_size,
                tree_max_depth,
                tree_min_purity,
                min_samples_leaf,
                cookie_weight,
            },
        ),
        #[cfg(feature = "training")]
        Commands::SweepCookieWeight {
            dataset,
            detector,
            weights,
            tree_max_depth,
            tree_min_purity,
            min_samples_leaf,
        } => sunbeam_proxy::training::sweep::run_cookie_sweep(
            &dataset,
            &detector,
            weights.as_deref(),
            tree_max_depth,
            tree_min_purity,
            min_samples_leaf,
        ),
    }
}

fn run_serve(upgrade: bool, caddyfile: Option<&str>, caddyfile_dir: Option<&str>) -> Result<()> {
    // Install the aws-lc-rs crypto provider for rustls before any TLS init.
    // Required because rustls 0.23 no longer auto-selects a provider at compile time.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("crypto provider already installed");

    let config_path =
        std::env::var("SUNBEAM_CONFIG").unwrap_or_else(|_| "/etc/pingora/config.toml".to_string());
    let cfg = config::Config::load(&config_path)?;

    // Reserve ports used by internal services so Gateway API listeners cannot
    // claim them. If a Gateway listener references a reserved port, its
    // Accepted condition is set to False with reason PortUnavailable.
    let mut reserved_ports = std::collections::HashSet::new();
    if cfg.telemetry.metrics_port > 0 {
        reserved_ports.insert(cfg.telemetry.metrics_port);
    }
    sunbeam_proxy::gateway::reconcile::listener_common::set_reserved_ports(reserved_ports);

    if !cfg.routes.is_empty() {
        return Err(anyhow::anyhow!(
            "config.toml [[routes]] has been removed; migrate routes to a Caddyfile \
             (see --caddyfile / SUNBEAM_CADDYFILE)"
        ));
    }

    // 1. Init telemetry (JSON logs + optional OTEL traces). The guard must
    // outlive the server so the tracer provider is never shut down early.
    let _otel_guard = telemetry::init(&cfg.telemetry.otlp_endpoint);

    // Shared Tokio runtime for all application async work. Pingora still manages
    // its own runtime internally via server.run_forever().
    let runtime = tokio::runtime::Runtime::new().expect("shared tokio runtime");
    let rt_handle = runtime.handle().clone();

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
                tracing::warn!(
                    "DDoS detector in OBSERVE-ONLY mode — decisions are logged but traffic is never blocked"
                );
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
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(interval));
                    evict_limiter.evict_stale();
                }
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
                tracing::info!(rules = scanner_cfg.allowlist.len(), "bot allowlist enabled");
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
                tracing::warn!(
                    "scanner detector in OBSERVE-ONLY mode — decisions are logged but traffic is never blocked"
                );
            }
            (Some(handle), bot_allowlist)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    // 3. Fetch the TLS cert from K8s before Pingora binds the TLS port.
    //    The Client is created and dropped within the shared runtime — we do NOT
    //    carry it across runtime boundaries, which would kill its tower workers.
    //    The watcher task creates its own fresh Client on the same runtime.
    let k8s_available = runtime.block_on(async {
        match Client::try_default().await {
            Ok(c) => {
                if !upgrade
                    && let Err(e) = sunbeam_proxy::cert::fetch_and_write(
                        &c,
                        &cfg.kubernetes.namespace,
                        &cfg.kubernetes.tls_secret,
                        &cfg.tls.cert_path,
                        &cfg.tls.key_path,
                    ).await
                {
                    tracing::warn!(error = %e, "cert fetch from K8s failed; using existing files");
                }
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "no K8s client; cert auto-reload and ACME routing disabled");
                false
            }
        }
    });

    let gateway_enabled = cfg.gateway.enabled;

    // 3b. Central TLS certificate registry.  L4 listeners terminate TLS here,
    //     and the registry is hot-swapped by RouteManager updates.
    let tls_registry = Arc::new(TlsRegistry::new());
    let disk_cert_source = Arc::new(DiskCertSource::new(
        Arc::from(cfg.tls.cert_path.as_str()),
        Arc::from(cfg.tls.key_path.as_str()),
    ));
    let gateway_cert_source = Arc::new(GatewayCertSource::new());
    tls_registry.apply(merge_cert_sources(
        disk_cert_source.snapshot(),
        gateway_cert_source.snapshot(),
    ));

    // Pingora runs as a plaintext HTTP proxy on a loopback address.
    // The L4 manager owns the public HTTPS socket and forwards decrypted
    // traffic here.
    let pingora_http_addr = "127.0.0.1:10443";

    // 2d. Spawn cluster gossip if configured.
    let cluster_handle = if let Some(cc) = &cfg.cluster {
        if cc.enabled {
            match sunbeam_proxy::cluster::spawn_cluster(&rt_handle, cc) {
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

    let (route_manager, routes_tx) = sunbeam_proxy::route_manager::RouteManager::spawn(10);
    sunbeam_proxy::l4::current::set(route_manager.l4_config());

    // Source precedence: Gateway API > Caddyfile > legacy TOML.
    route_manager.set_priority("gateway-api", 100);
    route_manager.set_priority("caddyfile", 50);
    route_manager.set_priority("toml", 0);

    // Load Caddyfile route source(s) if provided.
    let caddyfile_table = match (caddyfile, caddyfile_dir) {
        (Some(path), _) => Some(sunbeam_proxy::caddyfile::parse_file(path.as_ref())),
        (None, Some(dir)) => Some(sunbeam_proxy::caddyfile::parse_dir(dir.as_ref())),
        (None, None) => None,
    };
    if let Some(table) = caddyfile_table {
        let table = table.map_err(|e| anyhow::anyhow!("failed to load Caddyfile: {e}"))?;
        route_manager
            .apply("caddyfile", table)
            .map_err(|e| anyhow::anyhow!("failed to compile Caddyfile routes: {e}"))?;
    }

    let mut startup_ir = ir::from_config::from_route_configs(&cfg.routes);
    if !cfg.listen.https.is_empty() {
        let https_listener_id: Arc<str> = Arc::from("https");
        let tls = if std::path::Path::new(&cfg.tls.cert_path).exists() {
            Some(ir::TlsConfig::Files {
                cert_path: Arc::from(cfg.tls.cert_path.as_str()),
                key_path: Arc::from(cfg.tls.key_path.as_str()),
            })
        } else {
            Some(ir::TlsConfig::Registry {
                cert_id: Arc::from("default"),
            })
        };
        startup_ir.listeners.push(ir::ListenerConfig {
            id: Arc::clone(&https_listener_id),
            bind_addr: Arc::from(cfg.listen.https.as_str()),
            protocol: ir::Protocol::Https,
            tls,
            redirect_http_to_https: false,
            frontend_validation: None,
        });
        // Terminate TLS for all traffic on the public HTTPS listener and
        // forward the decrypted plaintext HTTP to Pingora.  Pingora still
        // performs host-level routing.
        // In Gateway API mode each HTTPS listener supplies its own SNI-specific
        // L4 route. A global catch-all here would terminate TLS for hostnames
        // whose Gateway listener is invalid or unprogrammed (e.g. broken frontend
        // client-certificate config) and make conformance tests expect failure.
        if !gateway_enabled {
            startup_ir.l4_routes.push(ir::L4Route {
                listener_id: Arc::clone(&https_listener_id),
                listener_hostname: ir::HostnameMatch::Any,
                match_: ir::L4Match::Any,
                action: ir::L4Action::TerminateAndHttp(Arc::from(pingora_http_addr)),
            });
        }
    }
    if let Err(e) = route_manager.apply("toml", startup_ir) {
        return Err(anyhow::anyhow!("failed to compile startup routes: {e}"));
    }

    // 3c. Start metrics + health HTTP server early so readiness probes pass
    // while Gateway API resources are being reconciled.
    if metrics_port > 0 {
        rt_handle.spawn(async move {
            sunbeam_proxy::metrics::spawn_metrics_server(metrics_port);
        });
    }

    // 3d. Start the Gateway API reconciler before Pingora boots so that
    // Gateway API routes and TLS certificates are reconciled as early as
    // possible.
    if k8s_available && gateway_enabled {
        let gateway_ns = cfg.kubernetes.namespace.clone();
        let cluster_for_reconcile = cluster_handle.clone();
        let tls_registry_for_reconcile = Arc::clone(&tls_registry);
        rt_handle.spawn(async move {
            let client = match Client::try_default().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "gateway: failed to create K8s client; reconciler disabled");
                    return;
                }
            };
            let election = sunbeam_proxy::gateway::election::Election::new(
                client.clone(),
                gateway_ns,
                "sunbeam-proxy-gateway".to_string(),
                std::env::var("HOSTNAME").unwrap_or_else(|_| "sunbeam-proxy".to_string()),
            );
            sunbeam_proxy::gateway::reconcile::run_reconcile_loop(
                election,
                client,
                routes_tx.clone(),
                cluster_for_reconcile,
                Arc::clone(&tls_registry_for_reconcile),
                Arc::clone(&gateway_cert_source),
                Arc::clone(&disk_cert_source),
            ).await;
        });
    }

    // Pingora now runs as a plaintext HTTP proxy on a loopback address.
    // The L4 manager owns the public HTTPS socket and forwards decrypted
    // traffic here.

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

    // 4b. Spawn the L4 socket manager and wire it to RouteManager updates.
    let l4_config = route_manager.l4_config();
    let sni_context: Arc<
        std::sync::Mutex<std::collections::HashMap<std::net::SocketAddr, Arc<str>>>,
    > = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let http_context: Arc<
        std::sync::Mutex<
            std::collections::HashMap<
                std::net::SocketAddr,
                sunbeam_proxy::l4::context::HttpRelayContext,
            >,
        >,
    > = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let l4_router = Arc::new(sunbeam_proxy::l4::router::Router::new_with_http_context(
        Arc::clone(&l4_config),
        Arc::clone(&tls_registry),
        Arc::clone(&sni_context),
        Arc::clone(&http_context),
    ));
    let l4_manager = sunbeam_proxy::l4::manager::spawn_with_config(
        rt_handle.clone(),
        Arc::clone(&tls_registry),
        l4_router,
        Arc::clone(&l4_config),
    );
    l4_manager.apply(l4_config.load_full());

    let l4_manager_for_updates = l4_manager.clone();
    let l4_config_for_updates = route_manager.l4_config();
    let l4_changed = route_manager.l4_changed();
    std::thread::spawn(move || {
        let mut last = l4_config_for_updates.load_full();
        loop {
            {
                let (lock, cvar) = &*l4_changed;
                let mut guard = lock.lock().unwrap();
                if !*guard {
                    guard = cvar
                        .wait_timeout(guard, std::time::Duration::from_secs(1))
                        .unwrap()
                        .0;
                }
                *guard = false;
            }
            let current = l4_config_for_updates.load_full();
            if !Arc::ptr_eq(&last, &current) {
                l4_manager_for_updates.apply(current.clone());
                last = current;
            }
        }
    });
    let routes = route_manager.current();
    let compiled_rewrites = route_manager.rewrites();
    let http_client = reqwest::Client::new();

    let proxy = SunbeamProxy {
        routes: routes.clone(),
        l4_config: route_manager.l4_config(),
        acme_routes: acme_routes.clone(),
        ddos_detector,
        scanner_detector,
        bot_allowlist,
        rate_limiter,
        compiled_rewrites: compiled_rewrites.clone(),
        http_client,
        pipeline_bypass_cidrs: crate::rate_limit::cidr::parse_cidrs(
            &cfg.rate_limit
                .as_ref()
                .map(|rl| rl.bypass_cidrs.clone())
                .unwrap_or_default(),
        ),
        trusted_proxy_cidrs: crate::rate_limit::cidr::parse_cidrs(&cfg.trusted_proxy_cidrs),
        x_forwarded_for: cfg.x_forwarded_for,
        cluster: cluster_handle.clone(),
        ddos_observe_only: cfg.ddos.as_ref().map(|d| d.observe_only).unwrap_or(false),
        scanner_observe_only: cfg
            .scanner
            .as_ref()
            .map(|s| s.observe_only)
            .unwrap_or(false),
        sni_context,
        http_context,
        tls_registry: Some(Arc::clone(&tls_registry)),
    };
    let mut svc = http_proxy_service(&server.configuration, proxy);
    if let Some(app) = svc.app_logic_mut() {
        let mut server_options = HttpServerOptions::default();
        server_options.h2c = true;
        app.server_options = Some(server_options);
    }

    // When Gateway API is enabled, plain HTTP listeners are bound dynamically
    // by the L4 manager so arbitrary Gateway ports can be served. Otherwise
    // fall back to the static listen.http / extra_http configuration.
    let gateway_enabled = cfg.gateway.enabled;
    if !gateway_enabled {
        svc.add_tcp(&cfg.listen.http);
        for addr in &cfg.listen.extra_http {
            svc.add_tcp(addr);
            tracing::info!(%addr, "extra HTTP listener added");
        }
    }

    // Pingora runs plaintext HTTP on a loopback address.  The L4 manager owns
    // the public HTTPS socket and forwards decrypted traffic here.
    svc.add_tcp(pingora_http_addr);
    tracing::info!(addr = %pingora_http_addr, "Pingora plaintext HTTP listener added");

    server.add_service(svc);

    // 5c. SSH TCP passthrough (port 22 → Gitea SSH), if configured.
    if let Some(ssh_cfg) = &cfg.ssh {
        let listen = ssh_cfg.listen.clone();
        let backend = ssh_cfg.backend.clone();
        tracing::info!(%listen, %backend, "SSH TCP proxy enabled");
        rt_handle.spawn(async move {
            sunbeam_proxy::ssh::run_tcp_proxy(&listen, &backend).await;
        });
    }

    // 6. Background K8s watchers as tasks on the shared runtime.
    if k8s_available {
        let k8s_cfg = cfg.kubernetes.clone();
        let cert_path = cfg.tls.cert_path.clone();
        let key_path = cfg.tls.key_path.clone();

        rt_handle.spawn(async move {
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
    }

    tracing::info!(upgrade, "sunbeam-proxy starting");
    server.run_forever();
}

/// Merge disk and Gateway API certificate snapshots into a single store.
fn merge_cert_sources(disk: Option<Arc<CertStore>>, gateway: Option<Arc<CertStore>>) -> CertStore {
    let mut store = disk.map(|s| (*s).clone()).unwrap_or_default();
    if let Some(gw) = gateway {
        merge_cert_store(&mut store, &gw);
    }
    store
}
