mod cert;
mod telemetry;
mod watcher;

use sunbeam_proxy::{acme, config};
use sunbeam_proxy::proxy::SunbeamProxy;

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use kube::Client;
use pingora::server::{configuration::Opt, Server};
use pingora_proxy::http_proxy_service;
use std::sync::RwLock;

fn main() -> Result<()> {
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

    // 2. Detect --upgrade flag.  When present, Pingora inherits listening socket
    //    FDs from the upgrade Unix socket instead of binding fresh ports, enabling
    //    zero-downtime cert/config reloads triggered by the K8s watcher below.
    let upgrade = std::env::args().any(|a| a == "--upgrade");

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
                            // Non-fatal: Secret may not exist yet on first deploy (cert-manager
                            // is still issuing), or the Secret name may differ in dev.
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
    };
    let mut svc = http_proxy_service(&server.configuration, proxy);

    // Port 80: always serve plain HTTP (ACME challenges + redirect to HTTPS).
    svc.add_tcp(&cfg.listen.http);

    // Port 443: only add the TLS listener if the cert files exist.
    // On first deploy cert-manager hasn't issued the cert yet, so we start
    // HTTP-only.  Once the pingora-tls Secret is created (ACME challenge
    // completes), the watcher in step 6 writes the cert files and triggers
    // a graceful upgrade.  The upgrade process finds the cert files and adds
    // the TLS listener, inheriting the port-80 socket from the old process.
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
    // Runs on its own OS thread + Tokio runtime — same pattern as the cert/ingress watcher.
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

    // 6. Background K8s watchers on their own OS thread + tokio runtime so they
    //    don't interfere with Pingora's internal runtime.  A fresh Client is
    //    created here so its tower workers live on this runtime (not the
    //    now-dropped temp runtime from step 3).
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
