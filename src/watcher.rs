use futures::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::{runtime::watcher, Api, Client};
use tokio::sync::mpsc;

/// Watch `pingora-tls` and `pingora-config` in the ingress namespace.
///
/// On cert change: write new cert bytes from the Apply event directly to the
/// configured paths (avoiding kubelet volume-sync delay), then trigger a
/// graceful upgrade so the new process reads the updated cert immediately.
///
/// On config change: trigger the upgrade immediately; the kubelet usually
/// syncs ConfigMap volumes within ~60s, so the new process reads the updated
/// config shortly after restarting.
///
/// No-ops when no K8s client is available (e.g. ad-hoc local runs outside a
/// cluster) so the binary works in both environments.
pub async fn run_watcher(client: Client, cert_path: String, key_path: String) {
    let (tx, mut rx) = mpsc::channel::<()>(2);

    let secret_api: Api<Secret> = Api::namespaced(client.clone(), "ingress");
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), "ingress");

    tokio::spawn(watch_secret(secret_api, cert_path, key_path, tx.clone()));
    tokio::spawn(watch_configmap(cm_api, tx));

    if rx.recv().await.is_some() {
        tracing::info!("initiating graceful upgrade");
        trigger_upgrade();
    }
}

async fn watch_secret(
    api: Api<Secret>,
    cert_path: String,
    key_path: String,
    tx: mpsc::Sender<()>,
) {
    let cfg = watcher::Config::default().fields("metadata.name=pingora-tls");
    let mut stream = Box::pin(watcher(api, cfg));
    let mut initialized = false;

    while let Some(result) = stream.next().await {
        match result {
            Ok(watcher::Event::InitDone) => {
                initialized = true;
                tracing::debug!("pingora-tls watcher ready");
            }
            // Write the new cert directly from the event object before triggering the
            // upgrade.  The Apply event carries the full updated Secret, so we don't
            // need a separate API call and the cert files are ready before the new
            // process's svc.add_tls() runs.
            Ok(watcher::Event::Apply(secret)) if initialized => {
                tracing::info!("pingora-tls changed — writing new cert");
                match crate::cert::write_from_secret(&secret, &cert_path, &key_path) {
                    Ok(()) => {
                        let _ = tx.send(()).await;
                    }
                    Err(e) => tracing::error!(error = %e, "cert write failed; skipping upgrade"),
                }
                return;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, resource = "pingora-tls", "watcher error; retrying in 10s");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    }
}

async fn watch_configmap(api: Api<ConfigMap>, tx: mpsc::Sender<()>) {
    let cfg = watcher::Config::default().fields("metadata.name=pingora-config");
    let mut stream = Box::pin(watcher(api, cfg));
    let mut initialized = false;

    while let Some(result) = stream.next().await {
        match result {
            Ok(watcher::Event::InitDone) => {
                initialized = true;
                tracing::debug!("pingora-config watcher ready");
            }
            Ok(watcher::Event::Apply(_)) if initialized => {
                tracing::info!("pingora-config changed — triggering upgrade");
                let _ = tx.send(()).await;
                return;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, resource = "pingora-config", "watcher error; retrying in 10s");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    }
}

/// Spawn a new process with `--upgrade`, then send SIGQUIT to self.
///
/// Pingora's SIGQUIT handler transfers all listening socket FDs to the new
/// process via a Unix socket and begins draining existing connections.  The
/// new process calls `Server::new(Some(Opt { upgrade: true }))` in
/// `bootstrap()`, inherits the FDs, and takes over without dropping connections.
fn trigger_upgrade() {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "cannot resolve current exe; upgrade aborted");
            return;
        }
    };

    match std::process::Command::new(&exe).arg("--upgrade").spawn() {
        Ok(child) => tracing::info!(pid = child.id(), "upgrade process spawned"),
        Err(e) => {
            tracing::error!(error = %e, "failed to spawn upgrade process; upgrade aborted");
            return;
        }
    }

    // SAFETY: kill(getpid(), SIGQUIT) is always safe; we're only signalling ourselves.
    unsafe { libc::kill(libc::getpid(), libc::SIGQUIT) };
}
