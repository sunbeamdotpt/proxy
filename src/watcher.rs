// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use futures::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::{runtime::watcher, Api, Client};
use tokio::sync::mpsc;

/// Watch the TLS Secret and config ConfigMap for changes.
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
pub async fn run_watcher(
    client: Client,
    namespace: String,
    tls_secret: String,
    config_configmap: String,
    cert_path: String,
    key_path: String,
) {
    let (tx, mut rx) = mpsc::channel::<()>(2);

    let secret_api: Api<Secret> = Api::namespaced(client.clone(), &namespace);
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);

    tokio::spawn(watch_secret(
        secret_api,
        tls_secret,
        cert_path,
        key_path,
        tx.clone(),
    ));
    tokio::spawn(watch_configmap(cm_api, config_configmap, tx));

    if rx.recv().await.is_some() {
        tracing::info!("initiating graceful upgrade");
        trigger_upgrade();
    }
}

async fn watch_secret(
    api: Api<Secret>,
    secret_name: String,
    cert_path: String,
    key_path: String,
    tx: mpsc::Sender<()>,
) {
    let field_selector = format!("metadata.name={secret_name}");
    let cfg = watcher::Config::default().fields(&field_selector);
    let mut stream = Box::pin(watcher(api, cfg));
    let mut initialized = false;

    while let Some(result) = stream.next().await {
        match result {
            Ok(watcher::Event::InitDone) => {
                initialized = true;
                tracing::debug!(%secret_name, "TLS secret watcher ready");
            }
            Ok(watcher::Event::Apply(secret)) if initialized => {
                tracing::info!(%secret_name, "TLS secret changed — writing new cert");
                match sunbeam_proxy::cert::write_from_secret(&secret, &cert_path, &key_path) {
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

async fn watch_configmap(api: Api<ConfigMap>, configmap_name: String, tx: mpsc::Sender<()>) {
    let field_selector = format!("metadata.name={configmap_name}");
    let cfg = watcher::Config::default().fields(&field_selector);
    let mut stream = Box::pin(watcher(api, cfg));
    let mut initialized = false;

    while let Some(result) = stream.next().await {
        match result {
            Ok(watcher::Event::InitDone) => {
                initialized = true;
                tracing::debug!(%configmap_name, "config watcher ready");
            }
            Ok(watcher::Event::Apply(_)) if initialized => {
                tracing::info!(%configmap_name, "config changed — triggering upgrade");
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

fn trigger_upgrade() {
    sunbeam_proxy::upgrade::trigger_upgrade();
}
