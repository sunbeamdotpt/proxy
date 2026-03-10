use futures::StreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{runtime::watcher, Api, Client};
use std::{collections::HashMap, sync::{Arc, RwLock}};

/// Maps a challenge path to the backend address that can answer it.
///
/// Key:   `/.well-known/acme-challenge/<token>`
/// Value: `cm-acme-http-solver-<hash>.ingress.svc.cluster.local:8089`
///
/// cert-manager creates one Ingress per challenge domain with exactly this
/// path and backend.  Our proxy consults this table to route each challenge
/// request to the specific solver pod that holds the matching token, which
/// is required for multi-SAN certificates (one solver pod per domain, all
/// running concurrently).
///
/// Uses std::sync::RwLock (not tokio) so reads are wait-free and the table
/// can be written from the watcher runtime without cross-runtime waker issues.
pub type AcmeRoutes = Arc<RwLock<HashMap<String, String>>>;

/// Watch Ingress objects in the ingress namespace and maintain `routes`.
///
/// cert-manager creates an Ingress for each HTTP-01 challenge it manages.
/// The Ingress contains a path rule for `/.well-known/acme-challenge/<token>`
/// pointing to a per-challenge solver Service.  We populate the route table
/// from these rules so the proxy can forward each challenge token to the
/// correct solver pod without the nondeterminism of a shared stable Service.
pub async fn watch_ingresses(client: Client, routes: AcmeRoutes) {
    let api: Api<Ingress> = Api::namespaced(client, "ingress");

    // Verify Ingress API access before entering the watch loop. A failure here
    // almost always means cert-manager is not installed or RBAC is wrong.
    if let Err(e) = api.list(&Default::default()).await {
        tracing::error!(
            error = %e,
            "initial Ingress list failed — is cert-manager installed? \
             is the pingora-watcher Role bound correctly?"
        );
        // Continue into the watch loop; it will surface further errors.
    }

    let mut stream = Box::pin(watcher(api, watcher::Config::default()));

    while let Some(result) = stream.next().await {
        match result {
            // InitApply fires for each Ingress during the initial list (kube v3+).
            // Apply fires for subsequent creates/updates.
            // Both must be handled to catch Ingresses that existed before the proxy started.
            Ok(watcher::Event::InitApply(ing)) | Ok(watcher::Event::Apply(ing)) => {
                let mut map = routes.write().unwrap_or_else(|e| e.into_inner());
                upsert_routes(&ing, &mut map);
            }
            Ok(watcher::Event::Delete(ing)) => {
                let mut map = routes.write().unwrap_or_else(|e| e.into_inner());
                remove_routes(&ing, &mut map);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "Ingress watcher error; retrying in 10s");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    }
}

fn upsert_routes(ingress: &Ingress, map: &mut HashMap<String, String>) {
    let Some(spec) = &ingress.spec else { return };
    for rule in spec.rules.as_deref().unwrap_or(&[]) {
        let Some(http) = &rule.http else { continue };
        for p in &http.paths {
            let Some(path) = p.path.as_deref() else { continue };
            if !path.starts_with("/.well-known/acme-challenge/") {
                continue;
            }
            let Some(svc) = p.backend.service.as_ref() else { continue };
            let Some(port) = svc.port.as_ref().and_then(|p| p.number) else { continue };
            let backend = format!(
                "{}.ingress.svc.cluster.local:{port}",
                svc.name
            );
            tracing::debug!(path, %backend, "added ACME challenge route");
            map.insert(path.to_string(), backend);
        }
    }
}

fn remove_routes(ingress: &Ingress, map: &mut HashMap<String, String>) {
    let Some(spec) = &ingress.spec else { return };
    for rule in spec.rules.as_deref().unwrap_or(&[]) {
        let Some(http) = &rule.http else { continue };
        for p in &http.paths {
            let Some(path) = p.path.as_deref() else { continue };
            if path.starts_with("/.well-known/acme-challenge/") {
                tracing::debug!(path, "removed ACME challenge route");
                map.remove(path);
            }
        }
    }
}
