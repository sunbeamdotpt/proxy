// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use futures::StreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::{runtime::watcher, Api, Client};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// Maps a challenge path to the backend address that can answer it.
///
/// Key:   `/.well-known/acme-challenge/<token>`
/// Value: `cm-acme-http-solver-<hash>.<namespace>.svc.cluster.local:8089`
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

/// Watch Ingress objects and maintain `routes`.
///
/// cert-manager creates an Ingress for each HTTP-01 challenge it manages.
/// The Ingress contains a path rule for `/.well-known/acme-challenge/<token>`
/// pointing to a per-challenge solver Service.  We populate the route table
/// from these rules so the proxy can forward each challenge token to the
/// correct solver pod without the nondeterminism of a shared stable Service.
pub async fn watch_ingresses(client: Client, namespace: String, routes: AcmeRoutes) {
    let api: Api<Ingress> = Api::namespaced(client, &namespace);

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
            Ok(watcher::Event::InitApply(ing)) | Ok(watcher::Event::Apply(ing)) => {
                let mut map = routes.write().unwrap_or_else(|e| e.into_inner());
                upsert_routes(&ing, &namespace, &mut map);
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

fn upsert_routes(ingress: &Ingress, namespace: &str, map: &mut HashMap<String, String>) {
    let Some(spec) = &ingress.spec else { return };
    for rule in spec.rules.as_deref().unwrap_or(&[]) {
        let Some(http) = &rule.http else { continue };
        for p in &http.paths {
            let Some(path) = p.path.as_deref() else {
                continue;
            };
            if !path.starts_with("/.well-known/acme-challenge/") {
                continue;
            }
            let Some(svc) = p.backend.service.as_ref() else {
                continue;
            };
            let Some(port) = svc.port.as_ref().and_then(|p| p.number) else {
                continue;
            };
            let backend = format!("{}.{namespace}.svc.cluster.local:{port}", svc.name);
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
            let Some(path) = p.path.as_deref() else {
                continue;
            };
            if path.starts_with("/.well-known/acme-challenge/") {
                tracing::debug!(path, "removed ACME challenge route");
                map.remove(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, IngressBackend, IngressRule, IngressServiceBackend, IngressSpec,
        ServiceBackendPort,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_ingress(path: &str, svc: &str, port: i32) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                namespace: Some("cert-manager".to_string()),
                name: Some("challenge".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                rules: Some(vec![IngressRule {
                    host: None,
                    http: Some(k8s_openapi::api::networking::v1::HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some(path.to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: svc.to_string(),
                                    port: Some(ServiceBackendPort {
                                        name: None,
                                        number: Some(port),
                                    }),
                                }),
                                ..Default::default()
                            },
                        }],
                    }),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn upsert_adds_acme_challenge_route() {
        let mut map = HashMap::new();
        let ing = make_ingress("/.well-known/acme-challenge/token", "solver", 8089);
        upsert_routes(&ing, "ns", &mut map);
        assert_eq!(
            map.get("/.well-known/acme-challenge/token"),
            Some(&"solver.ns.svc.cluster.local:8089".to_string())
        );
    }

    #[test]
    fn upsert_ignores_non_acme_paths() {
        let mut map = HashMap::new();
        let ing = make_ingress("/healthz", "solver", 8089);
        upsert_routes(&ing, "ns", &mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn upsert_requires_service_port() {
        let mut map = HashMap::new();
        let mut ing = make_ingress("/.well-known/acme-challenge/token", "solver", 8089);
        ing.spec.as_mut().unwrap().rules.as_mut().unwrap()[0]
            .http
            .as_mut()
            .unwrap()
            .paths[0]
            .backend
            .service
            .as_mut()
            .unwrap()
            .port = None;
        upsert_routes(&ing, "ns", &mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn remove_deletes_acme_route() {
        let mut map = HashMap::new();
        let ing = make_ingress("/.well-known/acme-challenge/token", "solver", 8089);
        upsert_routes(&ing, "ns", &mut map);
        remove_routes(&ing, &mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn upsert_ignores_ingress_without_spec() {
        let mut map = HashMap::new();
        let ing = Ingress {
            spec: None,
            ..Default::default()
        };
        upsert_routes(&ing, "ns", &mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn upsert_ignores_rule_without_http() {
        let mut map = HashMap::new();
        let ing = Ingress {
            spec: Some(IngressSpec {
                rules: Some(vec![IngressRule {
                    host: None,
                    http: None,
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        upsert_routes(&ing, "ns", &mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn upsert_ignores_path_without_service() {
        let mut map = HashMap::new();
        let ing = Ingress {
            spec: Some(IngressSpec {
                rules: Some(vec![IngressRule {
                    host: None,
                    http: Some(k8s_openapi::api::networking::v1::HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some("/.well-known/acme-challenge/token".to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: None,
                                ..Default::default()
                            },
                        }],
                    }),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        upsert_routes(&ing, "ns", &mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn remove_ignores_ingress_without_spec() {
        let mut map = HashMap::new();
        map.insert(
            "/.well-known/acme-challenge/token".to_string(),
            "backend".to_string(),
        );
        let ing = Ingress {
            spec: None,
            ..Default::default()
        };
        remove_routes(&ing, &mut map);
        assert!(!map.is_empty());
    }

    #[test]
    fn remove_ignores_non_acme_paths() {
        let mut map = HashMap::new();
        map.insert(
            "/.well-known/acme-challenge/token".to_string(),
            "backend".to_string(),
        );
        let ing = make_ingress("/healthz", "solver", 8089);
        remove_routes(&ing, &mut map);
        assert!(!map.is_empty());
    }
}
