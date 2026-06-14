// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fetch TLS certificates referenced by Gateway HTTPS listeners and write
//! them to disk so that Pingora can load them on the next graceful upgrade.

use crate::gateway::api::Gateway;
use crate::gateway::model::GatewayView;
use crate::gateway::reconcile::refgrant::GrantIndex;
use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;

/// Scan `view` for the first Gateway HTTPS listener with a valid
/// `certificateRefs` pointing to a core `Secret`, fetch that Secret, and
/// write `tls.crt` / `tls.key` to `cert_path` / `key_path`.
///
/// Returns `true` when the files were actually changed (so the caller can
/// trigger a graceful upgrade).
pub async fn maybe_write_gateway_certs(
    client: &kube::Client,
    view: &GatewayView,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<bool> {
    let grant_index = GrantIndex::new(view.reference_grants.clone());

    for gw_state in &view.gateways {
        let gateways_api: Api<Gateway> = Api::namespaced(client.clone(), &gw_state.namespace);
        let gw = match gateways_api.get(&gw_state.name).await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(name = %gw_state.name, error = %e, "failed to fetch Gateway for cert lookup");
                continue;
            }
        };

        for listener in &gw.spec.listeners {
            let obj = match listener.as_object() {
                Some(o) => o,
                None => continue,
            };

            let protocol = obj
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("HTTP");
            if protocol != "HTTPS" {
                continue;
            }

            let tls = match obj.get("tls") {
                Some(t) => t,
                None => continue,
            };
            let tls_obj = match tls.as_object() {
                Some(o) => o,
                None => continue,
            };
            let cert_refs = match tls_obj.get("certificateRefs") {
                Some(r) => r,
                None => continue,
            };
            let refs = match cert_refs.as_array() {
                Some(a) => a,
                None => continue,
            };

            for cert_ref in refs {
                let cert_obj = match cert_ref.as_object() {
                    Some(o) => o,
                    None => continue,
                };
                let kind = cert_obj.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let group = cert_obj.get("group").and_then(|v| v.as_str()).unwrap_or("");
                if kind != "Secret" || !group.is_empty() {
                    continue;
                }
                let secret_name = match cert_obj.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n,
                    None => continue,
                };
                let secret_ns = cert_obj
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&gw_state.namespace);

                if secret_ns != gw_state.namespace.as_ref()
                    && !grant_index.is_permitted(
                        &gw_state.namespace,
                        "gateway.networking.k8s.io",
                        "Gateway",
                        secret_ns,
                        "",
                        "Secret",
                        secret_name,
                    )
                {
                    tracing::warn!(
                        gateway = %gw_state.name,
                        namespace = %gw_state.namespace,
                        listener = %obj.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                        %secret_name,
                        %secret_ns,
                        "cross-namespace Gateway certificateRef denied by ReferenceGrant"
                    );
                    continue;
                }

                let secret_api: Api<Secret> = Api::namespaced(client.clone(), secret_ns);
                let secret = match secret_api.get(secret_name).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(%secret_name, %secret_ns, error = %e, "Gateway cert Secret not found yet");
                        continue;
                    }
                };

                let data = secret
                    .data
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("TLS Secret has no data"))?;
                let new_crt = data
                    .get("tls.crt")
                    .ok_or_else(|| anyhow::anyhow!("TLS Secret missing tls.crt"))?;
                let new_key = data
                    .get("tls.key")
                    .ok_or_else(|| anyhow::anyhow!("TLS Secret missing tls.key"))?;

                let changed = {
                    let old_crt = std::fs::read(cert_path).unwrap_or_default();
                    let old_key = std::fs::read(key_path).unwrap_or_default();
                    old_crt != new_crt.0 || old_key != new_key.0
                };

                if !changed {
                    return Ok(false);
                }

                return match crate::cert::write_from_secret(&secret, cert_path, key_path) {
                    Ok(()) => {
                        tracing::info!(%secret_name, %secret_ns, %cert_path, "wrote Gateway TLS cert");
                        Ok(true)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to write Gateway TLS cert");
                        Err(e)
                    }
                };
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::{GatewayState, ListenerState, ReconciledView};
    use std::sync::Arc;

    fn b64(input: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let buf = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            out.push(TABLE[(buf[0] >> 2) as usize] as char);
            out.push(TABLE[(((buf[0] & 0x03) << 4) | (buf[1] >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                TABLE[(((buf[1] & 0x0f) << 2) | (buf[2] >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[(buf[2] & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    fn test_dir() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::TempDir::new().unwrap();
        let cert_path = dir.path().join("tls.crt").to_string_lossy().to_string();
        let key_path = dir.path().join("tls.key").to_string_lossy().to_string();
        (dir, cert_path, key_path)
    }

    fn gateway_with_https_cert(secret_name: &str) -> Gateway {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw-1", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{
                    "name": "https",
                    "protocol": "HTTPS",
                    "port": 443,
                    "tls": {
                        "certificateRefs": [{"kind": "Secret", "name": secret_name}]
                    }
                }]
            }
        }))
        .unwrap()
    }

    fn view_with_gateway(gw: Gateway) -> GatewayView {
        let state = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("https"),
                protocol: Arc::from("HTTPS"),
                port: 443,
                hostname: None,
                tls_mode: None,
        frontend_validation: None,
    }],
        backend_client_cert_id: None,
    };
        let _ = gw;
        ReconciledView {
            gateways: vec![state],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn maybe_write_gateway_certs_writes_new_cert() {
        let (_dir, cert_path, key_path) = test_dir();
        let gw = gateway_with_https_cert("tls-secret");
        let view = view_with_gateway(gw.clone());
        let cert_pem = b"-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----";
        let key_pem = b"-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----";
        let client = kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let cert_pem = cert_pem.to_vec();
                let key_pem = key_pem.to_vec();
                async move {
                    let body = if path.contains("/gateways/gw-1") {
                        serde_json::json!({
                            "apiVersion": "gateway.networking.k8s.io/v1",
                            "kind": "Gateway",
                            "metadata": { "name": "gw-1", "namespace": "default" },
                            "spec": {
                                "gatewayClassName": "sunbeam",
                                "listeners": [{
                                    "name": "https",
                                    "protocol": "HTTPS",
                                    "port": 443,
                                    "tls": {
                                        "certificateRefs": [{"kind": "Secret", "name": "tls-secret"}]
                                    }
                                }]
                            }
                        })
                    } else if path.contains("/secrets/tls-secret") {
                        serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "Secret",
                            "metadata": { "name": "tls-secret", "namespace": "default" },
                            "data": {
                                "tls.crt": b64(&cert_pem),
                                "tls.key": b64(&key_pem)
                            }
                        })
                    } else {
                        serde_json::json!({"apiVersion": "v1", "kind": "List", "items": []})
                    };
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );

        let changed = maybe_write_gateway_certs(&client, &view, &cert_path, &key_path)
            .await
            .unwrap();
        assert!(changed);
        assert_eq!(std::fs::read(&cert_path).unwrap(), cert_pem);
        assert_eq!(std::fs::read(&key_path).unwrap(), key_pem);

        // Second call with identical data reports no change.
        let changed = maybe_write_gateway_certs(&client, &view, &cert_path, &key_path)
            .await
            .unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn maybe_write_gateway_certs_skips_http_listener() {
        let (_dir, cert_path, key_path) = test_dir();
        let view = ReconciledView {
            gateways: vec![GatewayState {
                namespace: Arc::from("default"),
                name: Arc::from("gw-1"),
                generation: 1,
                listeners: vec![ListenerState {
                    name: Arc::from("http"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: None,
                    tls_mode: None,
        frontend_validation: None,
    }],
        backend_client_cert_id: None,
    }],
            ..Default::default()
        };
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let changed = maybe_write_gateway_certs(&client, &view, &cert_path, &key_path)
            .await
            .unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn maybe_write_gateway_certs_returns_false_when_gateway_fetch_fails() {
        let (_dir, cert_path, key_path) = test_dir();
        let view = view_with_gateway(gateway_with_https_cert("tls-secret"));
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(500)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let changed = maybe_write_gateway_certs(&client, &view, &cert_path, &key_path)
            .await
            .unwrap();
        assert!(!changed);
    }
}
