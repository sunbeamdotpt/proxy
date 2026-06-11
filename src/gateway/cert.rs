// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Fetch TLS certificates referenced by Gateway HTTPS listeners and write
//! them to disk so that Pingora can load them on the next graceful upgrade.

use crate::gateway::api::Gateway;
use crate::gateway::model::GatewayView;
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

            let protocol = obj.get("protocol").and_then(|v| v.as_str()).unwrap_or("HTTP");
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
