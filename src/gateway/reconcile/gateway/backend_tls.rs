// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backend / client TLS validation for Gateways.

use crate::gateway::api::gateway::Gateway;
use crate::gateway::reconcile::gateway::certificates::{CertValidation, secret_data_valid};
use crate::gateway::reconcile::gateway::listeners::listener_frontend_validation;
use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::ir::compile::CompiledL4Config;
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::Api;
use std::sync::Arc;

/// Returns true when the compiled L4 dataplane has applied this Gateway's
/// TLS-terminated listeners with a matching frontend validation mode.
///
/// This prevents the Gateway from reporting `Programmed=True` before the
/// listener socket is actually enforcing the requested client-certificate
/// policy.  Listeners with unresolved certificate references are skipped so
/// that invalid configs still get their status patched promptly.
pub(crate) fn gateway_l4_ready(
    gw: &Gateway,
    l4_config: &CompiledL4Config,
    cert_errors: &[Option<CertValidation>],
) -> bool {
    let gw_tls = gw.spec.tls.as_ref();
    for (idx, listener) in gw.spec.listeners.iter().enumerate() {
        let Some(obj) = listener.as_object() else {
            continue;
        };
        // A listener that failed validation is not expected to be programmed
        // into the dataplane with the requested frontend validation.
        if cert_errors.get(idx).copied().flatten().is_some() {
            continue;
        }
        let protocol = obj
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("HTTP");
        let tls_mode = crate::gateway::reconcile::gateway::listeners::parse_tls_mode(obj, protocol);
        if !matches!(protocol, "HTTPS" | "TLS")
            || tls_mode != Some(crate::gateway::model::TlsMode::Terminate)
        {
            continue;
        }
        let port = obj.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
        let ir_protocol = match protocol {
            "HTTPS" => crate::ir::Protocol::Https,
            "TLS" => crate::ir::Protocol::Tls,
            _ => continue,
        };
        let id: Arc<str> = format!("0.0.0.0:{}#{:?}", port, ir_protocol).into();
        let expected =
            listener_frontend_validation(gw_tls, port).map(|spec| spec.allow_insecure_fallback);
        let actual = l4_config
            .listeners
            .iter()
            .find(|l| l.id == id)
            .and_then(|l| {
                l.frontend_validation
                    .as_ref()
                    .map(|v| v.allow_insecure_fallback)
            });
        match (expected, actual) {
            (None, None) => {}
            (Some(expected), Some(actual)) if expected == actual => {}
            _ => return false,
        }
    }
    true
}

/// Extract a syntactically valid Gateway backend client certificate reference.
pub(crate) fn gateway_backend_client_cert_ref(
    gw: &Gateway,
) -> Option<(Arc<str>, Arc<str>, Arc<str>)> {
    let tls = gw.spec.tls.as_ref()?.as_object()?;
    let backend = tls.get("backend")?.as_object()?;
    let cert_ref = backend.get("clientCertificateRef")?.as_object()?;
    let group = cert_ref.get("group").and_then(|v| v.as_str()).unwrap_or("");
    let kind = cert_ref.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if !group.is_empty() || kind != "Secret" {
        return None;
    }
    let name = cert_ref.get("name").and_then(|v| v.as_str())?;
    if name.is_empty() {
        return None;
    }
    let ns = cert_ref
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| gw.metadata.namespace.as_deref().unwrap_or("default"));
    Some((Arc::from(ns), Arc::from(name), Arc::from("Secret")))
}

/// Validate a Gateway's backend TLS client certificate reference.
pub async fn validate_gateway_backend_tls(
    client: &Client,
    gw: &Gateway,
    grant_index: &GrantIndex,
) -> Option<CertValidation> {
    let tls = match gw.spec.tls.as_ref().and_then(|v| v.as_object()) {
        Some(t) => t,
        None => return None,
    };
    let backend = match tls.get("backend").and_then(|v| v.as_object()) {
        Some(b) => b,
        None => return None,
    };
    let cert_ref = match backend
        .get("clientCertificateRef")
        .and_then(|v| v.as_object())
    {
        Some(r) => r,
        None => return None,
    };

    let group = cert_ref.get("group").and_then(|v| v.as_str()).unwrap_or("");
    let kind = cert_ref.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if !group.is_empty() || kind != "Secret" {
        return Some(CertValidation {
            reason: "InvalidClientCertificateRef",
            message: "Gateway backend clientCertificateRef must be a core Secret",
        });
    }
    let name = match cert_ref.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n,
        _ => {
            return Some(CertValidation {
                reason: "InvalidClientCertificateRef",
                message: "Gateway backend clientCertificateRef name is required",
            });
        }
    };
    let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
    let ns = cert_ref
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or(gw_ns);

    if ns != gw_ns {
        let permitted = grant_index.is_permitted(
            gw_ns,
            "gateway.networking.k8s.io",
            "Gateway",
            ns,
            "",
            "Secret",
            name,
        );
        if !permitted {
            return Some(CertValidation {
                reason: "RefNotPermitted",
                message: "Cross-namespace Gateway backend clientCertificateRef is not permitted",
            });
        }
    }

    let secrets: Api<Secret> = Api::namespaced(client.clone(), ns);
    match secrets.get(name).await {
        Ok(s) => {
            if !secret_data_valid(&s) {
                return Some(CertValidation {
                    reason: "InvalidClientCertificateRef",
                    message: "Gateway backend clientCertificateRef Secret does not contain a valid TLS certificate",
                });
            }
        }
        Err(_) => {
            return Some(CertValidation {
                reason: "InvalidClientCertificateRef",
                message: "Gateway backend clientCertificateRef Secret not found",
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::reconcile::gateway::test_helpers::{
        CERT_B64, KEY_B64, TEST_CERT_PEM, cross_ns_grant, fake_kube_client,
    };

    #[tokio::test]
    async fn validate_gateway_backend_tls_rejects_invalid_kind() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: ConfigMap
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_gateway_backend_tls(&client, &gw, &grant_index).await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidClientCertificateRef"));
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_rejects_missing_secret() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: missing
              listeners: []
        "#,
        )
        .unwrap();
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(404)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_gateway_backend_tls(&client, &gw, &grant_index).await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidClientCertificateRef"));
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_accepts_valid_secret() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "default"},
            "data": {"tls.crt": CERT_B64, "tls.key": KEY_B64}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_gateway_backend_tls(&client, &gw, &grant_index).await;
        assert!(err.is_none());
    }

    #[test]
    fn gateway_backend_client_cert_ref_extracts_secret() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let (ns, name, kind) = gateway_backend_client_cert_ref(&gw).unwrap();
        assert_eq!(ns.as_ref(), "default");
        assert_eq!(name.as_ref(), "cert");
        assert_eq!(kind.as_ref(), "Secret");
    }

    #[test]
    fn gateway_backend_client_cert_ref_rejects_non_secret() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: ConfigMap
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        assert!(gateway_backend_client_cert_ref(&gw).is_none());
    }

    #[test]
    fn gateway_backend_client_cert_ref_rejects_empty_name() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: ""
              listeners: []
        "#,
        )
        .unwrap();
        assert!(gateway_backend_client_cert_ref(&gw).is_none());
    }

    #[test]
    fn gateway_backend_client_cert_ref_uses_default_namespace() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let (ns, name, kind) = gateway_backend_client_cert_ref(&gw).unwrap();
        assert_eq!(ns.as_ref(), "default");
        assert_eq!(name.as_ref(), "cert");
        assert_eq!(kind.as_ref(), "Secret");
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_no_tls_returns_none() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              listeners: []
        "#,
        )
        .unwrap();
        let client = fake_kube_client(String::new());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_no_backend_returns_none() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls: {}
              listeners: []
        "#,
        )
        .unwrap();
        let client = fake_kube_client(String::new());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_no_cert_ref_returns_none() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend: {}
              listeners: []
        "#,
        )
        .unwrap();
        let client = fake_kube_client(String::new());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_rejects_empty_name() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: ""
              listeners: []
        "#,
        )
        .unwrap();
        let client = fake_kube_client(String::new());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidClientCertificateRef"));
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_accepts_cross_namespace_with_grant() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
                    namespace: other
              listeners: []
        "#,
        )
        .unwrap();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "other"},
            "data": {"tls.crt": CERT_B64, "tls.key": KEY_B64}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let grant_index = GrantIndex::new(vec![cross_ns_grant("other", "Secret", Some("cert"))]);
        let err = validate_gateway_backend_tls(&client, &gw, &grant_index).await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_rejects_invalid_secret_data() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "default"},
            "data": {"tls.crt": "bm90", "tls.key": "bm90"}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidClientCertificateRef"));
    }

    #[test]
    fn gateway_l4_ready_true_when_validation_matches() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let l4 = crate::ir::compile::CompiledL4Config {
            listeners: vec![crate::ir::compile::CompiledListener {
                id: "0.0.0.0:443#Https".into(),
                bind_addr: "0.0.0.0:443".into(),
                protocol: crate::ir::Protocol::Https,
                tls: None,
                redirect_http_to_https: false,
                frontend_validation: Some(crate::ir::compile::CompiledFrontendValidation {
                    ca_bundle_pem: TEST_CERT_PEM.into(),
                    allow_insecure_fallback: false,
                }),
            }],
            ..Default::default()
        };
        assert!(gateway_l4_ready(&gw, &l4, &[None]));
    }

    #[test]
    fn gateway_l4_ready_false_when_validation_mode_mismatches() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      mode: AllowInsecureFallback
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let l4 = crate::ir::compile::CompiledL4Config {
            listeners: vec![crate::ir::compile::CompiledListener {
                id: "0.0.0.0:443#Https".into(),
                bind_addr: "0.0.0.0:443".into(),
                protocol: crate::ir::Protocol::Https,
                tls: None,
                redirect_http_to_https: false,
                frontend_validation: Some(crate::ir::compile::CompiledFrontendValidation {
                    ca_bundle_pem: TEST_CERT_PEM.into(),
                    allow_insecure_fallback: false,
                }),
            }],
            ..Default::default()
        };
        assert!(!gateway_l4_ready(&gw, &l4, &[None]));
    }

    #[test]
    fn gateway_l4_ready_skips_listener_with_cert_error() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: does-not-exist
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let l4 = crate::ir::compile::CompiledL4Config {
            listeners: vec![crate::ir::compile::CompiledListener {
                id: "0.0.0.0:443#Https".into(),
                bind_addr: "0.0.0.0:443".into(),
                protocol: crate::ir::Protocol::Https,
                tls: None,
                redirect_http_to_https: false,
                frontend_validation: None,
            }],
            ..Default::default()
        };
        let err = Some(CertValidation {
            reason: "InvalidCACertificateRef",
            message: "missing",
        });
        assert!(gateway_l4_ready(&gw, &l4, &[err]));
    }
}
