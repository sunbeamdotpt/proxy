// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Listener TLS certificate reference validation.

use crate::gateway::reconcile::refgrant::GrantIndex;
use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;
use kube::Client;

/// Certificate validation outcome for a single listener.
#[derive(Clone, Copy, Debug)]
pub struct CertValidation {
    pub reason: &'static str,
    pub message: &'static str,
}

/// Returns true when a `CertValidation` reason is one produced by frontend
/// client-certificate validation, which uses `NoValidCACertificate` for the
/// `Accepted` condition.
pub(crate) fn is_frontend_ca_error(reason: &str) -> bool {
    matches!(
        reason,
        "InvalidCACertificateRef" | "InvalidCACertificateKind" | "RefNotPermitted"
    )
}

/// Validate a listener's TLS certificate references.
///
/// Returns `Some(CertValidation)` when any certificate reference is malformed,
/// points to an unsupported resource kind, crosses a namespace boundary without
/// a matching ReferenceGrant, or the referenced Secret does not exist or does
/// not contain valid certificate data.
pub async fn validate_listener_certificates(
    client: &Client,
    from_ns: &str,
    from_kind: &str,
    listener: &serde_json::Map<String, serde_json::Value>,
    grant_index: &GrantIndex,
) -> Option<CertValidation> {
    let tls = listener.get("tls")?;
    let certs = tls.get("certificateRefs").and_then(|v| v.as_array())?;
    if certs.is_empty() {
        return None;
    }

    for cert in certs {
        let group = cert.get("group").and_then(|v| v.as_str()).unwrap_or("");
        let kind = cert.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if !group.is_empty() || kind != "Secret" {
            return Some(CertValidation {
                reason: "InvalidCertificateRef",
                message: "CertificateRef must be a core Secret",
            });
        }
        let name = match cert.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => n,
            _ => {
                return Some(CertValidation {
                    reason: "InvalidCertificateRef",
                    message: "CertificateRef name is required",
                })
            }
        };
        let ns = cert
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(from_ns);
        if ns != from_ns {
            let permitted = grant_index.is_permitted(
                from_ns,
                "gateway.networking.k8s.io",
                from_kind,
                ns,
                group,
                kind,
                name,
            );
            if !permitted {
                return Some(CertValidation {
                    reason: "RefNotPermitted",
                    message: "Cross-namespace CertificateRef is not permitted by ReferenceGrant",
                });
            }
        }

        let secrets: Api<Secret> = Api::namespaced(client.clone(), ns);
        let secret = match secrets.get(name).await {
            Ok(s) => s,
            Err(_) => {
                return Some(CertValidation {
                    reason: "InvalidCertificateRef",
                    message: "CertificateRef Secret not found",
                })
            }
        };
        if !secret_data_valid(&secret) {
            return Some(CertValidation {
                reason: "InvalidCertificateRef",
                message: "CertificateRef Secret does not contain a valid TLS certificate",
            });
        }
    }

    None
}

pub(crate) fn secret_data_valid(secret: &Secret) -> bool {
    use k8s_openapi::ByteString;
    let data = match secret.data.as_ref() {
        Some(d) => d,
        None => return false,
    };
    let check_pem = |key: &str| -> bool {
        let bytes: Vec<u8> = match data.get(key) {
            Some(ByteString(b)) => b.clone(),
            None => return false,
        };
        // Quick PEM sanity check: decoded bytes must contain the BEGIN header.
        String::from_utf8_lossy(&bytes).contains("-----BEGIN")
    };
    check_pem("tls.crt") && check_pem("tls.key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::reconcile::gateway::test_helpers::{
        cross_ns_grant, fake_kube_client, CERT_B64, KEY_B64,
    };

    #[test]
    fn is_frontend_ca_error_detects_ca_reasons() {
        assert!(is_frontend_ca_error("InvalidCACertificateRef"));
        assert!(is_frontend_ca_error("InvalidCACertificateKind"));
        assert!(is_frontend_ca_error("RefNotPermitted"));
        assert!(!is_frontend_ca_error("InvalidCertificateRef"));
        assert!(!is_frontend_ca_error(
            "InvalidFrontendClientCertificateValidation"
        ));
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_non_secret_ref() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "GatewayClass", "name": "gc"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert!(err.is_some());
        assert_eq!(err.unwrap().reason, "InvalidCertificateRef");
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_missing_name() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "Secret"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCertificateRef"));
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_cross_namespace_without_grant() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "Secret", "name": "cert", "namespace": "other"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert_eq!(err.map(|e| e.reason), Some("RefNotPermitted"));
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_missing_secret() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "Secret", "name": "missing"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
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
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCertificateRef"));
    }

    #[tokio::test]
    async fn validate_listener_certificates_no_tls_returns_none() {
        let listener = serde_json::json!({"name": "http", "protocol": "HTTP", "port": 80})
            .as_object()
            .unwrap()
            .clone();
        let client = fake_kube_client(String::new());
        let err = validate_listener_certificates(
            &client,
            "default",
            "Gateway",
            &listener,
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_certificates_empty_certs_returns_none() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": []}
        })
        .as_object()
        .unwrap()
        .clone();
        let client = fake_kube_client(String::new());
        let err = validate_listener_certificates(
            &client,
            "default",
            "Gateway",
            &listener,
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_certificates_accepts_cross_namespace_with_grant() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "Secret", "name": "cert", "namespace": "other"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "other"},
            "data": {"tls.crt": CERT_B64, "tls.key": KEY_B64}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let grant_index = GrantIndex::new(vec![cross_ns_grant("other", "Secret", Some("cert"))]);
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_invalid_secret_data() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "default"},
            "data": {"tls.crt": "bm90", "tls.key": "bm90"}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let err = validate_listener_certificates(
            &client,
            "default",
            "Gateway",
            &listener,
            &GrantIndex::new(vec![]),
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCertificateRef"));
    }

    #[test]
    fn secret_data_valid_requires_tls_crt_and_key() {
        let valid = Secret {
            data: Some(std::collections::BTreeMap::from([
                (
                    "tls.crt".to_string(),
                    k8s_openapi::ByteString(b"-----BEGIN CERTIFICATE-----\n".to_vec()),
                ),
                (
                    "tls.key".to_string(),
                    k8s_openapi::ByteString(b"-----BEGIN PRIVATE KEY-----\n".to_vec()),
                ),
            ])),
            ..Default::default()
        };
        assert!(secret_data_valid(&valid));

        let missing_key = Secret {
            data: Some(std::collections::BTreeMap::from([(
                "tls.crt".to_string(),
                k8s_openapi::ByteString(b"-----BEGIN CERTIFICATE-----\n".to_vec()),
            )])),
            ..Default::default()
        };
        assert!(!secret_data_valid(&missing_key));

        let no_data = Secret {
            data: None,
            ..Default::default()
        };
        assert!(!secret_data_valid(&no_data));
    }
}
