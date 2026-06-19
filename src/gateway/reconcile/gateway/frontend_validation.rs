// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Frontend TLS / CA certificate validation.

use crate::gateway::api::gateway::Gateway;
use crate::gateway::model::view::FrontendValidation;
use crate::gateway::model::{GatewayState, TlsMode};
use crate::gateway::reconcile::gateway::certificates::{
    CertValidation, validate_listener_certificates,
};
use crate::gateway::reconcile::gateway::listeners::{listener_frontend_validation, parse_tls_mode};
use crate::gateway::reconcile::refgrant::GrantIndex;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::Client;
use kube::api::Api;
use std::sync::Arc;

/// Raw CA certificate reference extracted from a listener validation block.
#[derive(Clone, Debug)]
pub(crate) struct CaCertificateRefRaw {
    pub(crate) group: Arc<str>,
    pub(crate) kind: Arc<str>,
    pub(crate) name: Arc<str>,
    pub(crate) namespace: Option<Arc<str>>,
}

/// Raw frontend validation configuration parsed from a Gateway listener.
#[derive(Clone, Debug)]
pub(crate) struct FrontendValidationSpec {
    pub(crate) ca_certificate_refs: Vec<CaCertificateRefRaw>,
    pub(crate) allow_insecure_fallback: bool,
}

pub(crate) fn parse_frontend_validation_obj(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<FrontendValidationSpec> {
    let refs = obj.get("caCertificateRefs").and_then(|v| v.as_array())?;
    let mut ca_certificate_refs = Vec::new();
    for r in refs {
        let r = r.as_object()?;
        let name = r.get("name").and_then(|v| v.as_str())?;
        if name.is_empty() {
            return None;
        }
        ca_certificate_refs.push(CaCertificateRefRaw {
            group: Arc::from(r.get("group").and_then(|v| v.as_str()).unwrap_or("")),
            kind: Arc::from(r.get("kind").and_then(|v| v.as_str()).unwrap_or("")),
            name: Arc::from(name),
            namespace: r.get("namespace").and_then(|v| v.as_str()).map(Arc::from),
        });
    }
    let allow_insecure_fallback = obj
        .get("mode")
        .and_then(|v| v.as_str())
        .map(|s| s == "AllowInsecureFallback")
        .unwrap_or(false);
    Some(FrontendValidationSpec {
        ca_certificate_refs,
        allow_insecure_fallback,
    })
}

/// Returns true when any TLS-terminated listener on the Gateway uses a frontend
/// validation mode of `AllowInsecureFallback`.
pub(crate) fn gateway_insecure_frontend_mode(gw: &Gateway) -> bool {
    let gw_tls = gw.spec.tls.as_ref();
    for listener in &gw.spec.listeners {
        let Some(obj) = listener.as_object() else {
            continue;
        };
        let protocol = obj
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("HTTP");
        let tls_mode = parse_tls_mode(obj, protocol);
        if !matches!(protocol, "HTTPS" | "TLS") || tls_mode != Some(TlsMode::Terminate) {
            continue;
        }
        let port = obj.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
        if let Some(spec) = listener_frontend_validation(gw_tls, port)
            && spec.allow_insecure_fallback
        {
            return true;
        }
    }
    false
}

fn ca_bundle_valid(pem: &[u8]) -> bool {
    crate::tls::registry::parse_cert_chain(pem).is_ok()
}

/// Validate a listener's frontend client-certificate configuration.
///
/// Frontend validation only applies to TLS-terminated listeners. For other
/// listeners the configuration is ignored so that an invalid default does not
/// break plain HTTP listeners.
///
/// Returns `Some(CertValidation)` when the listener references an unsupported
/// resource kind, a missing ConfigMap, a ConfigMap that does not contain a
/// valid `ca.crt` entry, or a cross-namespace reference without a matching
/// ReferenceGrant.
pub async fn validate_listener_frontend_validation(
    client: &Client,
    gw_ns: &str,
    listener: &serde_json::Map<String, serde_json::Value>,
    gw_tls: Option<&serde_json::Value>,
    grant_index: &GrantIndex,
) -> Option<CertValidation> {
    let protocol = listener
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("HTTP");
    let tls_mode = parse_tls_mode(listener, protocol);
    if !matches!(protocol, "HTTPS" | "TLS") || tls_mode != Some(TlsMode::Terminate) {
        return None;
    }

    let port = listener.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
    let spec = match listener_frontend_validation(gw_tls, port) {
        Some(s) => s,
        None => return None,
    };

    for r in &spec.ca_certificate_refs {
        if r.kind.as_ref() != "ConfigMap" || !r.group.as_ref().is_empty() {
            return Some(CertValidation {
                reason: "InvalidCACertificateKind",
                message: "Frontend CA certificate reference must be a core ConfigMap",
            });
        }
        let ref_ns = r.namespace.as_deref().unwrap_or(gw_ns);
        if ref_ns != gw_ns
            && !grant_index.is_permitted(
                gw_ns,
                "gateway.networking.k8s.io",
                "Gateway",
                ref_ns,
                "",
                "ConfigMap",
                r.name.as_ref(),
            )
        {
            return Some(CertValidation {
                reason: "RefNotPermitted",
                message: "Frontend CA certificate reference is not permitted by ReferenceGrant",
            });
        }
        let cms: Api<ConfigMap> = Api::namespaced(client.clone(), ref_ns);
        let cm = match cms.get(r.name.as_ref()).await {
            Ok(c) => c,
            Err(_) => {
                return Some(CertValidation {
                    reason: "InvalidCACertificateRef",
                    message: "Frontend CA certificate ConfigMap not found",
                });
            }
        };
        let data = match cm.data.as_ref() {
            Some(d) => d,
            None => {
                return Some(CertValidation {
                    reason: "InvalidCACertificateRef",
                    message: "Frontend CA certificate ConfigMap has no data",
                });
            }
        };
        let ca = match data.get("ca.crt") {
            Some(v) => v.as_bytes(),
            None => {
                return Some(CertValidation {
                    reason: "InvalidCACertificateRef",
                    message: "Frontend CA certificate ConfigMap missing ca.crt",
                });
            }
        };
        if !ca_bundle_valid(ca) {
            return Some(CertValidation {
                reason: "InvalidCACertificateRef",
                message: "Frontend CA certificate is not a valid PEM bundle",
            });
        }
    }

    None
}

/// Load the PEM CA bundle for each listener's frontend validation and store
/// it in the corresponding [`ListenerState`]. Invalid or missing references
/// mark the listener as unprogrammed so routes do not attach to it.
pub async fn load_gateway_frontend_validations(
    client: &Client,
    gateways: &[Gateway],
    states: &mut [GatewayState],
    grant_index: &GrantIndex,
) {
    for (gw, state) in gateways.iter().zip(states.iter_mut()) {
        let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
        let gw_tls = gw.spec.tls.as_ref();
        for (idx, listener) in state.listeners.iter_mut().enumerate() {
            if !matches!(listener.protocol.as_ref(), "HTTPS" | "TLS")
                || listener.tls_mode != Some(TlsMode::Terminate)
            {
                continue;
            }

            let mut valid = true;
            if let Some(obj) = gw.spec.listeners.get(idx).and_then(|v| v.as_object()) {
                if validate_listener_certificates(client, gw_ns, "Gateway", obj, grant_index)
                    .await
                    .is_some()
                {
                    valid = false;
                }
            } else {
                valid = false;
            }

            let spec = match listener_frontend_validation(gw_tls, listener.port) {
                Some(s) if valid => s,
                _ => {
                    if !valid {
                        listener.programmed = false;
                    }
                    continue;
                }
            };

            let mut bundle = String::new();
            for r in &spec.ca_certificate_refs {
                if r.kind.as_ref() != "ConfigMap" || !r.group.as_ref().is_empty() {
                    valid = false;
                    break;
                }
                let ref_ns = r.namespace.as_deref().unwrap_or(gw_ns);
                if ref_ns != gw_ns
                    && !grant_index.is_permitted(
                        gw_ns,
                        "gateway.networking.k8s.io",
                        "Gateway",
                        ref_ns,
                        "",
                        "ConfigMap",
                        r.name.as_ref(),
                    )
                {
                    valid = false;
                    break;
                }
                let cms: Api<ConfigMap> = Api::namespaced(client.clone(), ref_ns);
                let cm = match cms.get(r.name.as_ref()).await {
                    Ok(c) => c,
                    Err(_) => {
                        valid = false;
                        break;
                    }
                };
                let Some(data) = cm.data.as_ref() else {
                    valid = false;
                    break;
                };
                let Some(ca) = data.get("ca.crt") else {
                    valid = false;
                    break;
                };
                if !ca_bundle_valid(ca.as_bytes()) {
                    valid = false;
                    break;
                }
                bundle.push_str(ca);
                if !bundle.ends_with('\n') {
                    bundle.push('\n');
                }
            }

            if !valid {
                listener.programmed = false;
                continue;
            }
            listener.frontend_validation = Some(FrontendValidation {
                ca_bundle_pem: Arc::from(bundle),
                allow_insecure_fallback: spec.allow_insecure_fallback,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::ListenerState;
    use crate::gateway::reconcile::gateway::certificates::CertValidation;
    use crate::gateway::reconcile::gateway::listeners::build_listener_status;
    use crate::gateway::reconcile::gateway::test_helpers::{
        TEST_CERT_PEM, cross_ns_grant, fake_kube_client,
    };
    use std::sync::Arc;

    #[test]
    fn parse_frontend_validation_obj_extracts_configmap_refs() {
        let obj = serde_json::json!({
            "caCertificateRefs": [
                {"group": "", "kind": "ConfigMap", "name": "ca-1"},
                {"group": "", "kind": "ConfigMap", "name": "ca-2"}
            ],
            "mode": "AllowInsecureFallback"
        })
        .as_object()
        .unwrap()
        .clone();
        let spec = parse_frontend_validation_obj(&obj).unwrap();
        assert_eq!(spec.ca_certificate_refs.len(), 2);
        assert_eq!(spec.ca_certificate_refs[0].name.as_ref(), "ca-1");
        assert!(spec.allow_insecure_fallback);
    }

    #[test]
    fn parse_frontend_validation_obj_preserves_non_configmap_kind() {
        let obj = serde_json::json!({
            "caCertificateRefs": [
                {"group": "", "kind": "Secret", "name": "ca-1"}
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        let spec = parse_frontend_validation_obj(&obj).unwrap();
        assert_eq!(spec.ca_certificate_refs[0].kind.as_ref(), "Secret");
    }

    #[test]
    fn parse_frontend_validation_obj_missing_refs_returns_none() {
        assert!(parse_frontend_validation_obj(&serde_json::Map::new()).is_none());
    }

    #[test]
    fn parse_frontend_validation_obj_non_object_ref_returns_none() {
        let obj = serde_json::json!({"caCertificateRefs": ["not-object"]})
            .as_object()
            .unwrap()
            .clone();
        assert!(parse_frontend_validation_obj(&obj).is_none());
    }

    #[test]
    fn parse_frontend_validation_obj_empty_name_returns_none() {
        let obj = serde_json::json!({"caCertificateRefs": [{"kind": "ConfigMap", "name": ""}]})
            .as_object()
            .unwrap()
            .clone();
        assert!(parse_frontend_validation_obj(&obj).is_none());
    }

    #[test]
    fn parse_frontend_validation_obj_default_mode_false() {
        let obj = serde_json::json!({"caCertificateRefs": [{"kind": "ConfigMap", "name": "ca"}]})
            .as_object()
            .unwrap()
            .clone();
        let spec = parse_frontend_validation_obj(&obj).unwrap();
        assert!(!spec.allow_insecure_fallback);
    }

    #[test]
    fn listener_frontend_validation_default_applies_to_listener() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}],
                        "mode": "AllowValidOnly"
                    }
                }
            }
        });
        let spec = listener_frontend_validation(Some(&tls), 443).unwrap();
        assert_eq!(spec.ca_certificate_refs[0].name.as_ref(), "ca");
        assert!(!spec.allow_insecure_fallback);
    }

    #[test]
    fn listener_frontend_validation_per_port_overrides_default() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "default-ca"}]
                    }
                },
                "perPort": [
                    {
                        "port": 8443,
                        "tls": {
                            "validation": {
                                "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "port-ca"}]
                            }
                        }
                    }
                ]
            }
        });
        let default_spec = listener_frontend_validation(Some(&tls), 443).unwrap();
        assert_eq!(
            default_spec.ca_certificate_refs[0].name.as_ref(),
            "default-ca"
        );
        let port_spec = listener_frontend_validation(Some(&tls), 8443).unwrap();
        assert_eq!(port_spec.ca_certificate_refs[0].name.as_ref(), "port-ca");
    }

    #[test]
    fn listener_frontend_validation_returns_none_without_tls() {
        assert!(listener_frontend_validation(None, 443).is_none());
    }

    #[test]
    fn listener_frontend_validation_insecure_mode() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}],
                        "mode": "AllowInsecureFallback"
                    }
                }
            }
        });
        let spec = listener_frontend_validation(Some(&tls), 443).unwrap();
        assert!(spec.allow_insecure_fallback);
    }

    #[test]
    fn listener_frontend_validation_port_mismatch_uses_default() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"kind": "ConfigMap", "name": "default-ca"}]
                    }
                },
                "perPort": [
                    {
                        "port": 9999,
                        "tls": {
                            "validation": {
                                "caCertificateRefs": [{"kind": "ConfigMap", "name": "port-ca"}]
                            }
                        }
                    }
                ]
            }
        });
        let spec = listener_frontend_validation(Some(&tls), 443).unwrap();
        assert_eq!(spec.ca_certificate_refs[0].name.as_ref(), "default-ca");
    }

    #[test]
    fn listener_frontend_validation_per_port_missing_validation_returns_none() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"kind": "ConfigMap", "name": "default-ca"}]
                    }
                },
                "perPort": [{"port": 8443, "tls": {}}]
            }
        });
        assert!(listener_frontend_validation(Some(&tls), 8443).is_none());
    }

    #[test]
    fn listener_frontend_validation_tls_not_object_returns_none() {
        assert!(
            listener_frontend_validation(Some(&serde_json::json!("not-object")), 443).is_none()
        );
        assert!(
            listener_frontend_validation(Some(&serde_json::json!({"frontend": "not-object"})), 443)
                .is_none()
        );
    }

    #[test]
    fn gateway_insecure_frontend_mode_detects_allow_insecure_fallback() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
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
        assert!(gateway_insecure_frontend_mode(&gw));
    }

    #[test]
    fn gateway_insecure_frontend_mode_false_for_allow_valid_only() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
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
        assert!(!gateway_insecure_frontend_mode(&gw));
    }

    #[test]
    fn gateway_insecure_frontend_mode_ignores_non_object_listener() {
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
                frontend:
                  default:
                    validation:
                      mode: AllowInsecureFallback
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - not-an-object
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        assert!(gateway_insecure_frontend_mode(&gw));
    }

    #[test]
    fn gateway_insecure_frontend_mode_ignores_non_tls() {
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
                frontend:
                  default:
                    validation:
                      mode: AllowInsecureFallback
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
        "#,
        )
        .unwrap();
        assert!(!gateway_insecure_frontend_mode(&gw));
    }

    #[test]
    fn build_listener_status_marks_invalid_frontend_validation() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let features: std::collections::HashSet<String> =
            crate::gateway::reconcile::gatewayclass::supported_features()
                .into_iter()
                .collect();
        let err = Some(CertValidation {
            reason: "InvalidFrontendClientCertificateValidation",
            message: "Frontend CA certificate ConfigMap not found",
        });
        let statuses = build_listener_status(&gw, None, 1, &[err], &[0], &features);
        let resolved = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("ResolvedRefs"))
            .unwrap();
        assert_eq!(resolved["status"].as_str(), Some("False"));
        assert_eq!(
            resolved["reason"].as_str(),
            Some("InvalidFrontendClientCertificateValidation")
        );
        let programmed = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("Programmed"))
            .unwrap();
        assert_eq!(programmed["status"].as_str(), Some("False"));
    }

    #[test]
    fn build_listener_status_maps_frontend_ca_error_to_accepted_no_valid_ca() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let features: std::collections::HashSet<String> =
            crate::gateway::reconcile::gatewayclass::supported_features()
                .into_iter()
                .collect();
        let err = Some(CertValidation {
            reason: "InvalidCACertificateRef",
            message: "Frontend CA certificate ConfigMap not found",
        });
        let statuses = build_listener_status(&gw, None, 1, &[err], &[0], &features);
        let accepted = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("Accepted"))
            .unwrap();
        assert_eq!(accepted["status"].as_str(), Some("False"));
        assert_eq!(accepted["reason"].as_str(), Some("NoValidCACertificate"));
    }

    #[test]
    fn build_listener_status_maps_invalid_ca_kind_to_accepted_no_valid_ca() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let features: std::collections::HashSet<String> =
            crate::gateway::reconcile::gatewayclass::supported_features()
                .into_iter()
                .collect();
        let err = Some(CertValidation {
            reason: "InvalidCACertificateKind",
            message: "Frontend CA certificate reference must be a core ConfigMap",
        });
        let statuses = build_listener_status(&gw, None, 1, &[err], &[0], &features);
        let resolved = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("ResolvedRefs"))
            .unwrap();
        assert_eq!(resolved["status"].as_str(), Some("False"));
        assert_eq!(
            resolved["reason"].as_str(),
            Some("InvalidCACertificateKind")
        );
        let accepted = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("Accepted"))
            .unwrap();
        assert_eq!(accepted["status"].as_str(), Some("False"));
        assert_eq!(accepted["reason"].as_str(), Some("NoValidCACertificate"));
    }

    #[test]
    fn build_listener_status_maps_ref_not_permitted_to_accepted_no_valid_ca() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let features: std::collections::HashSet<String> =
            crate::gateway::reconcile::gatewayclass::supported_features()
                .into_iter()
                .collect();
        let err = Some(CertValidation {
            reason: "RefNotPermitted",
            message: "Frontend CA certificate reference is not permitted by ReferenceGrant",
        });
        let statuses = build_listener_status(&gw, None, 1, &[err], &[0], &features);
        let resolved = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("ResolvedRefs"))
            .unwrap();
        assert_eq!(resolved["status"].as_str(), Some("False"));
        assert_eq!(resolved["reason"].as_str(), Some("RefNotPermitted"));
        let accepted = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("Accepted"))
            .unwrap();
        assert_eq!(accepted["status"].as_str(), Some("False"));
        assert_eq!(accepted["reason"].as_str(), Some("NoValidCACertificate"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_non_configmap_ref() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "example.com", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateKind"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_returns_none_for_http() {
        let listener = serde_json::json!({
            "name": "http",
            "protocol": "HTTP",
            "port": 80
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_missing_configmap() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "missing"}]
                    }
                }
            }
        });
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
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateRef"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_accepts_valid_configmap() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"},
            "data": {"ca.crt": TEST_CERT_PEM}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_non_configmap_kind() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "Secret", "name": "ca"}]
                    }
                }
            }
        });
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateKind"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_cross_namespace_without_grant() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{
                            "group": "",
                            "kind": "ConfigMap",
                            "name": "ca",
                            "namespace": "other"
                        }]
                    }
                }
            }
        });
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("RefNotPermitted"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_accepts_cross_namespace_with_grant() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{
                            "group": "",
                            "kind": "ConfigMap",
                            "name": "ca",
                            "namespace": "other"
                        }]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "other"},
            "data": {"ca.crt": TEST_CERT_PEM}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![cross_ns_grant("other", "ConfigMap", Some("ca"))]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_missing_configmap_data() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateRef"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_missing_ca_crt() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"},
            "data": {}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateRef"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_invalid_pem() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"},
            "data": {"ca.crt": "not a pem"}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateRef"));
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_marks_listener_unprogrammed_on_invalid_ca() {
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
                        name: missing-ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
                  tls:
                    certificateRefs:
                    - kind: Secret
                      name: cert
        "#,
        )
        .unwrap();

        let mut state = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("https"),
                protocol: Arc::from("HTTPS"),
                port: 443,
                hostname: None,
                tls_mode: Some(TlsMode::Terminate),
                frontend_validation: None,
                programmed: true,
            }],
            backend_client_cert_id: None,
        };

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
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &grant_index,
        )
        .await;
        assert!(!state.listeners[0].programmed);
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_loads_valid_bundle() {
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
        let mut state = crate::gateway::reconcile::gateway::build_gateway_state(&gw);
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"},
            "data": {"ca.crt": TEST_CERT_PEM}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(state.listeners[0].programmed);
        let fv = state.listeners[0].frontend_validation.as_ref().unwrap();
        assert!(!fv.ca_bundle_pem.is_empty());
        assert!(fv.ca_bundle_pem.ends_with('\n'));
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_skips_http_listener() {
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
                - name: http
                  protocol: HTTP
                  port: 80
        "#,
        )
        .unwrap();
        let mut state = crate::gateway::reconcile::gateway::build_gateway_state(&gw);
        let client = fake_kube_client(String::new());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(state.listeners[0].programmed);
        assert!(state.listeners[0].frontend_validation.is_none());
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_marks_invalid_kind_unprogrammed() {
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
                      - kind: Secret
                        group: ""
                        name: ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let mut state = crate::gateway::reconcile::gateway::build_gateway_state(&gw);
        let client = fake_kube_client(String::new());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(!state.listeners[0].programmed);
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_marks_cross_namespace_unprogrammed() {
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
                        namespace: other
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let mut state = crate::gateway::reconcile::gateway::build_gateway_state(&gw);
        let client = fake_kube_client(String::new());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(!state.listeners[0].programmed);
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_marks_non_object_listener_unprogrammed() {
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
                - not-an-object
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let mut state = crate::gateway::reconcile::gateway::build_gateway_state(&gw);
        let client = fake_kube_client(String::new());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(!state.listeners[0].programmed);
    }
}
