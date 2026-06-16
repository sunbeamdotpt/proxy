// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway reconciler.
//!
//! Watches namespaced Gateway resources, computes `Accepted` and
//! `Programmed` status conditions, and builds the listener model.
//! Status writeback is gated on leadership.

pub mod addresses;
pub mod attachment;
pub mod backend_tls;
pub mod certificates;
pub mod controller;
pub mod frontend_validation;
pub mod listeners;

pub use backend_tls::validate_gateway_backend_tls;
pub use certificates::{validate_listener_certificates, CertValidation};
pub use controller::{
    build_gateway_state, reconcile_gateway, run_gateway_controller, GatewayContext,
};
pub use frontend_validation::{
    load_gateway_frontend_validations, validate_listener_frontend_validation,
};
pub use listeners::{
    build_listener_allowed_map, build_listener_model, build_listener_status,
    listener_supported_kinds, parse_allowed_routes, parse_tls_mode,
};

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::gateway::api::gateway::Gateway;
    use crate::gateway::api::gatewayclass::{GatewayClass, GatewayClassSpec};
    use crate::gateway::model::{GrantSubject, ReferenceGrantState};
    use std::sync::Arc;

    pub(crate) fn sample_gw(gateway_class_name: &str) -> Gateway {
        let yaml = format!(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: test-gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: {gateway_class_name}
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
                - name: https
                  protocol: HTTPS
                  port: 443
        "#
        );
        serde_yaml::from_str(&yaml).expect("deserializes")
    }

    pub(crate) fn sample_gc(controller_name: &str) -> GatewayClass {
        GatewayClass {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("test-gc".into()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller_name.into(),
                description: None,
            },
            status: None,
        }
    }

    pub(crate) fn empty_features() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    pub(crate) fn fake_kube_client(response_body: String) -> kube::Client {
        kube::Client::new(
            tower::service_fn(move |_req| {
                let body = response_body.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .body(kube::client::Body::from(bytes::Bytes::from(body)))
                            .unwrap(),
                    )
                }
            }),
            "default",
        )
    }

    pub(crate) fn empty_list(kind: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": kind,
            "items": []
        })
    }

    pub(crate) fn tls_gateway_yaml(mode_a: &str, mode_b: Option<&str>) -> Gateway {
        let listeners = match mode_b {
            Some(mode_b) => serde_yaml::from_str(&format!(
                r#"
                apiVersion: gateway.networking.k8s.io/v1
                kind: Gateway
                metadata:
                  name: tls-gw
                  namespace: default
                  generation: 1
                spec:
                  gatewayClassName: test-gc
                  listeners:
                    - name: tls-a
                      protocol: TLS
                      port: 8443
                      tls:
                        mode: {mode_a}
                        certificateRefs: [{{kind: Secret, name: cert-a}}]
                    - name: tls-b
                      protocol: TLS
                      port: 8443
                      tls:
                        mode: {mode_b}
                        certificateRefs: [{{kind: Secret, name: cert-b}}]
                "#
            )),
            None => serde_yaml::from_str(&format!(
                r#"
                apiVersion: gateway.networking.k8s.io/v1
                kind: Gateway
                metadata:
                  name: tls-gw
                  namespace: default
                  generation: 1
                spec:
                  gatewayClassName: test-gc
                  listeners:
                    - name: tls-a
                      protocol: TLS
                      port: 8443
                      tls:
                        mode: {mode_a}
                        certificateRefs: [{{kind: Secret, name: cert-a}}]
                "#
            )),
        };
        listeners.expect("deserializes")
    }

    pub(crate) fn accepted_reason(statuses: &[serde_json::Value], name: &str) -> Option<String> {
        statuses
            .iter()
            .find(|s| s.get("name").and_then(|v| v.as_str()) == Some(name))
            .and_then(|s| s.get("conditions").and_then(|v| v.as_array()))
            .and_then(|conds| {
                conds
                    .iter()
                    .find(|c| c.get("type").and_then(|v| v.as_str()) == Some("Accepted"))
            })
            .and_then(|c| c.get("reason").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
    }

    pub(crate) fn cross_ns_grant(
        to_ns: &str,
        to_kind: &str,
        to_name: Option<&str>,
    ) -> ReferenceGrantState {
        ReferenceGrantState {
            namespace: Arc::from(to_ns),
            name: Arc::from("grant"),
            generation: 1,
            from: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),
                namespace: Some(Arc::from("default")),
                name: None,
            }],
            to: vec![GrantSubject {
                group: Arc::from(""),
                kind: Arc::from(to_kind),
                namespace: None,
                name: to_name.map(Arc::from),
            }],
        }
    }

    pub(crate) const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIUae+5bMkQvXZI8kjz4yoGasBrilYwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjA2MTMxMDExMTJaFw0y
NzA2MTMxMDExMTJaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASnTjZLqwGQj3b8xkyDFQe38SBzfsyxNUEy5fzO
54cks0X7K9JIWJLigltzP4Jh5OwYUSD0UrKXSukj/LRKkL5Eo1MwUTAdBgNVHQ4E
FgQUyoVck0knQWBZB4na42ZOz3Ke/ykwHwYDVR0jBBgwFoAUyoVck0knQWBZB4na
42ZOz3Ke/ykwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAFHJQe
Ltr83KS7tC2NbWRybv6NdUG5fuzrS61t06Yi6wIgOkoD6+KlR4UOP4dFIojV5uz4
huKv4WWxIg9T0tCH/yU=
-----END CERTIFICATE-----
"#;

    pub(crate) const CERT_B64: &str = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJpakNDQVRHZ0F3SUJBZ0lVYWUrNWJNa1F2WFpJOGtqejR5b0dhc0JyaWxZd0NnWUlLb1pJemowRUF3SXcKR3pFWk1CY0dBMVVFQXd3UWRHVnpkQzVsZUdGdGNHeGxMbU52YlRBZUZ3MHlOakEyTVRNeE1ERXhNVEphRncweQpOekEyTVRNeE1ERXhNVEphTUJzeEdUQVhCZ05WQkFNTUVIUmxjM1F1WlhoaGJYQnNaUzVqYjIwd1dUQVRCZ2NxCmhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU25UalpMcXdHUWozYjh4a3lERlFlMzhTQnpmc3l4TlVFeTVmek8KNTRja3MwWDdLOUpJV0pMaWdsdHpQNEpoNU93WVVTRDBVcktYU3Vrai9MUktrTDVFbzFNd1VUQWRCZ05WSFE0RQpGZ1FVeW9WY2swa25RV0JaQjRuYTQyWk96M0tlL3lrd0h3WURWUjBqQkJnd0ZvQVV5b1ZjazBrblFXQlpCNG5hCjQyWk96M0tlL3lrd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBS0JnZ3Foa2pPUFFRREFnTkhBREJFQWlBRkhKUWUKTHRyODNLUzd0QzJOYldSeWJ2Nk5kVUc1ZnV6clM2MXQwNllpNndJZ09rb0Q2K0tsUjRVT1A0ZEZJb2pWNXV6NApodUt2NFdXeElnOVQwdENIL3lVPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==";
    pub(crate) const KEY_B64: &str = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZzkvT2h2a2E0NFdqYXlXRHAKeHozYnVwekphNWpvWmxyL081NXF1QTI4VUpXaFJBTkNBQVNuVGpaTHF3R1FqM2I4eGt5REZRZTM4U0J6ZnN5eApOVUV5NWZ6TzU0Y2tzMFg3SzlKSVdKTGlnbHR6UDRKaDVPd1lVU0QwVXJLWFN1a2ovTFJLa0w1RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==";
}
