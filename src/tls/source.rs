// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Certificate sources that feed the central [`TlsRegistry`].
//!
//! Multiple sources can be composed with a priority order; higher-priority
//! sources override lower-priority ones when the same hostname is claimed by
//! more than one certificate.

use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::tls::registry::{
    cert_key_from_secret, certified_key_from_pem, CertStore, WildcardPattern,
};
use arc_swap::ArcSwap;
use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;
use std::sync::Arc;

/// A synchronous snapshot of TLS material from some source.
pub trait CertSource: Send + Sync {
    /// Return the current certificate store snapshot, if available.
    fn snapshot(&self) -> Option<Arc<CertStore>>;
}

/// Static certificate source backed by files on disk.
#[derive(Clone, Debug)]
pub struct DiskCertSource {
    cert_path: Arc<str>,
    key_path: Arc<str>,
    store: Arc<ArcSwap<CertStore>>,
}

impl DiskCertSource {
    /// Create a disk source and load the certificate immediately.
    pub fn new(cert_path: Arc<str>, key_path: Arc<str>) -> Self {
        let store = Arc::new(ArcSwap::from_pointee(Self::load(&cert_path, &key_path)));
        Self {
            cert_path,
            key_path,
            store,
        }
    }

    /// Reload the certificate from disk.
    pub fn refresh(&self) {
        self.store
            .store(Arc::new(Self::load(&self.cert_path, &self.key_path)));
    }

    fn load(cert_path: &str, key_path: &str) -> CertStore {
        Self::try_load(cert_path, key_path).unwrap_or_default()
    }

    fn try_load(cert_path: &str, key_path: &str) -> Option<CertStore> {
        let cert_pem = std::fs::read(cert_path).ok()?;
        let key_pem = std::fs::read(key_path).ok()?;
        let certified_key = certified_key_from_pem(&cert_pem, &key_pem).ok()?;
        Some(CertStore {
            default: Some(certified_key),
            ..Default::default()
        })
    }
}

impl CertSource for DiskCertSource {
    fn snapshot(&self) -> Option<Arc<CertStore>> {
        Some(self.store.load_full())
    }
}

/// Certificate source backed by Gateway API `certificateRefs`.
///
/// The store is populated asynchronously from the reconciled Gateway view;
/// callers refresh it after each reconcile tick.
#[derive(Clone, Debug)]
pub struct GatewayCertSource {
    store: Arc<ArcSwap<CertStore>>,
}

impl GatewayCertSource {
    /// Create an empty gateway source.
    pub fn new() -> Self {
        Self {
            store: Arc::new(ArcSwap::from_pointee(CertStore::default())),
        }
    }

    /// Refresh the store from the current reconciled Gateway view.
    pub async fn refresh(&self, client: &kube::Client, view: &crate::gateway::model::GatewayView) {
        match build_gateway_cert_store(client, view).await {
            Ok(store) => self.store.store(Arc::new(store)),
            Err(e) => {
                tracing::warn!(error = %e, "gateway cert source refresh failed");
            }
        }
    }
}

impl Default for GatewayCertSource {
    fn default() -> Self {
        Self::new()
    }
}

impl CertSource for GatewayCertSource {
    fn snapshot(&self) -> Option<Arc<CertStore>> {
        Some(self.store.load_full())
    }
}

/// Priority-ordered composition of [`CertSource`]s.
#[derive(Clone, Default)]
pub struct CompositeCertSource {
    sources: Vec<(i32, Arc<dyn CertSource>)>,
}

impl CompositeCertSource {
    /// Create an empty composite source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a source with the given priority. Higher priorities override lower
    /// ones when the same hostname is present in multiple sources.
    pub fn add(&mut self, priority: i32, source: Arc<dyn CertSource>) {
        self.sources.push((priority, source));
        self.sources.sort_by_key(|(p, _)| -p);
    }

    /// Build a merged certificate store from all configured sources.
    pub fn merge(&self) -> CertStore {
        let mut merged = CertStore::default();
        for (_, source) in self.sources.iter().rev() {
            if let Some(store) = source.snapshot() {
                merge_cert_store(&mut merged, &store);
            }
        }
        merged
    }
}

impl CertSource for CompositeCertSource {
    fn snapshot(&self) -> Option<Arc<CertStore>> {
        Some(Arc::new(self.merge()))
    }
}

/// Merge a higher-priority certificate store into a lower-priority one.
///
/// Default and per-hostname certificates from `higher` override those in
/// `lower`. Trust roots are not currently merged.
pub fn merge_cert_store(lower: &mut CertStore, higher: &CertStore) {
    // Default certificate is overridden by the higher-priority source.
    if higher.default.is_some() {
        lower.default.clone_from(&higher.default);
    }

    // Exact and wildcard certificates are overridden by hostname.
    for (host, cert) in &higher.exact {
        lower.exact.insert(Arc::clone(host), Arc::clone(cert));
    }
    for (pattern, cert) in &higher.wildcard {
        lower.wildcard.retain(|(p, _)| p != pattern);
        lower.wildcard.push((pattern.clone(), Arc::clone(cert)));
    }

    // Merge upstream client certificates so that Gateway-wide backend client
    // certificates loaded by the Gateway cert source are available through the
    // shared TLS registry.
    for (id, cert) in &higher.client_certs {
        lower.client_certs.insert(Arc::clone(id), Arc::clone(cert));
    }

    // Trust roots are intentionally not merged here: the project does not
    // currently expose upstream or client-auth roots through certificate
    // sources, and RootCertStore only accepts the original certificate DER.
}

impl std::fmt::Debug for CompositeCertSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeCertSource")
            .field("sources", &self.sources.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::{GatewayState, GatewayView};
    use kube::Client;

    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
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

    const TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9/Ohvka44WjayWDp
xz3bupzJa5joZlr/O55quA28UJWhRANCAASnTjZLqwGQj3b8xkyDFQe38SBzfsyx
NUEy5fzO54cks0X7K9JIWJLigltzP4Jh5OwYUSD0UrKXSukj/LRKkL5E
-----END PRIVATE KEY-----
"#;

    fn test_cert_key() -> Arc<pingora_core::utils::tls::CertKey> {
        Arc::new(
            crate::tls::registry::cert_key_from_pem(
                TEST_CERT_PEM.as_bytes(),
                TEST_KEY_PEM.as_bytes(),
            )
            .unwrap(),
        )
    }

    fn test_certified_key() -> Arc<rustls::sign::CertifiedKey> {
        crate::tls::registry::certified_key_from_pem(
            TEST_CERT_PEM.as_bytes(),
            TEST_KEY_PEM.as_bytes(),
        )
        .unwrap()
    }

    const CERT_B64: &str = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJpakNDQVRHZ0F3SUJBZ0lVYWUrNWJNa1F2WFpJOGtqejR5b0dhc0JyaWxZd0NnWUlLb1pJemowRUF3SXcKR3pFWk1CY0dBMVVFQXd3UWRHVnpkQzVsZUdGdGNHeGxMbU52YlRBZUZ3MHlOakEyTVRNeE1ERXhNVEphRncweQpOekEyTVRNeE1ERXhNVEphTUJzeEdUQVhCZ05WQkFNTUVIUmxjM1F1WlhoaGJYQnNaUzVqYjIwd1dUQVRCZ2NxCmhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU25UalpMcXdHUWozYjh4a3lERlFlMzhTQnpmc3l4TlVFeTVmek8KNTRja3MwWDdLOUpJV0pMaWdsdHpQNEpoNU93WVVTRDBVcktYU3Vrai9MUktrTDVFbzFNd1VUQWRCZ05WSFE0RQpGZ1FVeW9WY2swa25RV0JaQjRuYTQyWk96M0tlL3lrd0h3WURWUjBqQkJnd0ZvQVV5b1ZjazBrblFXQlpCNG5hCjQyWk96M0tlL3lrd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBS0JnZ3Foa2pPUFFRREFnTkhBREJFQWlBRkhKUWUKTHRyODNLUzd0QzJOYldSeWJ2Nk5kVUc1ZnV6clM2MXQwNllpNndJZ09rb0Q2K0tsUjRVT1A0ZEZJb2pWNXV6NApodUt2NFdXeElnOVQwdENIL3lVPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==";
    const KEY_B64: &str = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZzkvT2h2a2E0NFdqYXlXRHAKeHozYnVwekphNWpvWmxyL081NXF1QTI4VUpXaFJBTkNBQVNuVGpaTHF3R1FqM2I4eGt5REZRZTM4U0J6ZnN5eApOVUV5NWZ6TzU0Y2tzMFg3SzlKSVdKTGlnbHR6UDRKaDVPd1lVU0QwVXJLWFN1a2ovTFJLa0w1RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==";

    #[test]
    fn merge_cert_store_overrides_default_and_merges_client_certs() {
        let mut lower = CertStore::default();
        let higher = CertStore {
            default: Some(test_certified_key()),
            exact: [(Arc::from("test.example.com"), test_certified_key())]
                .into_iter()
                .collect(),
            client_certs: [(Arc::from("gateway/default/cert"), test_cert_key())]
                .into_iter()
                .collect(),
            ..Default::default()
        };

        merge_cert_store(&mut lower, &higher);

        assert!(lower.default.is_some());
        assert!(lower.exact.contains_key("test.example.com"));
        assert!(lower.client_certs.contains_key("gateway/default/cert"));
    }

    #[test]
    fn merge_cert_store_overrides_wildcard_certs() {
        let mut lower = CertStore::default();
        let first = test_certified_key();
        let second = test_certified_key();
        lower.wildcard.push((
            crate::tls::registry::WildcardPattern::new("*.example.com").unwrap(),
            first,
        ));

        let higher = CertStore {
            wildcard: vec![(
                crate::tls::registry::WildcardPattern::new("*.example.com").unwrap(),
                second,
            )],
            ..Default::default()
        };

        merge_cert_store(&mut lower, &higher);
        assert_eq!(lower.wildcard.len(), 1);
    }

    #[test]
    fn disk_source_loads_existing_files() {
        let dir = std::env::temp_dir().join(format!("sunbeam-disk-cert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();

        let source = DiskCertSource::new(
            Arc::from(cert_path.to_string_lossy().as_ref()),
            Arc::from(key_path.to_string_lossy().as_ref()),
        );
        let snapshot = source.snapshot().unwrap();
        assert!(snapshot.default.is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disk_source_refreshes_changed_files() {
        let dir = std::env::temp_dir().join(format!("sunbeam-disk-refresh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();

        let source = DiskCertSource::new(
            Arc::from(cert_path.to_string_lossy().as_ref()),
            Arc::from(key_path.to_string_lossy().as_ref()),
        );
        source.refresh();
        let snapshot = source.snapshot().unwrap();
        assert!(snapshot.default.is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disk_source_defaults_when_files_missing() {
        let source = DiskCertSource::new(
            Arc::from("/tmp/sunbeam-does-not-exist-cert.pem"),
            Arc::from("/tmp/sunbeam-does-not-exist-key.pem"),
        );
        let snapshot = source.snapshot().unwrap();
        assert!(snapshot.default.is_none());
    }

    #[test]
    fn composite_source_merges_sources_by_priority() {
        let mut composite = CompositeCertSource::new();
        let disk = Arc::new(DiskCertSource::new(
            Arc::from("/tmp/sunbeam-does-not-exist-cert.pem"),
            Arc::from("/tmp/sunbeam-does-not-exist-key.pem"),
        ));
        let gateway = Arc::new(GatewayCertSource::new());
        composite.add(10, gateway);
        composite.add(5, disk);
        let merged = composite.merge();
        assert!(merged.default.is_none());
        assert!(merged.client_certs.is_empty());
    }

    #[tokio::test]
    async fn gateway_cert_source_loads_listener_and_backend_certs() {
        use crate::gateway::model::{GatewayState, GatewayView};

        fn secret_json(name: &str, cert_b64: &str, key_b64: &str) -> serde_json::Value {
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": name, "namespace": "default"},
                "data": {
                    "tls.crt": cert_b64,
                    "tls.key": key_b64
                }
            })
        }

        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [
                    {
                        "name": "https",
                        "port": 443,
                        "protocol": "HTTPS",
                        "hostname": "example.com",
                        "tls": {
                            "certificateRefs": [{"kind": "Secret", "name": "listener-cert"}]
                        }
                    }
                ],
                "tls": {
                    "backend": {
                        "clientCertificateRef": {"kind": "Secret", "name": "backend-cert"}
                    }
                }
            }
        });

        let client = kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let body = if path
                    == "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw"
                {
                    serde_json::to_string(&gateway_json).unwrap()
                } else if path == "/api/v1/namespaces/default/secrets/listener-cert"
                    || path == "/api/v1/namespaces/default/secrets/backend-cert"
                {
                    serde_json::to_string(&secret_json(
                        path.rsplit('/').next().unwrap(),
                        CERT_B64,
                        KEY_B64,
                    ))
                    .unwrap()
                } else {
                    String::new()
                };
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
        );

        let view = GatewayView {
            gateways: vec![GatewayState {
                namespace: Arc::from("default"),
                name: Arc::from("gw"),
                generation: 1,
                listeners: vec![],
                backend_client_cert_id: Some(Arc::from("gateway/default/backend-cert")),
            }],
            ..Default::default()
        };

        let store = build_gateway_cert_store(&client, &view).await.unwrap();
        assert!(store.exact.contains_key("example.com"));
        assert!(store
            .client_certs
            .contains_key("gateway/default/backend-cert"));
    }

    fn fake_client_with_responses(responses: std::collections::HashMap<String, String>) -> Client {
        let responses = std::sync::Arc::new(responses);
        Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let responses = Arc::clone(&responses);
                async move {
                    let body = responses.get(&path).cloned().unwrap_or_default();
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

    #[tokio::test]
    async fn gateway_cert_source_refresh_populates_store() {
        use crate::gateway::model::{GatewayState, GatewayView};

        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [
                    {
                        "name": "https",
                        "port": 443,
                        "protocol": "HTTPS",
                        "hostname": "example.com",
                        "tls": {
                            "certificateRefs": [{"kind": "Secret", "name": "listener-cert"}]
                        }
                    }
                ]
            }
        });
        let secret_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "listener-cert", "namespace": "default"},
            "data": {"tls.crt": CERT_B64, "tls.key": KEY_B64}
        });

        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        responses.insert(
            "/api/v1/namespaces/default/secrets/listener-cert".to_string(),
            serde_json::to_string(&secret_json).unwrap(),
        );

        let client = fake_client_with_responses(responses);
        let view = GatewayView {
            gateways: vec![GatewayState {
                namespace: Arc::from("default"),
                name: Arc::from("gw"),
                generation: 1,
                listeners: vec![],
                backend_client_cert_id: None,
            }],
            ..Default::default()
        };

        let source = GatewayCertSource::new();
        source.refresh(&client, &view).await;
        let snapshot = source.snapshot().unwrap();
        assert!(snapshot.exact.contains_key("example.com"));
    }

    #[tokio::test]
    async fn build_gateway_cert_store_loads_wildcard_listener_cert() {
        use crate::gateway::model::{GatewayState, GatewayView};

        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [
                    {
                        "name": "https",
                        "port": 443,
                        "protocol": "HTTPS",
                        "hostname": "*.example.com",
                        "tls": {
                            "certificateRefs": [{"kind": "Secret", "name": "listener-cert"}]
                        }
                    }
                ]
            }
        });
        let secret_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "listener-cert", "namespace": "default"},
            "data": {"tls.crt": CERT_B64, "tls.key": KEY_B64}
        });

        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        responses.insert(
            "/api/v1/namespaces/default/secrets/listener-cert".to_string(),
            serde_json::to_string(&secret_json).unwrap(),
        );

        let client = fake_client_with_responses(responses);
        let view = GatewayView {
            gateways: vec![GatewayState {
                namespace: Arc::from("default"),
                name: Arc::from("gw"),
                generation: 1,
                listeners: vec![],
                backend_client_cert_id: None,
            }],
            ..Default::default()
        };

        let store = build_gateway_cert_store(&client, &view).await.unwrap();
        assert!(!store.wildcard.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_skips_http_listener() {
        use crate::gateway::model::{GatewayState, GatewayView};

        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [
                    {
                        "name": "http",
                        "port": 80,
                        "protocol": "HTTP"
                    }
                ]
            }
        });

        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );

        let client = fake_client_with_responses(responses);
        let view = GatewayView {
            gateways: vec![GatewayState {
                namespace: Arc::from("default"),
                name: Arc::from("gw"),
                generation: 1,
                listeners: vec![],
                backend_client_cert_id: None,
            }],
            ..Default::default()
        };

        let store = build_gateway_cert_store(&client, &view).await.unwrap();
        assert!(store.default.is_none() && store.exact.is_empty());
    }

    fn gw_view(backend_id: Option<&str>) -> GatewayView {
        GatewayView {
            gateways: vec![GatewayState {
                namespace: Arc::from("default"),
                name: Arc::from("gw"),
                generation: 1,
                listeners: vec![],
                backend_client_cert_id: backend_id.map(|s| Arc::from(s)),
            }],
            ..Default::default()
        }
    }

    fn secret_json(name: &str, cert_b64: &str, key_b64: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": name, "namespace": "default"},
            "data": {"tls.crt": cert_b64, "tls.key": key_b64}
        })
    }

    fn invalid_secret_json(name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": name, "namespace": "default"},
            "data": {"tls.key": "aW52YWxpZA=="}
        })
    }

    #[test]
    fn disk_source_defaults_on_invalid_pem() {
        let dir = std::env::temp_dir().join(format!("sunbeam-disk-invalid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, "not a valid key").unwrap();
        let source = DiskCertSource::new(
            Arc::from(cert_path.to_string_lossy().as_ref()),
            Arc::from(key_path.to_string_lossy().as_ref()),
        );
        assert!(source.snapshot().unwrap().default.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gateway_cert_source_default_is_usable() {
        let source = GatewayCertSource::default();
        assert!(source.snapshot().unwrap().default.is_none());
    }

    #[test]
    fn composite_cert_source_snapshot_and_debug() {
        let mut composite = CompositeCertSource::new();
        let disk = Arc::new(DiskCertSource::new(
            Arc::from("/tmp/sunbeam-does-not-exist-cert.pem"),
            Arc::from("/tmp/sunbeam-does-not-exist-key.pem"),
        ));
        composite.add(1, disk);
        assert!(composite.snapshot().unwrap().default.is_none());
        let _ = format!("{:?}", composite);
    }

    #[tokio::test]
    async fn build_gateway_cert_store_continues_when_gateway_fetch_fails() {
        let client = fake_client_with_responses(std::collections::HashMap::new());
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.default.is_none() && store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_skips_non_object_listener() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": ["not-an-object"]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.default.is_none() && store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_skips_listener_without_tls() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS"}]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.default.is_none() && store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_skips_listener_without_certificate_refs() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS", "tls": {}}]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.default.is_none() && store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_skips_non_object_certificate_ref() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS", "tls": {"certificateRefs": ["not-an-object"]}}]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.default.is_none() && store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_skips_non_secret_certificate_ref() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS", "tls": {"certificateRefs": [{"kind": "ConfigMap", "name": "cm"}]}}]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.default.is_none() && store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_skips_certificate_ref_without_name() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS", "tls": {"certificateRefs": [{"kind": "Secret"}]}}]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.default.is_none() && store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_denies_cross_namespace_certificate_ref() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS", "hostname": "example.com", "tls": {"certificateRefs": [{"kind": "Secret", "name": "listener-cert", "namespace": "other"}]}}]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        responses.insert(
            "/api/v1/namespaces/other/secrets/listener-cert".to_string(),
            serde_json::to_string(&secret_json("listener-cert", CERT_B64, KEY_B64)).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_continues_when_secret_fetch_fails() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS", "hostname": "example.com", "tls": {"certificateRefs": [{"kind": "Secret", "name": "missing-cert"}]}}]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_continues_on_invalid_secret() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS", "hostname": "example.com", "tls": {"certificateRefs": [{"kind": "Secret", "name": "listener-cert"}]}}]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        responses.insert(
            "/api/v1/namespaces/default/secrets/listener-cert".to_string(),
            serde_json::to_string(&invalid_secret_json("listener-cert")).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_uses_default_when_hostname_empty() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS", "tls": {"certificateRefs": [{"kind": "Secret", "name": "listener-cert"}]}}]
            }
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        responses.insert(
            "/api/v1/namespaces/default/secrets/listener-cert".to_string(),
            serde_json::to_string(&secret_json("listener-cert", CERT_B64, KEY_B64)).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(None))
            .await
            .unwrap();
        assert!(store.default.is_some());
        assert!(store.exact.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_skips_malformed_backend_client_cert_id() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {"gatewayClassName": "sunbeam"}
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(Some("malformed")))
            .await
            .unwrap();
        assert!(store.client_certs.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_denies_cross_namespace_backend_client_cert() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {"gatewayClassName": "sunbeam"}
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        responses.insert(
            "/api/v1/namespaces/other/secrets/backend-cert".to_string(),
            serde_json::to_string(&secret_json("backend-cert", CERT_B64, KEY_B64)).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store = build_gateway_cert_store(&client, &gw_view(Some("gateway/other/backend-cert")))
            .await
            .unwrap();
        assert!(store.client_certs.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_continues_when_backend_secret_missing() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {"gatewayClassName": "sunbeam"}
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store =
            build_gateway_cert_store(&client, &gw_view(Some("gateway/default/backend-cert")))
                .await
                .unwrap();
        assert!(store.client_certs.is_empty());
    }

    #[tokio::test]
    async fn build_gateway_cert_store_continues_on_invalid_backend_secret() {
        let gateway_json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "default"},
            "spec": {"gatewayClassName": "sunbeam"}
        });
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/gw".to_string(),
            serde_json::to_string(&gateway_json).unwrap(),
        );
        responses.insert(
            "/api/v1/namespaces/default/secrets/backend-cert".to_string(),
            serde_json::to_string(&invalid_secret_json("backend-cert")).unwrap(),
        );
        let client = fake_client_with_responses(responses);
        let store =
            build_gateway_cert_store(&client, &gw_view(Some("gateway/default/backend-cert")))
                .await
                .unwrap();
        assert!(store.client_certs.is_empty());
    }
}

/// Scan all Gateway listeners with `certificateRefs`, fetch the referenced
/// Secrets, and build a `CertStore` keyed by listener hostname. Also loads
/// Gateway-wide backend client certificates.
async fn build_gateway_cert_store(
    client: &kube::Client,
    view: &crate::gateway::model::GatewayView,
) -> anyhow::Result<CertStore> {
    use crate::gateway::api::Gateway;

    let mut store = CertStore::default();
    let grant_index = GrantIndex::new(view.reference_grants.clone());

    for gw_state in &view.gateways {
        let gateways_api: Api<Gateway> = Api::namespaced(client.clone(), &gw_state.namespace);
        let gw = match gateways_api.get(&gw_state.name).await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(
                    name = %gw_state.name,
                    namespace = %gw_state.namespace,
                    error = %e,
                    "failed to fetch Gateway for certificate lookup"
                );
                continue;
            }
        };

        for listener in &gw.spec.listeners {
            let Some(obj) = listener.as_object() else {
                continue;
            };

            let protocol = obj
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("HTTP");
            if !matches!(protocol, "HTTPS" | "TLS") {
                continue;
            }

            let Some(tls) = obj.get("tls").and_then(|v| v.as_object()) else {
                continue;
            };
            let Some(refs) = tls.get("certificateRefs").and_then(|v| v.as_array()) else {
                continue;
            };

            // Listener hostname is used to index the certificate. A wildcard
            // listener hostname produces a wildcard cert entry.
            let listener_hostname = obj
                .get("hostname")
                .and_then(|v| v.as_str())
                .map(|h| h.to_lowercase());

            for cert_ref in refs {
                let Some(cert_obj) = cert_ref.as_object() else {
                    continue;
                };
                let kind = cert_obj.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let group = cert_obj.get("group").and_then(|v| v.as_str()).unwrap_or("");
                if kind != "Secret" || !group.is_empty() {
                    continue;
                }
                let Some(secret_name) = cert_obj.get("name").and_then(|v| v.as_str()) else {
                    continue;
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
                        tracing::debug!(
                            %secret_name,
                            %secret_ns,
                            error = %e,
                            "Gateway certificate Secret not found yet"
                        );
                        continue;
                    }
                };

                let certified_key = match crate::tls::registry::certified_key_from_secret(&secret) {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::warn!(
                            %secret_name,
                            %secret_ns,
                            error = %e,
                            "failed to parse Gateway certificate Secret"
                        );
                        continue;
                    }
                };

                match listener_hostname.as_deref() {
                    Some("") | None => {
                        store.default = Some(certified_key);
                    }
                    Some(host) if host.starts_with("*.") => {
                        if let Some(pattern) = WildcardPattern::new(host) {
                            store.wildcard.push((pattern, certified_key));
                        } else {
                            store.default = Some(certified_key);
                        }
                    }
                    Some(host) => {
                        store.exact.insert(Arc::from(host), certified_key);
                    }
                }

                tracing::info!(
                    gateway = %gw_state.name,
                    namespace = %gw_state.namespace,
                    listener = %obj.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    %secret_name,
                    %secret_ns,
                    "loaded Gateway TLS certificate"
                );
            }
        }

        // Load Gateway-wide backend client certificate, if configured.
        if let Some(id) = &gw_state.backend_client_cert_id {
            load_gateway_backend_client_cert(
                client,
                &grant_index,
                &gw_state.namespace,
                &gw_state.name,
                id,
                &mut store,
            )
            .await;
        }
    }

    Ok(store)
}

/// Load a Gateway backend client certificate into the store.
async fn load_gateway_backend_client_cert(
    client: &kube::Client,
    grant_index: &GrantIndex,
    gw_ns: &str,
    gw_name: &str,
    id: &str,
    store: &mut CertStore,
) {
    // The identifier is `gateway/{namespace}/{secret_name}`.
    let parts: Vec<&str> = id.split('/').collect();
    if parts.len() != 3 {
        return;
    }
    let ns = parts[1];
    let name = parts[2];

    if ns != gw_ns
        && !grant_index.is_permitted(
            gw_ns,
            "gateway.networking.k8s.io",
            "Gateway",
            ns,
            "",
            "Secret",
            name,
        )
    {
        tracing::warn!(
            gateway = %gw_name,
            namespace = %gw_ns,
            %name,
            %ns,
            "cross-namespace Gateway backend clientCertificateRef denied by ReferenceGrant"
        );
        return;
    }

    let secret_api: Api<Secret> = Api::namespaced(client.clone(), ns);
    let secret = match secret_api.get(name).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(
                %name,
                %ns,
                error = %e,
                "Gateway backend client certificate Secret not found yet"
            );
            return;
        }
    };
    let cert_key = match cert_key_from_secret(&secret) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(
                %name,
                %ns,
                error = %e,
                "failed to parse Gateway backend client certificate Secret"
            );
            return;
        }
    };
    store.client_certs.insert(Arc::from(id), Arc::new(cert_key));
    tracing::info!(
        gateway = %gw_name,
        namespace = %gw_ns,
        %name,
        %ns,
        "loaded Gateway backend client certificate"
    );
}
