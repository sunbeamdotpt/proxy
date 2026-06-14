// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Certificate sources that feed the central [`TlsRegistry`].
//!
//! Multiple sources can be composed with a priority order; higher-priority
//! sources override lower-priority ones when the same hostname is claimed by
//! more than one certificate.

use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::tls::registry::{cert_key_from_secret, certified_key_from_pem, CertStore, WildcardPattern};
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
    store
        .client_certs
        .insert(Arc::from(id), Arc::new(cert_key));
    tracing::info!(
        gateway = %gw_name,
        namespace = %gw_ns,
        %name,
        %ns,
        "loaded Gateway backend client certificate"
    );
}
