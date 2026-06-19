// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Centralized TLS certificate registry.
//!
//! Holds the default certificate, SNI-specific certificates, wildcard
//! certificates, trust roots, and client-auth roots. Updates are atomic via
//! `ArcSwap`, so consumers can reload certs without restarting.

use arc_swap::ArcSwap;
use pingora_core::utils::tls::CertKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{
    ClientHello, ResolvesServerCert, WebPkiClientVerifier,
    danger::{ClientCertVerified, ClientCertVerifier},
};
use rustls::sign::CertifiedKey;
use rustls::{
    DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme,
    client::danger::HandshakeSignatureValid,
};
use std::collections::HashMap;
use std::sync::Arc;

/// A wildcard pattern such as `*.example.com`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WildcardPattern {
    suffix: Arc<str>,
}

impl WildcardPattern {
    /// Create a wildcard pattern. Returns `None` if the string does not start
    /// with `*`.
    pub fn new(pattern: &str) -> Option<Self> {
        let pattern = pattern.to_lowercase();
        if pattern.starts_with("*.") {
            Some(Self {
                suffix: pattern.strip_prefix('*').unwrap().into(),
            })
        } else {
            None
        }
    }

    /// Match a hostname against the pattern. `*.example.com` matches
    /// `foo.example.com` but not `foo.bar.example.com`.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        host.strip_suffix(self.suffix.as_ref())
            .map(|prefix| !prefix.is_empty() && !prefix.contains('.'))
            .unwrap_or(false)
    }
}

/// In-memory snapshot of all TLS material.
#[derive(Clone, Debug)]
pub struct CertStore {
    /// Default certificate used when no SNI match is found.
    pub default: Option<Arc<CertifiedKey>>,
    /// Exact SNI hostname → certificate.
    pub exact: HashMap<Arc<str>, Arc<CertifiedKey>>,
    /// Wildcard patterns, checked in order after exact misses.
    pub wildcard: Vec<(WildcardPattern, Arc<CertifiedKey>)>,
    /// Roots used to validate upstream/backend TLS connections.
    pub trust_roots: RootCertStore,
    /// Roots used to validate client certificates for mTLS.
    pub client_auth_roots: RootCertStore,
    /// Client certificates keyed by identifier, used for upstream mTLS.
    pub client_certs: HashMap<Arc<str>, Arc<CertKey>>,
}

impl Default for CertStore {
    fn default() -> Self {
        Self {
            default: None,
            exact: HashMap::new(),
            wildcard: Vec::new(),
            trust_roots: RootCertStore::empty(),
            client_auth_roots: RootCertStore::empty(),
            client_certs: HashMap::new(),
        }
    }
}

impl CertStore {
    /// Resolve a certificate for the given SNI hostname.
    pub fn resolve(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let normalized = host.to_lowercase();
        if let Some(cert) = self.exact.get(normalized.as_str()) {
            return Some(Arc::clone(cert));
        }
        for (pattern, cert) in &self.wildcard {
            if pattern.matches(&normalized) {
                return Some(Arc::clone(cert));
            }
        }
        self.default.clone()
    }
}

/// Thread-safe, hot-reloadable TLS certificate registry.
#[derive(Clone, Debug)]
pub struct TlsRegistry {
    store: Arc<ArcSwap<CertStore>>,
}

impl Default for TlsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Client certificate verifier that requests a certificate but accepts any
/// (or no) certificate without validating it. This implements Gateway API
/// `AllowInsecureFallback` frontend validation mode.
#[derive(Debug)]
struct FallbackClientVerifier {
    subjects: Vec<DistinguishedName>,
}

impl FallbackClientVerifier {
    fn new(roots: &RootCertStore) -> Self {
        Self {
            subjects: roots.subjects(),
        }
    }
}

impl ClientCertVerifier for FallbackClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.subjects
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

impl TlsRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            store: Arc::new(ArcSwap::from_pointee(CertStore::default())),
        }
    }

    /// Return a snapshot of the current cert store.
    pub fn snapshot(&self) -> Arc<CertStore> {
        self.store.load_full()
    }

    /// Atomically replace the entire cert store.
    pub fn apply(&self, store: CertStore) {
        self.store.store(Arc::new(store));
    }

    /// Resolve a certificate for an SNI hostname.
    pub fn resolve(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        self.store.load().resolve(host)
    }

    /// Return true if the registry currently has no server certificates.
    pub fn is_empty(&self) -> bool {
        let store = self.store.load();
        store.default.is_none() && store.exact.is_empty() && store.wildcard.is_empty()
    }

    /// Build a `rustls::ServerConfig` that uses this registry for SNI
    /// certificate resolution. The caller must ensure the rustls crypto
    /// provider is installed.
    pub fn server_config(&self) -> anyhow::Result<rustls::ServerConfig> {
        self.server_config_inner(None)
    }

    /// Build a `rustls::ServerConfig` with optional frontend client-certificate
    /// validation. The `ca_bundle_pem` is a PEM-encoded CA certificate bundle;
    /// when `allow_insecure_fallback` is true, clients without a certificate are
    /// still allowed to connect.
    pub fn server_config_with_client_auth(
        &self,
        ca_bundle_pem: &str,
        allow_insecure_fallback: bool,
    ) -> anyhow::Result<rustls::ServerConfig> {
        self.server_config_inner(Some((ca_bundle_pem, allow_insecure_fallback)))
    }

    fn server_config_inner(
        &self,
        client_auth: Option<(&str, bool)>,
    ) -> anyhow::Result<rustls::ServerConfig> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no rustls crypto provider installed"))?;
        let builder = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("protocol versions: {e}"))?;

        let mut config = if let Some((ca_bundle_pem, allow_insecure_fallback)) = client_auth {
            if ca_bundle_pem.trim().is_empty() {
                // No CA bundle provided: do not request or validate client certificates.
                builder
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(self.clone()))
            } else {
                let roots = root_store_from_pem(ca_bundle_pem.as_bytes())
                    .map_err(|e| anyhow::anyhow!("invalid client-auth CA bundle: {e}"))?;
                let verifier: Arc<dyn ClientCertVerifier> = if allow_insecure_fallback {
                    Arc::new(FallbackClientVerifier::new(&roots))
                } else {
                    WebPkiClientVerifier::builder(Arc::new(roots))
                        .build()
                        .map_err(|e| anyhow::anyhow!("failed to build client cert verifier: {e}"))?
                };
                builder
                    .with_client_cert_verifier(verifier)
                    .with_cert_resolver(Arc::new(self.clone()))
            }
        } else {
            builder
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(self.clone()))
        };
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }

    /// Look up a client certificate by identifier.
    pub fn client_cert(&self, id: &str) -> Option<Arc<CertKey>> {
        self.store.load().client_certs.get(id).cloned()
    }

    /// Return true if the registry has a client certificate for the given id.
    pub fn has_client_cert(&self, id: &str) -> bool {
        self.store.load().client_certs.contains_key(id)
    }
}

impl ResolvesServerCert for TlsRegistry {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = client_hello
            .server_name()
            .map(|name| name.to_lowercase())
            .unwrap_or_default();
        if host.is_empty() {
            return self.store.load().default.clone();
        }
        self.store.load().resolve(&host)
    }
}

/// Parse a PEM-encoded certificate chain.
pub fn parse_cert_chain(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse certs: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("no certificates found in PEM"));
    }
    Ok(certs)
}

/// Parse a PEM-encoded private key (RSA or PKCS8).
pub fn parse_private_key(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem);
    rustls_pemfile::private_key(&mut cursor)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))
}

/// Validate that the end-entity certificate is temporally valid, suitable for
/// server authentication, and that its public key matches the supplied private
/// key.
fn validate_cert_key_pair(
    certs: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
) -> anyhow::Result<()> {
    let first = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no certificates"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(first.as_ref())
        .map_err(|e| anyhow::anyhow!("failed to parse certificate: {e}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    if now < not_before {
        return Err(anyhow::anyhow!("certificate is not yet valid"));
    }
    if now > not_after {
        return Err(anyhow::anyhow!("certificate has expired"));
    }

    // Reject certificates that explicitly forbid TLS server authentication.
    if let Ok(Some(eku)) = cert.extended_key_usage()
        && !eku.value.server_auth
    {
        return Err(anyhow::anyhow!(
            "certificate lacks TLS server authentication extended key usage"
        ));
    }

    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(key)
        .map_err(|e| anyhow::anyhow!("unsupported private key: {e}"))?;
    let key_spki = signer
        .public_key()
        .ok_or_else(|| anyhow::anyhow!("could not extract public key from private key"))?;
    let cert_spki = cert.tbs_certificate.subject_pki.raw;
    if key_spki.as_ref() != cert_spki {
        return Err(anyhow::anyhow!("private key does not match certificate"));
    }

    Ok(())
}

/// Build a `CertifiedKey` from PEM-encoded cert chain + key.
pub fn certified_key_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<Arc<CertifiedKey>> {
    let certs = parse_cert_chain(cert_pem)?;
    let key = parse_private_key(key_pem)?;
    certified_key_from_parts(certs, key)
}

/// Build a `CertifiedKey` from already-parsed parts.
pub fn certified_key_from_parts(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<Arc<CertifiedKey>> {
    validate_cert_key_pair(&certs, &key)?;
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("unsupported private key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(certs, signer)))
}

/// Build a `RootCertStore` from PEM-encoded roots.
pub fn root_store_from_pem(pem: &[u8]) -> anyhow::Result<RootCertStore> {
    let certs = parse_cert_chain(pem)?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("invalid root cert: {e}"))?;
    }
    Ok(store)
}

/// Load a `CertKey` (Pingora upstream client certificate) from PEM data.
pub fn cert_key_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<CertKey> {
    let certs: Vec<Vec<u8>> = parse_cert_chain(cert_pem)?
        .into_iter()
        .map(|c| c.into_owned().as_ref().to_vec())
        .collect();
    let key = parse_private_key(key_pem)?;
    Ok(CertKey::new(certs, key.secret_der().to_vec()))
}

/// Load a `CertKey` from a Kubernetes Secret's `tls.crt` / `tls.key` data.
pub fn cert_key_from_secret(
    secret: &k8s_openapi::api::core::v1::Secret,
) -> anyhow::Result<CertKey> {
    let data = secret
        .data
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS Secret has no data"))?;
    let cert = data
        .get("tls.crt")
        .ok_or_else(|| anyhow::anyhow!("TLS Secret missing tls.crt"))?;
    let key = data
        .get("tls.key")
        .ok_or_else(|| anyhow::anyhow!("TLS Secret missing tls.key"))?;
    cert_key_from_pem(&cert.0, &key.0)
}

/// Load a `CertifiedKey` from a Kubernetes Secret's `tls.crt` / `tls.key` data.
pub fn certified_key_from_secret(
    secret: &k8s_openapi::api::core::v1::Secret,
) -> anyhow::Result<Arc<CertifiedKey>> {
    let data = secret
        .data
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS Secret has no data"))?;
    let cert = data
        .get("tls.crt")
        .ok_or_else(|| anyhow::anyhow!("TLS Secret missing tls.crt"))?;
    let key = data
        .get("tls.key")
        .ok_or_else(|| anyhow::anyhow!("TLS Secret missing tls.key"))?;
    certified_key_from_pem(&cert.0, &key.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_provider() {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
    }

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

    const WILD_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUTVcr3mi310mbUo6l1cqjneEribQwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNKi5leGFtcGxlLmNvbTAeFw0yNjA2MTMxMDExMTlaFw0yNzA2
MTMxMDExMTlaMBgxFjAUBgNVBAMMDSouZXhhbXBsZS5jb20wWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQ/0RScEV0AyXgVlpOwjUmzOwA7xQY5Z1T+wZ5BhcaJwKvU
w5VjYp+vsUP7nNMO7EwmiIRL9Oh27vkGMxj3scvDo1MwUTAdBgNVHQ4EFgQUONDU
Yyau39iCktm09CmOBU8G+y0wHwYDVR0jBBgwFoAUONDUYyau39iCktm09CmOBU8G
+y0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiA1mweY5Bv2c0q3
ZXAmP9m8coqzKsJIB91ZK0tQnxUiWQIhAOmofFKyOOgHf0/9447K/gzUmAgGwOxL
DkkSdMdmE3GA
-----END CERTIFICATE-----
"#;

    const WILD_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmIetJrd8LWi+H1Xx
LWXJM1WunlFitvkYZxa57QSRfiyhRANCAAQ/0RScEV0AyXgVlpOwjUmzOwA7xQY5
Z1T+wZ5BhcaJwKvUw5VjYp+vsUP7nNMO7EwmiIRL9Oh27vkGMxj3scvD
-----END PRIVATE KEY-----
"#;

    const CLIENT_AUTH_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBeDCCAR+gAwIBAgIUVEmEW3EToBLbEJ0PXAetEXtdhTgwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjA2MTUwMDMwNThaFw0yNjA2MjIwMDMw
NThaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATQQOy8c4IYRCvF+2eyqo7OgqYyM0ZoXp7VrKdIt6PZjWv3WRkt4wdS9Nd9r1bm
RG+K5XyNXgVsE9k62oBgnkzco1MwUTAdBgNVHQ4EFgQUpmCMSWMz9mnBS79SEzE4
jtV5PwQwHwYDVR0jBBgwFoAUpmCMSWMz9mnBS79SEzE4jtV5PwQwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB1dsAxvQaz62broeomlS+UCWde6fL3
nVURdix68mNEZgIgE1aRqiWqS3uFqMmNUAbUYo+5H8twXAUaPr48yKs8t9A=
-----END CERTIFICATE-----
"#;

    const EXPIRED_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBgjCCASmgAwIBAgIBZjAKBggqhkjOPQQDAjAgMR4wHAYDVQQDExV0ZXN0LXBh
c3QuZXhhbXBsZS5jb20wHhcNMjAwMTAxMDAwMDAwWhcNMjAwMTAyMDAwMDAwWjAg
MR4wHAYDVQQDExV0ZXN0LXBhc3QuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAQhXNi5taxgeXUbLmAGDB5JV5R4Jt/RNd0eL2/ZJMO7IbezjQbj
JLtaut1VhYS9T+wqiqSjkmJlUwAzlNp2LseFo1QwUjAMBgNVHRMBAf8EAjAAMBMG
A1UdJQQMMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUwfT3
0uPrUfD3ljQTi8YjIwg2n9gwCgYIKoZIzj0EAwIDRwAwRAIgH+O3aXWKNcjJmt57
LL/TZOHQ2mwGIigN0iUPI11RBIACIDhqrKE2BLJRRcHu05DbkF+BxsNsEELbWp17
K9BddYUF
-----END CERTIFICATE-----
"#;

    const EXPIRED_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0aa2xlHVeFK4HOF4
aQzKnv7oOA+RwkI+cQO4y3WkB+6hRANCAAQhXNi5taxgeXUbLmAGDB5JV5R4Jt/R
Nd0eL2/ZJMO7IbezjQbjJLtaut1VhYS9T+wqiqSjkmJlUwAzlNp2LseF
-----END PRIVATE KEY-----
"#;

    const NOT_YET_VALID_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBhjCCAS2gAwIBAgIBZTAKBggqhkjOPQQDAjAiMSAwHgYDVQQDExd0ZXN0LWZ1
dHVyZS5leGFtcGxlLmNvbTAeFw0yNjA2MTkyMzAwMDBaFw0yNzA2MTkyMzAwMDBa
MCIxIDAeBgNVBAMTF3Rlc3QtZnV0dXJlLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEIVzYubWsYHl1Gy5gBgweSVeUeCbf0TXdHi9v2STDuyG3
s40G4yS7WrrdVYWEvU/sKoqko5JiZVMAM5Tadi7HhaNUMFIwDAYDVR0TAQH/BAIw
ADATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYE
FMH099Lj61Hw95Y0E4vGIyMINp/YMAoGCCqGSM49BAMCA0cAMEQCIGEMmNvRuPn0
5/21UUQ+9IFLasI5J4MRREIT9gCmcaIuAiAc1LSyGr8RtPT9o7stLJ5D5mXW2+Iq
g49PpqbyDpG6kQ==
-----END CERTIFICATE-----
"#;

    const NO_SERVER_AUTH_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBrDCCAVKgAwIBAgIUSuMah+1CsnRTmIaz1VENZhyhLHYwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWdGVzdC1uby1zYS5leGFtcGxlLmNvbTAeFw0yNjA2MTUxMjQx
MjVaFw0yNzA2MTUxMjQxMjVaMCExHzAdBgNVBAMMFnRlc3Qtbm8tc2EuZXhhbXBs
ZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQoSizArljQBDm0OsNMHXSD
/44aCuRL8mFGPRi4SkqJCvIWRkc4s6Q6rMK5Xo65PPrLeX2nVD/Q2MIoachkLhUQ
o2gwZjAdBgNVHQ4EFgQUK2t/VctT1UaTrZD57zA3NQrhvXYwHwYDVR0jBBgwFoAU
K2t/VctT1UaTrZD57zA3NQrhvXYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAK
BggrBgEFBQcDAzAKBggqhkjOPQQDAgNIADBFAiEAwxhbAC9LPq0LMyvgJOguxoZQ
/Hylpvb7uW1iXhvH2+kCIHay1G/u82U9/0Qd3B2NdiewhREFiM/3A6zzl6rhsc7S
-----END CERTIFICATE-----
"#;

    const NO_SERVER_AUTH_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGiTv782OMnOXO4Nn
NtgBPIYTDhCNyDb1hwuXfjeYui6hRANCAAQoSizArljQBDm0OsNMHXSD/44aCuRL
8mFGPRi4SkqJCvIWRkc4s6Q6rMK5Xo65PPrLeX2nVD/Q2MIoachkLhUQ
-----END PRIVATE KEY-----
"#;

    fn test_key() -> Arc<CertifiedKey> {
        certified_key_from_pem(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes()).unwrap()
    }

    fn wild_key() -> Arc<CertifiedKey> {
        certified_key_from_pem(WILD_CERT_PEM.as_bytes(), WILD_KEY_PEM.as_bytes()).unwrap()
    }

    #[test]
    fn wildcard_pattern_matches_one_label() {
        let p = WildcardPattern::new("*.example.com").unwrap();
        assert!(p.matches("foo.example.com"));
        assert!(!p.matches("foo.bar.example.com"));
        assert!(!p.matches("example.com"));
        assert!(!p.matches("other.test"));
    }

    #[test]
    fn wildcard_pattern_is_case_insensitive() {
        let p = WildcardPattern::new("*.EXAMPLE.COM").unwrap();
        assert!(p.matches("Foo.Example.Com"));
    }

    #[test]
    fn wildcard_pattern_rejects_non_wildcard() {
        assert!(WildcardPattern::new("example.com").is_none());
    }

    #[test]
    fn cert_store_resolves_exact() {
        ensure_provider();
        let key = test_key();
        let mut store = CertStore::default();
        store
            .exact
            .insert("test.example.com".into(), Arc::clone(&key));
        assert!(store.resolve("test.example.com").is_some());
        assert!(store.resolve("TEST.EXAMPLE.COM").is_some());
        assert!(store.resolve("other.example.com").is_none());
    }

    #[test]
    fn cert_store_resolves_wildcard() {
        ensure_provider();
        let key = wild_key();
        let mut store = CertStore::default();
        store.wildcard.push((
            WildcardPattern::new("*.example.com").unwrap(),
            Arc::clone(&key),
        ));
        assert!(store.resolve("foo.example.com").is_some());
        assert!(store.resolve("bar.example.com").is_some());
        assert!(store.resolve("foo.bar.example.com").is_none());
    }

    #[test]
    fn cert_store_exact_wins_over_wildcard() {
        ensure_provider();
        let exact_key = test_key();
        let wild_key = wild_key();
        let mut store = CertStore::default();
        store
            .exact
            .insert("specific.example.com".into(), Arc::clone(&exact_key));
        store.wildcard.push((
            WildcardPattern::new("*.example.com").unwrap(),
            Arc::clone(&wild_key),
        ));
        let resolved = store.resolve("specific.example.com").unwrap();
        assert!(Arc::ptr_eq(&resolved, &exact_key));
    }

    #[test]
    fn cert_store_falls_back_to_default() {
        ensure_provider();
        let default_key = test_key();
        let store = CertStore {
            default: Some(Arc::clone(&default_key)),
            ..Default::default()
        };
        assert!(Arc::ptr_eq(
            &store.resolve("anything.example.com").unwrap(),
            &default_key
        ));
    }

    #[test]
    fn registry_apply_and_resolve() {
        ensure_provider();
        let registry = TlsRegistry::new();
        let store = CertStore {
            default: Some(test_key()),
            ..Default::default()
        };
        registry.apply(store);
        assert!(registry.resolve("missing.example.com").is_some());
    }

    #[test]
    fn registry_server_config_builds() {
        ensure_provider();
        let registry = TlsRegistry::new();
        let store = CertStore {
            default: Some(test_key()),
            ..Default::default()
        };
        registry.apply(store);
        let config = registry.server_config();
        assert!(config.is_ok());
    }

    #[test]
    fn registry_server_config_advertises_alpn() {
        ensure_provider();
        let registry = TlsRegistry::new();
        let store = CertStore {
            default: Some(test_key()),
            ..Default::default()
        };
        registry.apply(store);
        let config = registry.server_config().unwrap();
        assert!(config.alpn_protocols.contains(&b"h2".to_vec()));
        assert!(config.alpn_protocols.contains(&b"http/1.1".to_vec()));
    }

    #[test]
    fn parse_cert_chain_extracts_certificate() {
        let certs = parse_cert_chain(TEST_CERT_PEM.as_bytes()).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn parse_private_key_extracts_ec_key() {
        let key = parse_private_key(TEST_KEY_PEM.as_bytes()).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn root_store_from_pem_accepts_valid_root() {
        let store = root_store_from_pem(TEST_CERT_PEM.as_bytes()).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn certified_key_from_pem_succeeds() {
        ensure_provider();
        let key =
            certified_key_from_pem(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes()).unwrap();
        assert_eq!(key.cert.len(), 1);
    }

    #[test]
    fn certified_key_from_pem_fails_with_invalid_key() {
        ensure_provider();
        let result = certified_key_from_pem(TEST_CERT_PEM.as_bytes(), b"not a key");
        assert!(result.is_err());
    }

    #[test]
    fn certified_key_from_pem_rejects_key_mismatch() {
        ensure_provider();
        let result = certified_key_from_pem(TEST_CERT_PEM.as_bytes(), WILD_KEY_PEM.as_bytes());
        assert!(result.is_err(), "expected key mismatch error");
    }

    #[test]
    fn certified_key_from_secret_extracts_data() {
        ensure_provider();
        use k8s_openapi::ByteString;
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        data.insert(
            "tls.crt".to_string(),
            ByteString(TEST_CERT_PEM.as_bytes().to_vec()),
        );
        data.insert(
            "tls.key".to_string(),
            ByteString(TEST_KEY_PEM.as_bytes().to_vec()),
        );
        let secret = Secret {
            metadata: ObjectMeta::default(),
            data: Some(data),
            ..Default::default()
        };
        let key = certified_key_from_secret(&secret).unwrap();
        assert_eq!(key.cert.len(), 1);
    }

    #[test]
    fn certified_key_from_secret_errors_when_data_missing() {
        ensure_provider();
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let secret = Secret {
            metadata: ObjectMeta::default(),
            data: None,
            ..Default::default()
        };
        assert!(certified_key_from_secret(&secret).is_err());
    }

    #[test]
    fn server_config_with_empty_client_auth_bundle_ignores_client_auth() {
        ensure_provider();
        let registry = TlsRegistry::new();
        let store = CertStore {
            default: Some(test_key()),
            ..Default::default()
        };
        registry.apply(store);
        let config = registry.server_config_with_client_auth("", false);
        assert!(config.is_ok());
    }

    #[test]
    fn server_config_with_client_auth_bundle_builds_verifier() {
        ensure_provider();
        let registry = TlsRegistry::new();
        let store = CertStore {
            default: Some(test_key()),
            ..Default::default()
        };
        registry.apply(store);
        let config = registry.server_config_with_client_auth(CLIENT_AUTH_CA_PEM, false);
        assert!(config.is_ok());
    }

    #[test]
    fn server_config_with_client_auth_allow_unauthenticated() {
        ensure_provider();
        let registry = TlsRegistry::new();
        let store = CertStore {
            default: Some(test_key()),
            ..Default::default()
        };
        registry.apply(store);
        let config = registry.server_config_with_client_auth(CLIENT_AUTH_CA_PEM, true);
        assert!(config.is_ok());
    }

    #[test]
    fn webpki_verifier_default_is_mandatory() {
        ensure_provider();
        let roots = root_store_from_pem(CLIENT_AUTH_CA_PEM.as_bytes()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        assert!(verifier.client_auth_mandatory());
    }

    #[tokio::test]
    async fn fallback_client_auth_allows_handshake_without_client_cert() {
        ensure_provider();
        use rustls::pki_types::ServerName;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::time::timeout;
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let mut store = CertStore::default();
        store.default = Some(test_key());
        let registry = TlsRegistry::new();
        registry.apply(store);

        let server_config = registry
            .server_config_with_client_auth(CLIENT_AUTH_CA_PEM, true)
            .unwrap();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"hello").await.unwrap();
        });

        #[derive(Debug)]
        struct AcceptAnyVerifier;
        impl rustls::client::danger::ServerCertVerifier for AcceptAnyVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
            }
        }

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyVerifier))
            .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(client_config));
        let server_name = ServerName::try_from("test.example.com").unwrap();

        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(b"world").await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
        });

        timeout(Duration::from_secs(5), async {
            server.await.unwrap();
            client.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn client_cert_lookup() {
        ensure_provider();
        let mut store = CertStore::default();
        let cert_key = crate::tls::registry::cert_key_from_pem(
            TEST_CERT_PEM.as_bytes(),
            TEST_KEY_PEM.as_bytes(),
        )
        .unwrap();
        store
            .client_certs
            .insert(Arc::from("gateway/default/cert"), Arc::new(cert_key));
        let registry = TlsRegistry::new();
        registry.apply(store);
        assert!(registry.has_client_cert("gateway/default/cert"));
        assert!(registry.client_cert("gateway/default/cert").is_some());
        assert!(!registry.has_client_cert("missing"));
    }

    #[tokio::test]
    async fn full_tls_handshake_resolves_correct_certificate() {
        ensure_provider();
        use rustls::pki_types::ServerName;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::time::timeout;
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let key =
            certified_key_from_pem(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes()).unwrap();

        let mut store = CertStore::default();
        store.exact.insert(Arc::from("test.example.com"), key);
        let registry = TlsRegistry::new();
        registry.apply(store);

        let server_config = registry.server_config().unwrap();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"hello").await.unwrap();
        });

        #[derive(Debug)]
        struct AcceptAnyVerifier;
        impl rustls::client::danger::ServerCertVerifier for AcceptAnyVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
            }
        }

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyVerifier))
            .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(client_config));
        let server_name = ServerName::try_from("test.example.com").unwrap();

        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(b"world").await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
        });

        timeout(Duration::from_secs(5), async {
            server.await.unwrap();
            client.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn tls_registry_default_is_empty() {
        let registry = TlsRegistry::default();
        assert!(registry.is_empty());
    }

    #[test]
    fn tls_registry_snapshot_matches_applied_store() {
        ensure_provider();
        let registry = TlsRegistry::new();
        let mut store = CertStore::default();
        store.default = Some(test_key());
        registry.apply(store);
        let snapshot = registry.snapshot();
        assert!(snapshot.default.is_some());
        assert!(snapshot.exact.is_empty());
        assert!(snapshot.wildcard.is_empty());
    }

    #[test]
    fn parse_cert_chain_errors_on_invalid_pem() {
        let result = parse_cert_chain(b"not a pem");
        assert!(result.is_err());
    }

    #[test]
    fn parse_cert_chain_errors_when_no_certs() {
        let result =
            parse_cert_chain(b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----");
        assert!(result.is_err());
    }

    #[test]
    fn parse_private_key_errors_when_no_key() {
        let result =
            parse_private_key(b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----");
        assert!(result.is_err());
    }

    #[test]
    fn certified_key_from_parts_errors_with_no_certs() {
        ensure_provider();
        let key = parse_private_key(TEST_KEY_PEM.as_bytes()).unwrap();
        let result = certified_key_from_parts(vec![], key);
        assert!(result.is_err());
    }

    #[test]
    fn certified_key_from_parts_errors_with_malformed_cert() {
        ensure_provider();
        let key = parse_private_key(TEST_KEY_PEM.as_bytes()).unwrap();
        let bogus = CertificateDer::from(vec![1u8, 2, 3]);
        let result = certified_key_from_parts(vec![bogus], key);
        assert!(result.is_err());
    }

    #[test]
    fn certified_key_from_pem_rejects_expired_cert() {
        ensure_provider();
        let result =
            certified_key_from_pem(EXPIRED_CERT_PEM.as_bytes(), EXPIRED_KEY_PEM.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn certified_key_from_pem_rejects_not_yet_valid_cert() {
        ensure_provider();
        let result = certified_key_from_pem(
            NOT_YET_VALID_CERT_PEM.as_bytes(),
            EXPIRED_KEY_PEM.as_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn certified_key_from_pem_rejects_missing_server_auth_eku() {
        ensure_provider();
        let result = certified_key_from_pem(
            NO_SERVER_AUTH_CERT_PEM.as_bytes(),
            NO_SERVER_AUTH_KEY_PEM.as_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn cert_key_from_secret_errors_when_tls_crt_missing() {
        ensure_provider();
        use k8s_openapi::ByteString;
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        data.insert(
            "tls.key".to_string(),
            ByteString(TEST_KEY_PEM.as_bytes().to_vec()),
        );
        let secret = Secret {
            metadata: ObjectMeta::default(),
            data: Some(data),
            ..Default::default()
        };
        assert!(cert_key_from_secret(&secret).is_err());
    }

    #[test]
    fn cert_key_from_secret_errors_when_tls_key_missing() {
        ensure_provider();
        use k8s_openapi::ByteString;
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        data.insert(
            "tls.crt".to_string(),
            ByteString(TEST_CERT_PEM.as_bytes().to_vec()),
        );
        let secret = Secret {
            metadata: ObjectMeta::default(),
            data: Some(data),
            ..Default::default()
        };
        assert!(cert_key_from_secret(&secret).is_err());
    }

    #[test]
    fn certified_key_from_secret_errors_when_tls_crt_missing() {
        ensure_provider();
        use k8s_openapi::ByteString;
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        data.insert(
            "tls.key".to_string(),
            ByteString(TEST_KEY_PEM.as_bytes().to_vec()),
        );
        let secret = Secret {
            metadata: ObjectMeta::default(),
            data: Some(data),
            ..Default::default()
        };
        assert!(certified_key_from_secret(&secret).is_err());
    }

    #[test]
    fn certified_key_from_secret_errors_when_tls_key_missing() {
        ensure_provider();
        use k8s_openapi::ByteString;
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        data.insert(
            "tls.crt".to_string(),
            ByteString(TEST_CERT_PEM.as_bytes().to_vec()),
        );
        let secret = Secret {
            metadata: ObjectMeta::default(),
            data: Some(data),
            ..Default::default()
        };
        assert!(certified_key_from_secret(&secret).is_err());
    }
}
