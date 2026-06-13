// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Centralized TLS certificate registry.
//!
//! Holds the default certificate, SNI-specific certificates, wildcard
//! certificates, trust roots, and client-auth roots. Updates are atomic via
//! `ArcSwap`, so consumers can reload certs without restarting.

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::RootCertStore;
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
}

impl Default for CertStore {
    fn default() -> Self {
        Self {
            default: None,
            exact: HashMap::new(),
            wildcard: Vec::new(),
            trust_roots: RootCertStore::empty(),
            client_auth_roots: RootCertStore::empty(),
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
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no rustls crypto provider installed"))?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("protocol versions: {e}"))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(self.clone()));
        // L4 TLS termination forwards decrypted bytes to a local plaintext
        // HTTP/1.1 service, so only offer HTTP/1.1 to the client.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
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
        let mut store = CertStore::default();
        store.default = Some(Arc::clone(&default_key));
        assert!(Arc::ptr_eq(
            &store.resolve("anything.example.com").unwrap(),
            &default_key
        ));
    }

    #[test]
    fn registry_apply_and_resolve() {
        ensure_provider();
        let registry = TlsRegistry::new();
        let mut store = CertStore::default();
        store.default = Some(test_key());
        registry.apply(store);
        assert!(registry.resolve("missing.example.com").is_some());
    }

    #[test]
    fn registry_server_config_builds() {
        ensure_provider();
        let registry = TlsRegistry::new();
        let mut store = CertStore::default();
        store.default = Some(test_key());
        registry.apply(store);
        let config = registry.server_config();
        assert!(config.is_ok());
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
    fn certified_key_from_secret_extracts_data() {
        ensure_provider();
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use k8s_openapi::ByteString;
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
}
