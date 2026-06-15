// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Custom upstream L4 connector for BackendTLSPolicy backends.
//!
//! Pingora's default rustls connector loads the platform trust store once at
//! process start, so it cannot trust BackendTLSPolicy CA certificates that are
//! reconciled after startup. This connector performs the upstream TLS handshake
//! itself using the per-backend CA bundle stored in [`BackendTlsConfig`], which
//! makes the trust roots dynamic and per-backend.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::connectors::l4::Connect;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::l4::virt::{VirtualSockOpt, VirtualSocket, VirtualSocketStream};
use pingora_core::protocols::tls::TlsStream;
use pingora_core::upstreams::peer::ALPN;
use pingora_core::utils::tls::CertKey;
use pingora_core::{Error, ErrorType, OrErr, Result};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    client::WebPkiServerVerifier,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    CertificateError, DigitallySignedStruct, Error as RustlsError, RootCertStore,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Per-backend TLS settings used to build a fresh rustls config for every
/// upstream connection. Cloning is cheap because the heavy PEM data is `Arc`d.
#[derive(Clone, Debug)]
pub struct DynamicUpstreamL4 {
    sni: String,
    verify_hostname: bool,
    verify_cert: bool,
    alternative_cn: Option<String>,
    client_cert: Option<Arc<CertKey>>,
    ca_bundle_pem: Option<Arc<str>>,
    subject_alt_names: Vec<Arc<str>>,
    alpn: Option<ALPN>,
}

impl DynamicUpstreamL4 {
    /// Build a dynamic TLS connector from the compiled backend TLS config.
    pub fn new(
        tls: &crate::ir::BackendTlsConfig,
        client_cert: Option<Arc<CertKey>>,
        alpn: Option<ALPN>,
    ) -> Self {
        Self {
            sni: tls.sni.as_ref().to_string(),
            verify_hostname: tls.verify_hostname,
            verify_cert: true,
            alternative_cn: tls.alternative_cn.as_ref().map(|s| s.as_ref().to_string()),
            client_cert,
            ca_bundle_pem: tls.ca_bundle_pem.as_ref().map(Arc::clone),
            subject_alt_names: tls.subject_alt_names.clone(),
            alpn,
        }
    }

    /// Return the name used to verify the upstream server certificate.
    fn verify_domain(&self) -> Option<String> {
        self.alternative_cn.clone().or_else(|| {
            if self.sni.is_empty() {
                None
            } else {
                Some(self.sni.clone())
            }
        })
    }

    /// Return a cheap hash of the trust configuration so that connections
    /// established with different CA bundles are not reused for each other.
    pub fn trust_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.ca_bundle_pem.hash(&mut hasher);
        self.subject_alt_names.hash(&mut hasher);
        hasher.finish()
    }
}

#[async_trait]
impl Connect for DynamicUpstreamL4 {
    async fn connect(&self, addr: &SocketAddr) -> Result<L4Stream> {
        let inet_addr = match addr {
            SocketAddr::Inet(a) => *a,
            _ => {
                return Error::e_explain(
                    ErrorType::ConnectError,
                    "unsupported upstream address for dynamic TLS",
                )
            }
        };

        let tcp = TcpStream::connect(inet_addr)
            .await
            .explain_err(ErrorType::ConnectError, |e| format!("tcp connect: {e}"))?;

        let config = build_client_config(self)?;
        let connector = TlsConnector::from(Arc::new(config));
        let domain = self.verify_domain().unwrap_or_else(|| "localhost".to_string());
        let stream = L4Stream::from(tcp);
        let tls_stream = TlsStream::from_connector(&connector, &domain, stream)
            .await
            .explain_err(ErrorType::TLSHandshakeFailure, |e| format!("upstream tls: {e}"))?;

        Ok(L4Stream::from(VirtualSocketStream::new(Box::new(
            TlsVirtualSocket(tls_stream),
        ))))
    }
}

#[derive(Debug)]
struct TlsVirtualSocket(TlsStream<L4Stream>);

impl VirtualSocket for TlsVirtualSocket {
    fn set_socket_option(&self, _opt: VirtualSockOpt) -> std::io::Result<()> {
        // TLS streams do not expose raw socket options.
        Ok(())
    }
}

impl tokio::io::AsyncRead for TlsVirtualSocket {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        inner.poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TlsVirtualSocket {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        inner.poll_shutdown(cx)
    }
}

fn build_client_config(cfg: &DynamicUpstreamL4) -> Result<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    if let Some(pem) = &cfg.ca_bundle_pem {
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .explain_err(ErrorType::InvalidCert, |e| format!("failed to parse CA bundle: {e}"))?;
        roots.add_parsable_certificates(certs);
    }

    let builder = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_root_certificates(roots.clone());

    let mut client_config = if let Some(ck) = &cfg.client_cert {
        let certs: Vec<CertificateDer<'static>> = std::iter::once(ck.leaf())
            .chain(ck.intermediates())
            .map(|c| c.into())
            .collect();
        let key = PrivateKeyDer::try_from(ck.key().as_slice().to_vec())
            .explain_err(ErrorType::InvalidCert, |e| format!("invalid client key: {e}"))?;
        builder
            .with_client_auth_cert(certs, key)
            .explain_err(ErrorType::InvalidCert, |e| format!("client auth config: {e}"))?
    } else {
        builder.with_no_client_auth()
    };

    if !cfg.verify_cert {
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    } else {
        let delegate = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .explain_err(ErrorType::InvalidCert, |e| format!("failed to build verifier: {e}"))?;
        client_config.dangerous().set_certificate_verifier(Arc::new(DynamicVerifier {
            delegate,
            domain: cfg.verify_domain(),
            verify_hostname: cfg.verify_hostname,
            subject_alt_names: cfg.subject_alt_names.clone(),
        }));
    }

    if let Some(alpn) = &cfg.alpn {
        client_config.alpn_protocols = alpn_wire(alpn);
    }

    if cfg.verify_domain().is_none() {
        client_config.enable_sni = false;
    }

    Ok(client_config)
}

/// Verifier that optionally skips hostname verification while still validating
/// the certificate chain against the configured BackendTLSPolicy CAs. Also
/// enforces the allowed Subject Alternative Names list when it is non-empty.
#[derive(Debug)]
struct DynamicVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    domain: Option<String>,
    verify_hostname: bool,
    subject_alt_names: Vec<Arc<str>>,
}

impl ServerCertVerifier for DynamicVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let name = if self.verify_hostname {
            if let Some(domain) = &self.domain {
                ServerName::try_from(domain.as_str())
                    .map_err(|e| RustlsError::General(format!("invalid server name: {e}")))?
            } else {
                first_dns_name(end_entity)?
            }
        } else {
            first_dns_name(end_entity)?
        };

        let verified = self
            .delegate
            .verify_server_cert(end_entity, intermediates, &name, ocsp_response, now)?;

        if !self.subject_alt_names.is_empty() {
            let allowed: HashSet<&str> = self.subject_alt_names.iter().map(|s| s.as_ref()).collect();
            let names = dns_names(end_entity);
            if !names.iter().any(|n| allowed.contains(n.as_str())) {
                return Err(RustlsError::InvalidCertificate(
                    CertificateError::NotValidForName,
                ));
            }
        }

        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.delegate.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.delegate.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![]
    }
}

fn first_dns_name(cert: &CertificateDer<'_>) -> std::result::Result<ServerName<'static>, RustlsError> {
    dns_names(cert)
        .into_iter()
        .next()
        .ok_or_else(|| RustlsError::InvalidCertificate(CertificateError::NotValidForName))
        .and_then(|n| {
            ServerName::try_from(n)
                .map_err(|e| RustlsError::General(format!("invalid server name: {e}")))
        })
}

fn dns_names(cert: &CertificateDer<'_>) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
        if let Ok(Some(san)) = parsed.subject_alternative_name() {
            for name in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(d) = name {
                    names.push(d.to_string());
                }
            }
        }
    }
    names
}

/// Convert an [`ALPN`] selection to the wire format expected by rustls.
fn alpn_wire(alpn: &ALPN) -> Vec<Vec<u8>> {
    match alpn {
        ALPN::H1 => vec![b"http/1.1".to_vec()],
        ALPN::H2 => vec![b"h2".to_vec()],
        ALPN::H2H1 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        ALPN::Custom(custom) => vec![custom.protocol().to_vec()],
    }
}

/// Map a proxy [`ALPN`] selection to the peer ALPN type expected by Pingora.
pub fn alpn_for_protocol(protocol: crate::ir::BackendProtocol) -> Option<ALPN> {
    match protocol {
        crate::ir::BackendProtocol::H2c => Some(ALPN::H2),
        crate::ir::BackendProtocol::Https => Some(ALPN::H2H1),
        crate::ir::BackendProtocol::Http
        | crate::ir::BackendProtocol::WebSocket
        | crate::ir::BackendProtocol::WebSocketSecure => Some(ALPN::H1),
    }
}
