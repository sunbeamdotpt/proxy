// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-wide upstream CA bundle used by Pingora's rustls upstream connector.
//!
//! Pingora 0.8's rustls connector builds its root store once at process start
//! from the platform trust store plus the file pointed to by `SSL_CERT_FILE`.
//! BackendTLSPolicy and Gateway frontend-validation CA bundles are written to
//! this file; when the bundle changes we trigger a graceful upgrade so the new
//! process loads the updated roots.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Manages the on-disk upstream CA bundle.
#[derive(Clone, Debug)]
pub struct UpstreamCaBundle {
    path: PathBuf,
    last: Arc<Mutex<Option<String>>>,
}

impl UpstreamCaBundle {
    /// Create a manager for the given bundle path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            last: Arc::new(Mutex::new(None)),
        }
    }

    /// Return the bundle path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Collect CA bundles from the reconciled Gateway view and write them to
    /// disk. Returns `true` when the file content changed.
    pub fn write_from_view(&self, view: &crate::gateway::model::GatewayView) -> anyhow::Result<bool> {
        let mut bundles = Vec::new();

        for policy in &view.backend_tls_policies {
            if policy.programmed && !policy.ca_bundle_pem.is_empty() {
                bundles.push(Arc::clone(&policy.ca_bundle_pem));
            }
        }

        for gw in &view.gateways {
            for listener in &gw.listeners {
                if let Some(v) = listener.frontend_validation.as_ref() {
                    if !v.ca_bundle_pem.is_empty() {
                        bundles.push(Arc::clone(&v.ca_bundle_pem));
                    }
                }
            }
        }

        for ls in &view.listener_sets {
            for listener in &ls.listeners {
                if let Some(v) = listener.frontend_validation.as_ref() {
                    if !v.ca_bundle_pem.is_empty() {
                        bundles.push(Arc::clone(&v.ca_bundle_pem));
                    }
                }
            }
        }

        self.write(&bundles)
    }

    /// Write the concatenated PEM bundles to disk, returning `true` if the
    /// content changed.
    pub fn write(&self, bundles: &[Arc<str>]) -> anyhow::Result<bool> {
        use std::io::Write;

        let mut content = String::new();
        for bundle in bundles {
            content.push_str(bundle.as_ref());
            if !content.ends_with('\n') {
                content.push('\n');
            }
        }

        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        if last.as_deref() == Some(content.as_str()) {
            return Ok(false);
        }

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut tmp = self.path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp_path = PathBuf::from(tmp);
        {
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp_path, &self.path)?;

        *last = Some(content);
        Ok(true)
    }

    /// Create an empty bundle file if it does not already exist.
    pub fn ensure_exists(&self) -> anyhow::Result<()> {
        if !self.path.exists() {
            self.write(&[])?;
        }
        Ok(())
    }

    /// Returns true when the current bundle has no CA certificates.
    pub fn is_empty(&self) -> bool {
        self.last
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::{
        GatewayState, ListenerState, ReconciledView, TlsMode,
    };
    use crate::gateway::model::view::FrontendValidation;
    use std::sync::Arc;

    #[test]
    fn empty_bundle_does_not_change_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.crt");
        let bundle = UpstreamCaBundle::new(&path);
        bundle.ensure_exists().unwrap();
        assert!(path.exists());
        assert!(!bundle.write_from_view(&ReconciledView::default()).unwrap());
    }

    #[test]
    fn bundle_collects_backend_tls_and_frontend_validation_cas() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.crt");
        let bundle = UpstreamCaBundle::new(&path);

        let ca1 = "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n";
        let ca2 = "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----\n";

        let mut view = ReconciledView::default();
        view.backend_tls_policies.push(crate::gateway::model::BackendTLSPolicyState {
            programmed: true,
            ca_bundle_pem: Arc::from(ca1),
            ..Default::default()
        });
        view.gateways.push(GatewayState {
            listeners: vec![ListenerState {
                protocol: Arc::from("HTTPS"),
                                tls_mode: Some(TlsMode::Terminate),
                frontend_validation: Some(FrontendValidation {
                    ca_bundle_pem: Arc::from(ca2),
                    allow_insecure_fallback: false,
                }),
                ..Default::default()
            }],
            ..Default::default()
        });

        assert!(bundle.write_from_view(&view).unwrap());
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("AA"));
        assert!(written.contains("BB"));
        assert!(!bundle.write_from_view(&view).unwrap());
    }
}
