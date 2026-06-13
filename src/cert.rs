// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::{Api, Client};

/// Fetch the TLS Secret and write `tls.crt` / `tls.key` to the configured paths.
///
/// Called at startup (non-upgrade) so the proxy never depends on kubelet
/// volume-sync timing: the cert files are written directly from the K8s API
/// before `svc.add_tls()` is called.
pub async fn fetch_and_write(
    client: &Client,
    namespace: &str,
    secret_name: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<()> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret = api
        .get(secret_name)
        .await
        .with_context(|| format!("fetching {secret_name} Secret from K8s API"))?;
    write_from_secret(&secret, cert_path, key_path)
}

/// Write `tls.crt` and `tls.key` from a Secret data map to the configured paths.
///
/// k8s-openapi base64-decodes Secret values automatically, so `data["tls.crt"].0`
/// is the raw PEM bytes ready to write.  Called both from `fetch_and_write` at
/// startup and directly from the cert watcher when an `Apply` event delivers
/// the updated Secret object without requiring an additional API round-trip.
pub fn write_from_secret(secret: &Secret, cert_path: &str, key_path: &str) -> Result<()> {
    let data = secret
        .data
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS Secret has no data"))?;

    let crt = data
        .get("tls.crt")
        .ok_or_else(|| anyhow::anyhow!("TLS Secret missing tls.crt"))?;
    let key = data
        .get("tls.key")
        .ok_or_else(|| anyhow::anyhow!("TLS Secret missing tls.key"))?;

    // /etc/tls is an emptyDir; create it if the pod just started.
    if let Some(parent) = std::path::Path::new(cert_path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating cert dir {}", parent.display()))?;
    }

    std::fs::write(cert_path, &crt.0).with_context(|| format!("writing {cert_path}"))?;
    std::fs::write(key_path, &key.0).with_context(|| format!("writing {key_path}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key_perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(key_path, key_perms)
            .with_context(|| format!("restricting permissions on {key_path}"))?;
    }

    tracing::info!(cert_path, key_path, "cert files written from K8s Secret");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::ByteString;
    use std::collections::BTreeMap;

    fn secret_with_data(data: BTreeMap<String, ByteString>) -> Secret {
        Secret {
            metadata: ObjectMeta::default(),
            data: Some(data),
            ..Default::default()
        }
    }

    #[test]
    fn write_from_secret_writes_cert_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), ByteString(b"CERT".to_vec()));
        data.insert("tls.key".to_string(), ByteString(b"KEY".to_vec()));
        let secret = secret_with_data(data);

        write_from_secret(
            &secret,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(std::fs::read(&cert_path).unwrap(), b"CERT");
        assert_eq!(std::fs::read(&key_path).unwrap(), b"KEY");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "TLS private key must be readable only by owner"
            );
        }
    }

    #[test]
    fn write_from_secret_errors_when_data_missing() {
        let secret = Secret {
            metadata: ObjectMeta::default(),
            data: None,
            ..Default::default()
        };
        let err = write_from_secret(&secret, "/tmp/crt", "/tmp/key").unwrap_err();
        assert!(err.to_string().contains("no data"));
    }

    #[test]
    fn write_from_secret_errors_when_cert_missing() {
        let mut data = BTreeMap::new();
        data.insert("tls.key".to_string(), ByteString(b"KEY".to_vec()));
        let secret = secret_with_data(data);
        let err = write_from_secret(&secret, "/tmp/crt", "/tmp/key").unwrap_err();
        assert!(err.to_string().contains("missing tls.crt"));
    }

    #[test]
    fn write_from_secret_errors_when_key_missing() {
        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), ByteString(b"CERT".to_vec()));
        let secret = secret_with_data(data);
        let err = write_from_secret(&secret, "/tmp/crt", "/tmp/key").unwrap_err();
        assert!(err.to_string().contains("missing tls.key"));
    }
}
