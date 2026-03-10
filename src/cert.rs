use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::{Api, Client};

/// Fetch the `pingora-tls` Secret from the ingress namespace and write
/// `tls.crt` / `tls.key` to the paths declared in config.toml.
///
/// Called at startup (non-upgrade) so the proxy never depends on kubelet
/// volume-sync timing: the cert files are written directly from the K8s API
/// before `svc.add_tls()` is called.
pub async fn fetch_and_write(client: &Client, cert_path: &str, key_path: &str) -> Result<()> {
    let api: Api<Secret> = Api::namespaced(client.clone(), "ingress");
    let secret = api
        .get("pingora-tls")
        .await
        .context("fetching pingora-tls Secret from K8s API")?;
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
        .ok_or_else(|| anyhow::anyhow!("pingora-tls Secret has no data"))?;

    let crt = data
        .get("tls.crt")
        .ok_or_else(|| anyhow::anyhow!("pingora-tls missing tls.crt"))?;
    let key = data
        .get("tls.key")
        .ok_or_else(|| anyhow::anyhow!("pingora-tls missing tls.key"))?;

    // /etc/tls is an emptyDir; create it if the pod just started.
    if let Some(parent) = std::path::Path::new(cert_path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating cert dir {}", parent.display()))?;
    }

    std::fs::write(cert_path, &crt.0).with_context(|| format!("writing {cert_path}"))?;
    std::fs::write(key_path, &key.0).with_context(|| format!("writing {key_path}"))?;

    tracing::info!(cert_path, key_path, "cert files written from K8s Secret");
    Ok(())
}
