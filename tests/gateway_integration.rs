// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway API integration test.
//!
//! Applies the fixtures under `tests/fixtures/gateway-integration/manifests/`
//! to a Kubernetes cluster, waits for the proxy Deployment to roll out, and
//! validates that HTTPRoutes are routed to the correct echo backends via the
//! NodePort service.
//!
//! # Running
//!
//! The test is ignored by default because it requires a live cluster. Run with:
//!
//! ```text
//! cargo test --test gateway_integration -- --ignored
//! ```
//!
//! Environment variables:
//!
//! * `KUBECONFIG` – path to kubeconfig (required)
//! * `SUNBEAM_GATEWAY_URL` – proxy NodePort URL, default `http://192.168.252.19:30080`

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

/// Directory containing the integration manifests, relative to the workspace root.
const MANIFEST_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/gateway-integration/manifests"
);

fn kubeconfig_path() -> PathBuf {
    std::env::var_os("KUBECONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/k3s.yaml"))
}

fn gateway_url() -> String {
    std::env::var("SUNBEAM_GATEWAY_URL").unwrap_or_else(|_| "http://192.168.252.19:30080".into())
}

fn kubectl(args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new("kubectl");
    cmd.env("KUBECONFIG", kubeconfig_path())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

async fn apply_manifests() {
    let mut entries: Vec<_> = std::fs::read_dir(MANIFEST_DIR)
        .expect("read manifest dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false)
        })
        .map(|e| e.path())
        .collect();
    entries.sort();

    for path in entries {
        let output = kubectl(&["apply", "-f", path.to_str().unwrap()])
            .output()
            .expect("kubectl apply");
        if !output.status.success() {
            panic!(
                "kubectl apply failed for {}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

async fn wait_for_rollout() {
    let output = kubectl(&[
        "rollout",
        "status",
        "-n",
        "gateway-conformance",
        "deployment/sunbeam-proxy",
        "--timeout=120s",
    ])
    .output()
    .expect("kubectl rollout status");
    if !output.status.success() {
        panic!(
            "rollout did not complete: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

async fn wait_for_backends() {
    for _ in 0..30 {
        let ready = kubectl(&[
            "get",
            "-n",
            "gateway-conformance",
            "pods",
            "-l",
            "app.kubernetes.io/name=infra-backend",
            "-o",
            "jsonpath={.items[*].status.phase}",
        ])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.split_whitespace().all(|phase| phase == "Running"))
        .unwrap_or(false);
        if ready {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("backend pods did not become Running");
}

#[tokio::test]
#[ignore]
async fn gateway_api_routes_traffic_to_backends() {
    apply_manifests().await;
    wait_for_backends().await;
    wait_for_rollout().await;

    let client = reqwest::Client::new();
    let base = gateway_url();

    let v1 = client
        .get(format!("{}/v1/", base))
        .header("Host", "example.com")
        .send()
        .await
        .expect("request to /v1/")
        .json::<serde_json::Value>()
        .await
        .expect("decode /v1/ response");

    assert_eq!(v1["path"], "/v1/");
    assert!(
        v1["pod"]
            .as_str()
            .unwrap_or("")
            .contains("infra-backend-v1"),
        "expected backend v1, got {:?}",
        v1["pod"]
    );

    let v2 = client
        .get(format!("{}/v2/", base))
        .header("Host", "example.com")
        .send()
        .await
        .expect("request to /v2/")
        .json::<serde_json::Value>()
        .await
        .expect("decode /v2/ response");

    assert_eq!(v2["path"], "/v2/");
    assert!(
        v2["pod"]
            .as_str()
            .unwrap_or("")
            .contains("infra-backend-v2"),
        "expected backend v2, got {:?}",
        v2["pod"]
    );
}
