// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Bandwidth.
pub mod bandwidth;
pub mod gateway_topics;
/// Messages.
pub mod messages;
/// Node.
pub mod node;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{mpsc, watch};

use crate::cluster::node::ClusterReady;
use crate::config::ClusterConfig;
use bandwidth::{
    gbps_to_bytes_per_sec, BandwidthLimiter, BandwidthMeter, BandwidthTracker,
    ClusterBandwidthState,
};

/// Clusterhandle.
pub struct ClusterHandle {
    /// Bandwidth.
    pub bandwidth: Arc<BandwidthTracker>,
    /// Cluster bandwidth.
    pub cluster_bandwidth: Arc<ClusterBandwidthState>,
    /// Sliding-window aggregate bandwidth rate across the cluster.
    pub meter: Arc<BandwidthMeter>,
    /// Cluster-wide bandwidth limiter (0 = unlimited).
    pub limiter: Arc<BandwidthLimiter>,
    /// Endpoint id.
    pub endpoint_id: iroh::PublicKey,
    /// Sender for `gateway_state` gossip broadcasts (bytes are bincode-encoded [`ClusterMessage`]).
    pub gateway_state_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Sender for `gateway_notify` gossip broadcasts (bytes are bincode-encoded [`ClusterMessage`]).
    pub gateway_notify_tx: Option<mpsc::Sender<Vec<u8>>>,
    pub(crate) shutdown_tx: watch::Sender<bool>,
}

impl ClusterHandle {
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for ClusterHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Spawn the cluster subsystem on a dedicated OS thread with its own tokio runtime.
/// Returns a handle for bandwidth recording and cluster state queries.
pub fn spawn_cluster(cfg: &ClusterConfig) -> Result<ClusterHandle> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let stale_timeout = cfg
        .bandwidth
        .as_ref()
        .map(|b| b.stale_peer_timeout_secs)
        .unwrap_or(30);

    let meter_window = cfg
        .bandwidth
        .as_ref()
        .map(|b| b.meter_window_secs)
        .unwrap_or(30);

    // Default: 1 Gbps cap. Updated at runtime via license gossip.
    let limit_bytes_per_sec = gbps_to_bytes_per_sec(1.0);

    let bandwidth = Arc::new(BandwidthTracker::new());
    let cluster_bandwidth = Arc::new(ClusterBandwidthState::new(stale_timeout));
    let meter = Arc::new(BandwidthMeter::new(meter_window));
    let limiter = Arc::new(BandwidthLimiter::new(meter.clone(), limit_bytes_per_sec));

    let bw = bandwidth.clone();
    let cbw = cluster_bandwidth.clone();
    let m = meter.clone();
    let cluster_cfg = cfg.clone();

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    std::thread::Builder::new()
        .name("cluster".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("cluster-worker")
                .build()
                .expect("cluster runtime");

            rt.block_on(node::run_cluster(
                &cluster_cfg,
                bw,
                cbw,
                m,
                shutdown_rx,
                ready_tx,
            ));
        })?;

    // Wait for the cluster to initialize (or fail).
    let ready: ClusterReady = ready_rx
        .blocking_recv()
        .map_err(|_| anyhow::anyhow!("cluster thread exited before initialization"))??;

    Ok(ClusterHandle {
        bandwidth,
        cluster_bandwidth,
        meter,
        limiter,
        endpoint_id: ready.endpoint_id,
        gateway_state_tx: Some(ready.gateway_state_tx),
        gateway_notify_tx: Some(ready.gateway_notify_tx),
        shutdown_tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BandwidthClusterConfig, DiscoveryConfig};

    fn test_cfg(key_path: &std::path::Path) -> ClusterConfig {
        ClusterConfig {
            enabled: true,
            tenant: "test-tenant".to_string(),
            gossip_port: 0,
            key_path: Some(key_path.to_str().unwrap().to_string()),
            discovery: DiscoveryConfig {
                method: "k8s".to_string(),
                headless_service: None,
                bootstrap_peers: None,
            },
            bandwidth: Some(BandwidthClusterConfig {
                broadcast_interval_secs: 1,
                stale_peer_timeout_secs: 1,
                meter_window_secs: 1,
            }),
            models: None,
        }
    }

    fn dummy_handle() -> (ClusterHandle, watch::Receiver<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let secret = iroh::SecretKey::generate(&mut rand::rng());
        let handle = ClusterHandle {
            bandwidth: Arc::new(BandwidthTracker::new()),
            cluster_bandwidth: Arc::new(ClusterBandwidthState::new(30)),
            meter: Arc::new(BandwidthMeter::new(30)),
            limiter: Arc::new(BandwidthLimiter::new(
                Arc::new(BandwidthMeter::new(30)),
                gbps_to_bytes_per_sec(1.0),
            )),
            endpoint_id: secret.public(),
            gateway_state_tx: None,
            gateway_notify_tx: None,
            shutdown_tx,
        };
        (handle, shutdown_rx)
    }

    #[test]
    fn shutdown_sends_signal() {
        let (handle, rx) = dummy_handle();
        assert_eq!(*rx.borrow(), false);
        handle.shutdown();
        assert_eq!(*rx.borrow(), true);
    }

    #[test]
    fn drop_sends_shutdown_signal() {
        let (handle, rx) = dummy_handle();
        assert_eq!(*rx.borrow(), false);
        drop(handle);
        assert_eq!(*rx.borrow(), true);
    }

    #[test]
    fn handle_fields_are_populated() {
        let (handle, _rx) = dummy_handle();
        assert_eq!(handle.bandwidth.snapshot_and_reset().request_count, 0);
        assert_eq!(
            handle
                .cluster_bandwidth
                .peer_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(handle.limiter.limit(), gbps_to_bytes_per_sec(1.0));
    }

    #[test]
    fn spawn_cluster_initializes_and_shuts_down() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("node.key");
        let handle = spawn_cluster(&test_cfg(&key_path)).unwrap();

        assert!(key_path.exists());
        assert_eq!(handle.limiter.limit(), gbps_to_bytes_per_sec(1.0));
        assert!(handle.gateway_state_tx.is_some());
        assert!(handle.gateway_notify_tx.is_some());
        assert_eq!(handle.bandwidth.snapshot_and_reset().request_count, 0);

        handle.shutdown();
    }

    #[test]
    fn spawn_cluster_with_invalid_bootstrap_peers_initializes() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("node.key");
        let mut cfg = test_cfg(&key_path);
        cfg.discovery.method = "bootstrap".to_string();
        cfg.discovery.bootstrap_peers =
            Some(vec!["not-an-id".to_string(), "missing-at-sign".to_string()]);

        let handle = spawn_cluster(&cfg).unwrap();
        assert!(handle.gateway_state_tx.is_some());
        handle.shutdown();
    }

    #[test]
    fn spawn_cluster_with_bootstrap_connection_failure_initializes() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("node.key");
        let secret = iroh::SecretKey::generate(&mut rand::rng());
        let mut cfg = test_cfg(&key_path);
        cfg.discovery.method = "bootstrap".to_string();
        // Valid format, but 127.0.0.1:1 has no listener so the pre-connect will fail.
        cfg.discovery.bootstrap_peers = Some(vec![format!("{}@127.0.0.1:1", secret.public())]);

        let handle = spawn_cluster(&cfg).unwrap();
        assert!(handle.gateway_state_tx.is_some());
        handle.shutdown();
    }

    #[test]
    fn spawn_cluster_with_unknown_discovery_initializes() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("node.key");
        let mut cfg = test_cfg(&key_path);
        cfg.discovery.method = "unknown".to_string();

        let handle = spawn_cluster(&cfg).unwrap();
        assert!(handle.gateway_state_tx.is_some());
        handle.shutdown();
    }
}
