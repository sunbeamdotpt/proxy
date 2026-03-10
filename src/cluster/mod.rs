// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

pub mod bandwidth;
pub mod messages;
pub mod node;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::watch;

use crate::config::ClusterConfig;
use bandwidth::{
    gbps_to_bytes_per_sec, BandwidthLimiter, BandwidthMeter, BandwidthTracker,
    ClusterBandwidthState,
};

pub struct ClusterHandle {
    pub bandwidth: Arc<BandwidthTracker>,
    pub cluster_bandwidth: Arc<ClusterBandwidthState>,
    /// Sliding-window aggregate bandwidth rate across the cluster.
    pub meter: Arc<BandwidthMeter>,
    /// Cluster-wide bandwidth limiter (0 = unlimited).
    pub limiter: Arc<BandwidthLimiter>,
    pub endpoint_id: iroh::PublicKey,
    shutdown_tx: watch::Sender<bool>,
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
    let endpoint_id = ready_rx
        .blocking_recv()
        .map_err(|_| anyhow::anyhow!("cluster thread exited before initialization"))??;

    Ok(ClusterHandle {
        bandwidth,
        cluster_bandwidth,
        meter,
        limiter,
        endpoint_id,
        shutdown_tx,
    })
}
