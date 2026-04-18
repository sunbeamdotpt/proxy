// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use futures::stream::StreamExt;
use iroh::protocol::Router;
use iroh::{Endpoint, RelayMode, SecretKey};
use iroh_gossip::net::Gossip;
use iroh_gossip::{api::Event, proto::TopicId, ALPN};
use tokio::sync::watch;

use crate::cluster::bandwidth::{BandwidthMeter, BandwidthTracker, ClusterBandwidthState};
use crate::cluster::messages::{ClusterMessage, Payload};
use crate::config::ClusterConfig;
use crate::metrics;

/// Derive a deterministic TopicId from tenant UUID and channel name.
pub fn derive_topic(tenant: &str, channel: &str) -> TopicId {
    let input = format!("/sunbeam-proxy/1.0/{tenant}/{channel}");
    let hash = blake3::hash(input.as_bytes());
    TopicId::from_bytes(*hash.as_bytes())
}

/// Load or generate a persistent ed25519 identity key.
fn load_or_generate_key(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let data = std::fs::read(path).context("reading node key")?;
        let bytes: [u8; 32] = data
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid key file length"))?;
        Ok(SecretKey::from_bytes(&bytes))
    } else {
        let key = SecretKey::generate(&mut rand::rng());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, key.to_bytes()).context("writing node key")?;
        tracing::info!(path = %path.display(), "generated new node identity key");
        Ok(key)
    }
}

/// Parse and pre-connect to bootstrap peers.
/// K8s mode starts with no bootstrap peers — relies on incoming connections.
/// Bootstrap mode parses "endpointid@host:port" and initiates connections.
async fn resolve_bootstrap_peers(
    cfg: &ClusterConfig,
    endpoint: &Endpoint,
) -> Vec<iroh::PublicKey> {
    match cfg.discovery.method.as_str() {
        "k8s" => {
            tracing::info!("k8s discovery mode: waiting for peers to connect");
            vec![]
        }
        "bootstrap" => {
            let mut peers = Vec::new();
            for entry in cfg
                .discovery
                .bootstrap_peers
                .as_deref()
                .unwrap_or_default()
            {
                if let Some((id_str, addr_str)) = entry.split_once('@') {
                    match id_str.parse::<iroh::PublicKey>() {
                        Ok(id) => {
                            if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                                let node_addr = iroh::EndpointAddr::from_parts(
                                    id,
                                    [iroh::TransportAddr::Ip(addr)],
                                );
                                // Pre-connect so the gossip layer can reach this peer.
                                match endpoint.connect(node_addr, ALPN).await {
                                    Ok(conn) => {
                                        tracing::info!(peer = %id, addr = %addr, "connected to bootstrap peer");
                                        // Drop the connection — gossip will reuse the underlying QUIC path.
                                        drop(conn);
                                    }
                                    Err(e) => {
                                        tracing::warn!(peer = %id, addr = %addr, error = %e, "failed to connect to bootstrap peer");
                                    }
                                }
                            }
                            peers.push(id);
                        }
                        Err(e) => {
                            tracing::warn!(entry, error = %e, "invalid bootstrap peer id");
                        }
                    }
                } else {
                    tracing::warn!(entry, "invalid bootstrap peer format (expected id@host:port)");
                }
            }
            peers
        }
        other => {
            tracing::warn!(method = other, "unknown discovery method");
            vec![]
        }
    }
}

/// Run the cluster node. Called from a dedicated OS thread with its own tokio runtime.
/// Sends the endpoint ID through `ready_tx` once initialization is complete,
/// then runs event loops until shutdown.
pub async fn run_cluster(
    cfg: &ClusterConfig,
    bandwidth: Arc<BandwidthTracker>,
    cluster_bandwidth: Arc<ClusterBandwidthState>,
    meter: Arc<BandwidthMeter>,
    mut shutdown_rx: watch::Receiver<bool>,
    ready_tx: tokio::sync::oneshot::Sender<Result<iroh::PublicKey>>,
) {
    // Helper macro to send error through ready channel and return early.
    macro_rules! try_init {
        ($expr:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => {
                    let _ = ready_tx.send(Err(e.into()));
                    return;
                }
            }
        };
    }

    // 1. Load or generate identity.
    let key_path = cfg
        .key_path
        .as_deref()
        .unwrap_or("/var/lib/sunbeam/node.key");
    let secret_key = try_init!(load_or_generate_key(Path::new(key_path)));

    // 2. Create iroh endpoint. iroh 0.95 split bind_addr into bind_addr_v4/v6.
    let builder = Endpoint::builder()
        .secret_key(secret_key)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, cfg.gossip_port));
    let endpoint = try_init!(builder.bind().await.context("binding iroh endpoint"));

    let my_id = endpoint.id();
    let my_id_bytes: [u8; 32] = *my_id.as_bytes();
    tracing::info!(endpoint_id = %my_id, port = cfg.gossip_port, "cluster node started");

    // 3. Create gossip instance and router.
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, gossip.clone())
        .spawn();

    // 4. Resolve bootstrap peers.
    let peers = resolve_bootstrap_peers(cfg, &endpoint).await;

    // 5. Derive topics.
    let bandwidth_topic = derive_topic(&cfg.tenant, "bandwidth");
    let models_topic = derive_topic(&cfg.tenant, "models");
    let leader_topic = derive_topic(&cfg.tenant, "leader");
    let license_topic = derive_topic(&cfg.tenant, "license");

    tracing::info!(
        tenant = %cfg.tenant,
        bandwidth_topic = ?bandwidth_topic,
        "subscribing to gossip topics"
    );

    // 6. Subscribe to topics.
    let bw_gossip_topic = try_init!(gossip
        .subscribe(bandwidth_topic, peers.clone())
        .await
        .context("subscribing to bandwidth topic"));
    let (bw_sender, bw_receiver) = bw_gossip_topic.split();

    let models_gossip_topic = try_init!(gossip
        .subscribe(models_topic, peers.clone())
        .await
        .context("subscribing to models topic"));
    let (_models_sender, models_receiver) = models_gossip_topic.split();

    let leader_gossip_topic = try_init!(gossip
        .subscribe(leader_topic, peers.clone())
        .await
        .context("subscribing to leader topic"));
    let (_leader_sender, leader_receiver) = leader_gossip_topic.split();

    let license_gossip_topic = try_init!(gossip
        .subscribe(license_topic, peers)
        .await
        .context("subscribing to license topic"));
    let (_license_sender, license_receiver) = license_gossip_topic.split();

    // Initialization complete — signal the caller with our endpoint ID.
    let _ = ready_tx.send(Ok(my_id));

    let broadcast_interval = Duration::from_secs(
        cfg.bandwidth
            .as_ref()
            .map(|b| b.broadcast_interval_secs)
            .unwrap_or(5),
    );
    let stale_timeout = Duration::from_secs(
        cfg.bandwidth
            .as_ref()
            .map(|b| b.stale_peer_timeout_secs)
            .unwrap_or(30),
    );

    // 7. Bandwidth broadcast loop.
    let bw_tracker = bandwidth.clone();
    let bw_sender_clone = bw_sender.clone();
    let meter_broadcast = meter.clone();
    let my_id_bw = my_id_bytes;
    let broadcast_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(broadcast_interval);
        loop {
            interval.tick().await;
            let snap = bw_tracker.snapshot_and_reset();
            // Feed local node's delta into the sliding window meter.
            meter_broadcast.record_sample(snap.bytes_in, snap.bytes_out);
            let msg = ClusterMessage {
                version: 1,
                sender: my_id_bw,
                payload: Payload::BandwidthReport {
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    bytes_in: snap.bytes_in,
                    bytes_out: snap.bytes_out,
                    request_count: snap.request_count,
                    cumulative_in: snap.cumulative_in,
                    cumulative_out: snap.cumulative_out,
                },
            };
            match msg.encode() {
                Ok(data) => {
                    if let Err(e) = bw_sender_clone.broadcast(data.into()).await {
                        tracing::debug!(error = %e, "bandwidth broadcast failed");
                    }
                    metrics::CLUSTER_GOSSIP_MESSAGES
                        .with_label_values(&["bandwidth"])
                        .inc();
                }
                Err(e) => tracing::warn!(error = %e, "failed to encode bandwidth report"),
            }
        }
    });

    // 8. Bandwidth receive loop.
    let cluster_bw = cluster_bandwidth.clone();
    let meter_recv = meter.clone();
    let bw_recv_task = tokio::spawn(handle_bandwidth_events(bw_receiver, cluster_bw, meter_recv));

    // 9. Model receive loop (stub).
    let models_recv_task = tokio::spawn(handle_model_events(models_receiver));

    // 10. Leader topic (stub).
    let leader_recv_task = tokio::spawn(handle_stub_events(leader_receiver, "leader"));

    // 11. License topic (stub).
    let license_recv_task = tokio::spawn(handle_stub_events(license_receiver, "license"));

    // 12. Stale peer eviction loop.
    let cluster_bw_evict = cluster_bandwidth.clone();
    let eviction_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(stale_timeout);
        loop {
            interval.tick().await;
            cluster_bw_evict.evict_stale();
        }
    });

    // 13. Aggregate rate metrics updater (every broadcast interval).
    let meter_metrics = meter;
    let metrics_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(broadcast_interval);
        loop {
            interval.tick().await;
            let rate = meter_metrics.aggregate_rate();
            metrics::CLUSTER_AGGREGATE_IN_RATE.set(rate.bytes_in_per_sec);
            metrics::CLUSTER_AGGREGATE_OUT_RATE.set(rate.bytes_out_per_sec);
            metrics::CLUSTER_AGGREGATE_TOTAL_RATE.set(rate.total_per_sec);
        }
    });

    // Wait for shutdown or task failure.
    tokio::select! {
        _ = shutdown_rx.changed() => {
            tracing::info!("cluster shutdown signal received");
        }
        r = broadcast_task => {
            tracing::error!(result = ?r, "bandwidth broadcast task exited");
        }
        r = bw_recv_task => {
            tracing::error!(result = ?r, "bandwidth receive task exited");
        }
        r = models_recv_task => {
            tracing::error!(result = ?r, "model receive task exited");
        }
        r = leader_recv_task => {
            tracing::error!(result = ?r, "leader receive task exited");
        }
        r = license_recv_task => {
            tracing::error!(result = ?r, "license receive task exited");
        }
        r = eviction_task => {
            tracing::error!(result = ?r, "eviction task exited");
        }
        r = metrics_task => {
            tracing::error!(result = ?r, "metrics task exited");
        }
    }

    if let Err(e) = router.shutdown().await {
        tracing::error!(error = %e, "router shutdown failed");
    }
}

async fn handle_bandwidth_events(
    mut receiver: iroh_gossip::api::GossipReceiver,
    cluster_bw: Arc<ClusterBandwidthState>,
    meter: Arc<BandwidthMeter>,
) {
    while let Some(Ok(event)) = receiver.next().await {
        if let Event::Received(message) = event {
            match ClusterMessage::decode(&message.content) {
                Ok(ClusterMessage {
                    sender,
                    payload:
                        Payload::BandwidthReport {
                            cumulative_in,
                            cumulative_out,
                            bytes_in,
                            bytes_out,
                            request_count,
                            ..
                        },
                    ..
                }) => {
                    cluster_bw.update_peer(sender, cumulative_in, cumulative_out);
                    // Feed remote peer's delta into the sliding window meter.
                    meter.record_sample(bytes_in, bytes_out);
                    metrics::CLUSTER_GOSSIP_MESSAGES
                        .with_label_values(&["bandwidth"])
                        .inc();
                    tracing::debug!(
                        sender = hex::encode(sender),
                        bytes_in,
                        bytes_out,
                        request_count,
                        "received bandwidth report"
                    );
                }
                Ok(_) => tracing::debug!("unexpected payload on bandwidth topic"),
                Err(e) => tracing::debug!(error = %e, "failed to decode bandwidth message"),
            }
        }
    }
}

async fn handle_model_events(mut receiver: iroh_gossip::api::GossipReceiver) {
    while let Some(Ok(event)) = receiver.next().await {
        if let Event::Received(message) = event {
            match ClusterMessage::decode(&message.content) {
                Ok(ClusterMessage {
                    payload: Payload::ModelAnnounce { model_type, hash, total_size, .. },
                    ..
                }) => {
                    tracing::info!(
                        model_type,
                        hash = hex::encode(hash),
                        total_size,
                        "received model announce (stub — ignoring)"
                    );
                    metrics::CLUSTER_MODEL_UPDATES
                        .with_label_values(&[&model_type, "ignored"])
                        .inc();
                }
                Ok(ClusterMessage {
                    payload: Payload::ModelChunk { hash, chunk_index, .. },
                    ..
                }) => {
                    tracing::debug!(
                        hash = hex::encode(hash),
                        chunk_index,
                        "received model chunk (stub — ignoring)"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "failed to decode model message"),
            }
        }
    }
}

async fn handle_stub_events(mut receiver: iroh_gossip::api::GossipReceiver, channel: &str) {
    while let Some(Ok(event)) = receiver.next().await {
        if let Event::Received(message) = event {
            if let Ok(msg) = ClusterMessage::decode(&message.content) {
                tracing::debug!(?msg, channel, "received stub message");
                metrics::CLUSTER_GOSSIP_MESSAGES
                    .with_label_values(&[channel])
                    .inc();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_derivation_deterministic() {
        let t1 = derive_topic("550e8400-e29b-41d4-a716-446655440000", "bandwidth");
        let t2 = derive_topic("550e8400-e29b-41d4-a716-446655440000", "bandwidth");
        assert_eq!(t1, t2);
    }

    #[test]
    fn topic_derivation_different_channels() {
        let bw = derive_topic("550e8400-e29b-41d4-a716-446655440000", "bandwidth");
        let models = derive_topic("550e8400-e29b-41d4-a716-446655440000", "models");
        assert_ne!(bw, models);
    }

    #[test]
    fn topic_derivation_different_tenants() {
        let t1 = derive_topic("550e8400-e29b-41d4-a716-446655440000", "bandwidth");
        let t2 = derive_topic("660e8400-e29b-41d4-a716-446655440001", "bandwidth");
        assert_ne!(t1, t2);
    }
}
