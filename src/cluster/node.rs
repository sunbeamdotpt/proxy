// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use futures::stream::{Stream, StreamExt};
use iroh::protocol::Router;
use iroh::{Endpoint, RelayMode, SecretKey};
use iroh_gossip::net::Gossip;
use iroh_gossip::{api::Event, proto::TopicId, ALPN};
use tokio::sync::{mpsc, watch};

use crate::cluster::bandwidth::{BandwidthMeter, BandwidthTracker, ClusterBandwidthState};
use crate::cluster::messages::{ClusterMessage, Payload};
use crate::config::ClusterConfig;
use crate::metrics;

/// Information sent back to [`super::spawn_cluster`] once the cluster thread
/// has finished initialization.
pub struct ClusterReady {
    pub endpoint_id: iroh::PublicKey,
    pub gateway_state_tx: mpsc::Sender<Vec<u8>>,
    pub gateway_notify_tx: mpsc::Sender<Vec<u8>>,
}

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
        let key = SecretKey::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, key.to_bytes()).context("writing node key")?;
        tracing::info!(path = %path.display(), "generated new node identity key");
        Ok(key)
    }
}

/// Parse a bootstrap peer entry of the form "endpointid@host:port".
fn parse_bootstrap_peer(entry: &str) -> Option<(iroh::PublicKey, SocketAddr)> {
    let (id_str, addr_str) = entry.split_once('@')?;
    let id = id_str.parse::<iroh::PublicKey>().ok()?;
    let addr = addr_str.parse::<SocketAddr>().ok()?;
    Some((id, addr))
}

/// Parse and pre-connect to bootstrap peers.
/// K8s mode starts with no bootstrap peers — relies on incoming connections.
/// Bootstrap mode parses "endpointid@host:port" and initiates connections.
async fn resolve_bootstrap_peers(cfg: &ClusterConfig, endpoint: &Endpoint) -> Vec<iroh::PublicKey> {
    match cfg.discovery.method.as_str() {
        "k8s" => {
            tracing::info!("k8s discovery mode: waiting for peers to connect");
            vec![]
        }
        "bootstrap" => {
            let mut peers = Vec::new();
            for entry in cfg.discovery.bootstrap_peers.as_deref().unwrap_or_default() {
                match parse_bootstrap_peer(entry) {
                    Some((id, addr)) => {
                        let node_addr =
                            iroh::EndpointAddr::from_parts(id, [iroh::TransportAddr::Ip(addr)]);
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
                        peers.push(id);
                    }
                    None => {
                        tracing::warn!(
                            entry,
                            "invalid bootstrap peer format (expected id@host:port)"
                        );
                    }
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
    ready_tx: tokio::sync::oneshot::Sender<Result<ClusterReady>>,
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

    // 2. Create iroh endpoint.
    let builder = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, cfg.gossip_port));
    let builder = try_init!(builder.context("setting iroh bind address"));
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
        .subscribe(license_topic, peers.clone())
        .await
        .context("subscribing to license topic"));
    let (_license_sender, license_receiver) = license_gossip_topic.split();

    // Gateway API gossip topics.
    let gateway_state_topic = derive_topic(&cfg.tenant, "gateway_state");
    let gateway_notify_topic = derive_topic(&cfg.tenant, "gateway_notify");

    let gs_gossip_topic = try_init!(gossip
        .subscribe(gateway_state_topic, peers.clone())
        .await
        .context("subscribing to gateway_state topic"));
    let (gs_sender, gs_receiver) = gs_gossip_topic.split();

    let gn_gossip_topic = try_init!(gossip
        .subscribe(gateway_notify_topic, peers)
        .await
        .context("subscribing to gateway_notify topic"));
    let (gn_sender, gn_receiver) = gn_gossip_topic.split();

    let (gateway_state_tx, mut gateway_state_rx) = mpsc::channel::<Vec<u8>>(64);
    let (gateway_notify_tx, mut gateway_notify_rx) = mpsc::channel::<Vec<u8>>(64);

    // Initialization complete — signal the caller.
    let _ = ready_tx.send(Ok(ClusterReady {
        endpoint_id: my_id,
        gateway_state_tx,
        gateway_notify_tx,
    }));

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

    // 11a. Gateway state broadcast loop (driven by leader.rs digest publisher).
    let _my_id_gs = my_id_bytes;
    let gs_broadcast_task = tokio::spawn(async move {
        while let Some(data) = gateway_state_rx.recv().await {
            if let Err(e) = gs_sender.broadcast(data.into()).await {
                tracing::debug!(error = %e, "gateway_state broadcast failed");
            }
            metrics::CLUSTER_GOSSIP_MESSAGES
                .with_label_values(&["gateway_state"])
                .inc();
        }
    });

    // 11b. Gateway notify broadcast loop (driven by leader.rs resource notifier).
    let gn_broadcast_task = tokio::spawn(async move {
        while let Some(data) = gateway_notify_rx.recv().await {
            if let Err(e) = gn_sender.broadcast(data.into()).await {
                tracing::debug!(error = %e, "gateway_notify broadcast failed");
            }
            metrics::CLUSTER_GOSSIP_MESSAGES
                .with_label_values(&["gateway_notify"])
                .inc();
        }
    });

    // 11c. Gateway state receive loop (stub — logged for now).
    let gs_recv_task = tokio::spawn(handle_stub_events(gs_receiver, "gateway_state"));

    // 11d. Gateway notify receive loop (stub — logged for now).
    let gn_recv_task = tokio::spawn(handle_stub_events(gn_receiver, "gateway_notify"));

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
        r = gs_broadcast_task => {
            tracing::error!(result = ?r, "gateway_state broadcast task exited");
        }
        r = gn_broadcast_task => {
            tracing::error!(result = ?r, "gateway_notify broadcast task exited");
        }
        r = gs_recv_task => {
            tracing::error!(result = ?r, "gateway_state receive task exited");
        }
        r = gn_recv_task => {
            tracing::error!(result = ?r, "gateway_notify receive task exited");
        }
    }

    if let Err(e) = router.shutdown().await {
        tracing::error!(error = %e, "router shutdown failed");
    }
}

/// Apply a decoded cluster message to bandwidth state if it is a bandwidth report.
/// Returns true when the payload was a [`Payload::BandwidthReport`].
fn apply_bandwidth_message(
    msg: &ClusterMessage,
    cluster_bw: &ClusterBandwidthState,
    meter: &BandwidthMeter,
) -> bool {
    if let Payload::BandwidthReport {
        cumulative_in,
        cumulative_out,
        bytes_in,
        bytes_out,
        ..
    } = &msg.payload
    {
        cluster_bw.update_peer(msg.sender, *cumulative_in, *cumulative_out);
        // Feed remote peer's delta into the sliding window meter.
        meter.record_sample(*bytes_in, *bytes_out);
        true
    } else {
        false
    }
}

async fn handle_bandwidth_events<S, E>(
    mut receiver: S,
    cluster_bw: Arc<ClusterBandwidthState>,
    meter: Arc<BandwidthMeter>,
) where
    S: Stream<Item = Result<Event, E>> + Unpin,
{
    while let Some(Ok(event)) = receiver.next().await {
        if let Event::Received(message) = event {
            match ClusterMessage::decode(&message.content) {
                Ok(msg) => {
                    if apply_bandwidth_message(&msg, &cluster_bw, &meter) {
                        metrics::CLUSTER_GOSSIP_MESSAGES
                            .with_label_values(&["bandwidth"])
                            .inc();
                        if let Payload::BandwidthReport {
                            bytes_in,
                            bytes_out,
                            request_count,
                            ..
                        } = &msg.payload
                        {
                            tracing::debug!(
                                sender = hex::encode(msg.sender),
                                bytes_in,
                                bytes_out,
                                request_count,
                                "received bandwidth report"
                            );
                        }
                    } else {
                        tracing::debug!("unexpected payload on bandwidth topic");
                    }
                }
                Err(e) => tracing::debug!(error = %e, "failed to decode bandwidth message"),
            }
        }
    }
}

/// Apply a decoded model message (logging/metrics only — model distribution is stubbed).
fn apply_model_message(msg: &ClusterMessage) {
    match &msg.payload {
        Payload::ModelAnnounce {
            model_type,
            hash,
            total_size,
            ..
        } => {
            tracing::info!(
                model_type,
                hash = hex::encode(hash),
                total_size,
                "received model announce (stub — ignoring)"
            );
            metrics::CLUSTER_MODEL_UPDATES
                .with_label_values(&[model_type, "ignored"])
                .inc();
        }
        Payload::ModelChunk {
            hash, chunk_index, ..
        } => {
            tracing::debug!(
                hash = hex::encode(hash),
                chunk_index,
                "received model chunk (stub — ignoring)"
            );
        }
        _ => {}
    }
}

async fn handle_model_events<S, E>(mut receiver: S)
where
    S: Stream<Item = Result<Event, E>> + Unpin,
{
    while let Some(Ok(event)) = receiver.next().await {
        if let Event::Received(message) = event {
            match ClusterMessage::decode(&message.content) {
                Ok(msg) => apply_model_message(&msg),
                Err(e) => tracing::debug!(error = %e, "failed to decode model message"),
            }
        }
    }
}

/// Apply a decoded stub message for the given gossip channel.
fn apply_stub_message(msg: &ClusterMessage, channel: &str) {
    tracing::debug!(?msg, channel, "received stub message");
    metrics::CLUSTER_GOSSIP_MESSAGES
        .with_label_values(&[channel])
        .inc();
}

async fn handle_stub_events<S, E>(mut receiver: S, channel: &str)
where
    S: Stream<Item = Result<Event, E>> + Unpin,
{
    while let Some(Ok(event)) = receiver.next().await {
        if let Event::Received(message) = event
            && let Ok(msg) = ClusterMessage::decode(&message.content) {
                apply_stub_message(&msg, channel);
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::atomic::Ordering;

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

    #[test]
    fn load_or_generate_key_loads_existing_key() {
        let key = SecretKey::generate();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&key.to_bytes()).unwrap();
        let loaded = load_or_generate_key(tmp.path()).unwrap();
        assert_eq!(loaded.to_bytes(), key.to_bytes());
    }

    #[test]
    fn load_or_generate_key_generates_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        assert!(!path.exists());
        let key = load_or_generate_key(&path).unwrap();
        assert!(path.exists());
        let loaded = load_or_generate_key(&path).unwrap();
        assert_eq!(loaded.to_bytes(), key.to_bytes());
    }

    #[test]
    fn load_or_generate_key_rejects_bad_length() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"short").unwrap();
        assert!(load_or_generate_key(tmp.path()).is_err());
    }

    #[test]
    fn parse_bootstrap_peer_valid() {
        let secret = SecretKey::generate();
        let id = secret.public();
        let entry = format!("{}@127.0.0.1:11204", id);
        let (parsed_id, addr) = parse_bootstrap_peer(&entry).unwrap();
        assert_eq!(parsed_id, id);
        assert_eq!(
            addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 11204))
        );
    }

    #[test]
    fn parse_bootstrap_peer_missing_at_sign() {
        assert!(parse_bootstrap_peer("127.0.0.1:11204").is_none());
    }

    #[test]
    fn parse_bootstrap_peer_invalid_id() {
        assert!(parse_bootstrap_peer("not-an-id@127.0.0.1:11204").is_none());
    }

    #[test]
    fn parse_bootstrap_peer_invalid_addr() {
        let secret = SecretKey::generate();
        let id = secret.public();
        assert!(parse_bootstrap_peer(&format!("{}@bad-addr", id)).is_none());
    }

    #[test]
    fn apply_bandwidth_message_updates_state() {
        let cluster_bw = Arc::new(ClusterBandwidthState::new(30));
        let meter = Arc::new(BandwidthMeter::new(30));
        let msg = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::BandwidthReport {
                timestamp: 1,
                bytes_in: 100,
                bytes_out: 200,
                request_count: 5,
                cumulative_in: 1000,
                cumulative_out: 2000,
            },
        };
        assert!(apply_bandwidth_message(&msg, &cluster_bw, &meter));
        assert_eq!(cluster_bw.total_bytes_in.load(Ordering::Relaxed), 1000);
        assert_eq!(cluster_bw.total_bytes_out.load(Ordering::Relaxed), 2000);
        assert_eq!(cluster_bw.peer_count.load(Ordering::Relaxed), 1);
        let rate = meter.aggregate_rate();
        assert_eq!(rate.sample_count, 1);
    }

    #[test]
    fn apply_bandwidth_message_ignores_other_payloads() {
        let cluster_bw = Arc::new(ClusterBandwidthState::new(30));
        let meter = Arc::new(BandwidthMeter::new(30));
        let msg = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::LeaderHeartbeat {
                term: 1,
                leader_id: [2u8; 32],
            },
        };
        assert!(!apply_bandwidth_message(&msg, &cluster_bw, &meter));
        assert_eq!(cluster_bw.peer_count.load(Ordering::Relaxed), 0);
        assert_eq!(meter.aggregate_rate().sample_count, 0);
    }

    #[test]
    fn apply_model_message_handles_announce_and_chunk() {
        let announce = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::ModelAnnounce {
                model_type: "scanner".to_string(),
                hash: [0xAA; 32],
                total_size: 1_000_000,
                chunk_count: 16,
            },
        };
        // Should not panic and should exercise metric/logging paths.
        apply_model_message(&announce);

        let chunk = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::ModelChunk {
                hash: [0xBB; 32],
                chunk_index: 7,
                data: vec![1, 2, 3],
            },
        };
        apply_model_message(&chunk);

        let ignored = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::LeaderHeartbeat {
                term: 1,
                leader_id: [2u8; 32],
            },
        };
        apply_model_message(&ignored);
    }

    #[test]
    fn apply_stub_message_does_not_panic() {
        let msg = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::LeaderHeartbeat {
                term: 1,
                leader_id: [2u8; 32],
            },
        };
        apply_stub_message(&msg, "leader");
    }

    #[test]
    fn load_or_generate_key_creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("deep").join("node.key");
        assert!(!nested.parent().unwrap().exists());
        let key = load_or_generate_key(&nested).unwrap();
        assert!(nested.exists());
        let loaded = load_or_generate_key(&nested).unwrap();
        assert_eq!(loaded.to_bytes(), key.to_bytes());
    }

    #[tokio::test]
    async fn handle_bandwidth_events_processes_reports() {
        use bytes::Bytes;
        use futures::stream;
        use iroh_gossip::api::{Event, Message};
        use iroh_gossip::proto::DeliveryScope;

        let report = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::BandwidthReport {
                timestamp: 1,
                bytes_in: 100,
                bytes_out: 200,
                request_count: 5,
                cumulative_in: 1000,
                cumulative_out: 2000,
            },
        };
        let event = Event::Received(Message {
            content: Bytes::from(report.encode().unwrap()),
            scope: DeliveryScope::Neighbors,
            delivered_from: SecretKey::generate().public(),
        });

        let cluster_bw = Arc::new(ClusterBandwidthState::new(30));
        let meter = Arc::new(BandwidthMeter::new(30));
        handle_bandwidth_events(
            stream::iter(vec![Ok::<Event, std::convert::Infallible>(event)]),
            cluster_bw.clone(),
            meter,
        )
        .await;

        assert_eq!(cluster_bw.total_bytes_in.load(Ordering::Relaxed), 1000);
        assert_eq!(cluster_bw.peer_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn handle_model_events_processes_announce_and_chunk() {
        use bytes::Bytes;
        use futures::stream;
        use iroh_gossip::api::{Event, Message};
        use iroh_gossip::proto::DeliveryScope;

        let announce = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::ModelAnnounce {
                model_type: "scanner".to_string(),
                hash: [0xAA; 32],
                total_size: 1_000_000,
                chunk_count: 16,
            },
        };
        let chunk = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::ModelChunk {
                hash: [0xBB; 32],
                chunk_index: 3,
                data: vec![1, 2, 3],
            },
        };

        let events = stream::iter(vec![
            Ok::<Event, std::convert::Infallible>(Event::Received(Message {
                content: Bytes::from(announce.encode().unwrap()),
                scope: DeliveryScope::Neighbors,
                delivered_from: SecretKey::generate().public(),
            })),
            Ok::<Event, std::convert::Infallible>(Event::Received(Message {
                content: Bytes::from(chunk.encode().unwrap()),
                scope: DeliveryScope::Neighbors,
                delivered_from: SecretKey::generate().public(),
            })),
        ]);

        handle_model_events(events).await;
    }

    #[tokio::test]
    async fn handle_stub_events_processes_messages() {
        use bytes::Bytes;
        use futures::stream;
        use iroh_gossip::api::{Event, Message};
        use iroh_gossip::proto::DeliveryScope;

        let msg = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::LeaderHeartbeat {
                term: 1,
                leader_id: [2u8; 32],
            },
        };
        let event = Event::Received(Message {
            content: Bytes::from(msg.encode().unwrap()),
            scope: DeliveryScope::Neighbors,
            delivered_from: SecretKey::generate().public(),
        });

        handle_stub_events(
            stream::iter(vec![Ok::<Event, std::convert::Infallible>(event)]),
            "leader",
        )
        .await;
    }
}
