// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Debounced digest publisher and stale-state drift detector.
//!
//! After every local reconcile the replica computes a [`RouteTableDigest`] and
//! queues it for broadcast on the `gateway_state` gossip topic.  Publishes are
//! debounced to at most one per second.
//!
//! A background loop also tracks the latest digest received from each peer.
//! If any peer digest is older than 30 s the loop emits a `ForceReconcile`
//! event and updates the `gateway_state_drift_seconds` Prometheus gauge.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, warn};

use crate::cluster::gateway_topics::GatewayStateDigest;
use crate::gateway::model::{compute_digest, ReconciledView, RouteTableDigest};

/// Minimum time between two gossip broadcasts of the local digest.
const MIN_PUBLISH_INTERVAL: Duration = Duration::from_secs(1);
/// Peer digest age that triggers a forced local reconcile.
const DRIFT_THRESHOLD_SECS: u64 = 30;

/// Events emitted by the digest publisher loop to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestEvent {
    /// A digest should be broadcast over the `gateway_state` gossip topic.
    Broadcast(GatewayStateDigest),
    /// Local state may be stale; trigger a reconcile.
    ForceReconcile,
}

/// User-facing handle used to feed the publisher with local reconciles and
/// peer digests.
#[derive(Clone)]
pub struct DigestPublisher {
    view_tx: mpsc::Sender<ReconciledView>,
    peer_tx: mpsc::Sender<GatewayStateDigest>,
}

/// Background task state.  Call [`DigestPublisherHandle::run`] to drive it.
pub struct DigestPublisherHandle {
    view_rx: mpsc::Receiver<ReconciledView>,
    peer_rx: mpsc::Receiver<GatewayStateDigest>,
    node_id: [u8; 32],
    term: u64,
    last_publish: Instant,
    /// Most recently queued digest (not yet broadcast because of debounce).
    pending: Option<GatewayStateDigest>,
    /// Map from peer node_id -> latest received digest.
    peers: Arc<RwLock<HashMap<[u8; 32], GatewayStateDigest>>>,
}

/// Convenience wrapper: feed a reconciled view into the publisher so the
/// background loop can compute and (eventually) broadcast its digest.
pub async fn publish_digest(publisher: &DigestPublisher, view: &ReconciledView) {
    publisher.on_reconcile_done(view).await;
}

impl DigestPublisher {
    /// Create a new publisher/handle pair.
    ///
    /// `node_id` is the 32-byte public key of this replica and is included in
    /// every published digest.
    pub fn new(node_id: [u8; 32]) -> (Self, DigestPublisherHandle) {
        let (view_tx, view_rx) = mpsc::channel(16);
        let (peer_tx, peer_rx) = mpsc::channel(64);
        let handle = DigestPublisherHandle {
            view_rx,
            peer_rx,
            node_id,
            term: 0,
            last_publish: Instant::now() - MIN_PUBLISH_INTERVAL,
            pending: None,
            peers: Arc::new(RwLock::new(HashMap::new())),
        };
        (Self { view_tx, peer_tx }, handle)
    }

    /// Call after a local reconcile completes.
    ///
    /// The view is cloned onto an async channel; the background loop will
    /// compute the canonical digest and queue it for broadcast.
    pub async fn on_reconcile_done(&self, view: &ReconciledView) {
        let _ = self.view_tx.send(view.clone()).await;
    }

    /// Inject a digest received from a peer.
    ///
    /// In production this will be called by the gossip receiver stub once the
    /// real iroh-gossip subscription is wired up.
    pub async fn on_peer_digest(&self, digest: GatewayStateDigest) {
        let _ = self.peer_tx.send(digest).await;
    }
}

impl DigestPublisherHandle {
    /// Drive the publisher loop until the caller drops the corresponding
    /// [`DigestPublisher`] (which closes the channels).
    ///
    /// `events` is an outbound channel carrying [`DigestEvent`]s that the
    /// caller must act on (broadcast over gossip or trigger a reconcile).
    pub async fn run(mut self, mut events: mpsc::Sender<DigestEvent>) {
        let mut tick = interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                maybe_view = self.view_rx.recv() => {
                    match maybe_view {
                        Some(view) => {
                            let digest = RouteTableDigest::from_hash(compute_digest(&view));
                            let msg = self.build_digest(digest);
                            self.pending = Some(msg);
                        }
                        None if self.peer_rx.is_closed() => break,
                        None => {}
                    }
                }
                maybe_peer = self.peer_rx.recv() => {
                    match maybe_peer {
                        Some(peer) => {
                            self.peers.write().await.insert(peer.node_id, peer);
                        }
                        None if self.view_rx.is_closed() => break,
                        None => {}
                    }
                }
                _ = tick.tick() => {
                    if self.view_rx.is_closed() && self.peer_rx.is_closed() {
                        break;
                    }
                    self.maybe_publish(&mut events).await;
                    self.check_drift(&mut events).await;
                }
            }
        }
    }

    fn build_digest(&self, digest: RouteTableDigest) -> GatewayStateDigest {
        GatewayStateDigest {
            topic_version: 1,
            state_hash: *digest.as_bytes(),
            term: 0, // filled in at publish time
            node_id: self.node_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    async fn maybe_publish(&mut self, events: &mut mpsc::Sender<DigestEvent>) {
        if self.pending.is_none() {
            return;
        }
        if Instant::now().duration_since(self.last_publish) < MIN_PUBLISH_INTERVAL {
            return;
        }
        let mut digest = self.pending.take().expect("checked above");
        self.term += 1;
        digest.term = self.term;
        debug!(term = digest.term, "debounced gateway state digest publish");
        let _ = events.send(DigestEvent::Broadcast(digest)).await;
        self.last_publish = Instant::now();
    }

    async fn check_drift(&self, events: &mut mpsc::Sender<DigestEvent>) {
        let peers = self.peers.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut max_drift = 0u64;
        for (node_id, digest) in peers.iter() {
            if *node_id == self.node_id {
                continue;
            }
            let drift = now.saturating_sub(digest.timestamp);
            max_drift = max_drift.max(drift);
            if drift > DRIFT_THRESHOLD_SECS {
                warn!(
                    peer = hex::encode(node_id),
                    drift_secs = drift,
                    "peer gateway state digest is stale, forcing reconcile"
                );
                let _ = events.send(DigestEvent::ForceReconcile).await;
            }
        }
        crate::metrics::GATEWAY_STATE_DRIFT_SECONDS.set(max_drift as f64);
    }

    /// Exposed for unit tests that want to inject fake peer state.
    #[cfg(test)]
    pub fn peers(&self) -> Arc<RwLock<HashMap<[u8; 32], GatewayStateDigest>>> {
        self.peers.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_view() -> ReconciledView {
        ReconciledView::default()
    }

    #[tokio::test]
    async fn debounce_limits_publish_rate() {
        let (publisher, handle) = DigestPublisher::new([0xab; 32]);
        let (tx, mut rx) = mpsc::channel(16);

        // Drive the loop in a background task.
        let j = tokio::spawn(async move { handle.run(tx).await });

        // Fire two reconciles back-to-back.
        let view = sample_view();
        publisher.on_reconcile_done(&view).await;
        publisher.on_reconcile_done(&view).await;

        // We should receive exactly one broadcast within the first second.
        let evt = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for broadcast")
            .expect("channel closed");
        assert!(matches!(evt, DigestEvent::Broadcast(_)));

        // No second broadcast should arrive immediately.
        let second = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
        assert!(second.is_err() || second.unwrap().is_none());

        drop(publisher);
        let _ = j.await;
    }

    #[tokio::test]
    async fn force_reconcile_on_stale_peer() {
        let (publisher, handle) = DigestPublisher::new([0xab; 32]);
        let (tx, mut rx) = mpsc::channel(16);

        // Inject a stale peer digest (>30s old).
        let stale_peer = GatewayStateDigest {
            topic_version: 1,
            state_hash: [0xcd; 32],
            term: 1,
            node_id: [0xef; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                - 35,
        };
        handle
            .peers()
            .write()
            .await
            .insert(stale_peer.node_id, stale_peer);

        let j = tokio::spawn(async move { handle.run(tx).await });

        let evt = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");
        assert_eq!(evt, DigestEvent::ForceReconcile);

        // The drift gauge should have been updated (we can't easily read the
        // global gauge in a unit test, but the code path is exercised).
        drop(publisher);
        let _ = j.await;
    }

    #[tokio::test]
    async fn drift_ignores_own_node_id() {
        let node_id = [0xab; 32];
        let (publisher, handle) = DigestPublisher::new(node_id);
        let (tx, mut rx) = mpsc::channel(16);

        // Inject a stale digest that appears to come from us.
        let own_stale = GatewayStateDigest {
            topic_version: 1,
            state_hash: [0xcd; 32],
            term: 1,
            node_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                - 100,
        };
        handle.peers().write().await.insert(node_id, own_stale);

        let j = tokio::spawn(async move { handle.run(tx).await });

        // Should NOT receive ForceReconcile because we ignore our own node_id.
        let result = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
        assert!(
            result.is_err() || result.unwrap().is_none(),
            "should not force-reconcile on own stale digest"
        );

        drop(publisher);
        let _ = j.await;
    }

    #[tokio::test]
    async fn second_publish_after_interval() {
        let (publisher, handle) = DigestPublisher::new([0xab; 32]);
        let (tx, mut rx) = mpsc::channel(16);

        let j = tokio::spawn(async move { handle.run(tx).await });

        let view = sample_view();
        publisher.on_reconcile_done(&view).await;

        // First broadcast arrives quickly.
        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(first, DigestEvent::Broadcast(_)));

        // Wait for the min interval to elapse, then reconcile again.
        tokio::time::sleep(MIN_PUBLISH_INTERVAL + Duration::from_millis(200)).await;
        publisher.on_reconcile_done(&view).await;

        let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(second, DigestEvent::Broadcast(_)));

        // Verify terms incremented.
        let first_term = match first {
            DigestEvent::Broadcast(d) => d.term,
            _ => panic!(),
        };
        let second_term = match second {
            DigestEvent::Broadcast(d) => d.term,
            _ => panic!(),
        };
        assert_eq!(second_term, first_term + 1);

        drop(publisher);
        let _ = j.await;
    }

    #[tokio::test]
    async fn publish_digest_wrapper_emits_broadcast() {
        let (publisher, handle) = DigestPublisher::new([0xab; 32]);
        let (tx, mut rx) = mpsc::channel(16);

        let j = tokio::spawn(async move { handle.run(tx).await });

        let view = sample_view();
        publish_digest(&publisher, &view).await;

        let evt = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");
        assert!(matches!(evt, DigestEvent::Broadcast(_)));

        drop(publisher);
        let _ = j.await;
    }

    #[tokio::test]
    async fn on_peer_digest_stores_peer() {
        let (publisher, handle) = DigestPublisher::new([0xab; 32]);
        let peers = handle.peers();
        let (tx, _rx) = mpsc::channel(16);
        let j = tokio::spawn(async move { handle.run(tx).await });

        let peer_digest = GatewayStateDigest {
            topic_version: 1,
            state_hash: [0xcd; 32],
            term: 7,
            node_id: [0xef; 32],
            timestamp: 1_700_000_000,
        };

        publisher.on_peer_digest(peer_digest.clone()).await;

        // Wait briefly for the background loop to insert the peer digest.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                {
                    let map = peers.read().await;
                    if map.contains_key(&[0xef; 32]) {
                        assert_eq!(map.get(&[0xef; 32]).unwrap().term, 7);
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("peer digest not stored");

        drop(publisher);
        let _ = j.await;
    }

    #[test]
    fn digest_publisher_clone_smoke() {
        let (publisher, _handle) = DigestPublisher::new([0xab; 32]);
        let cloned = publisher.clone();
        // Clone copies the channel senders; the handles remain independent.
        let _ = cloned;
        let _ = publisher;
    }
}
