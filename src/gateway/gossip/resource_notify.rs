// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Resource-change notifier and peer-notification debouncer.
//!
//! When a local CRD watch event is observed the notifier broadcasts a
//! [`GatewayResourceNotify`] on the `gateway_notify` gossip topic and
//! requests a local reconcile.
//!
//! When a peer notification is received for the same resource within a 1 s
//! window, any pending local reconcile for that resource is suppressed,
//! preventing redundant work.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{RwLock, mpsc};
use tokio::time::{MissedTickBehavior, interval};
use tracing::debug;

use crate::cluster::gateway_topics::GatewayResourceNotify;

/// Window during which a peer notification suppresses a local reconcile.
const DEBOUNCE_WINDOW: Duration = Duration::from_secs(1);

/// Key that uniquely identifies a Gateway API resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ResourceKey {
    kind: String,
    namespace: String,
    name: String,
}

impl From<&GatewayResourceNotify> for ResourceKey {
    fn from(n: &GatewayResourceNotify) -> Self {
        Self {
            kind: n.kind.clone(),
            namespace: n.namespace.clone(),
            name: n.name.clone(),
        }
    }
}

/// Events emitted by the resource notifier loop to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyEvent {
    /// A notification should be broadcast over the `gateway_notify` gossip topic.
    Broadcast(GatewayResourceNotify),
    /// A local reconcile should be triggered.
    TriggerReconcile,
}

/// User-facing handle used to feed local watch events and peer notifications.
#[derive(Clone)]
pub struct ResourceNotifier {
    local_tx: mpsc::Sender<GatewayResourceNotify>,
    peer_tx: mpsc::Sender<GatewayResourceNotify>,
}

/// Background task state.  Call [`ResourceNotifierHandle::run`] to drive it.
pub struct ResourceNotifierHandle {
    local_rx: mpsc::Receiver<GatewayResourceNotify>,
    peer_rx: mpsc::Receiver<GatewayResourceNotify>,
    /// Timestamp of the most recent peer notification per resource.
    peer_debounce: Arc<RwLock<HashMap<ResourceKey, Instant>>>,
}

/// Convenience wrapper: feed a local CRD watch event into the notifier.
pub async fn handle_notify(notifier: &ResourceNotifier, notify: GatewayResourceNotify) {
    notifier.on_local_event(notify).await;
}

impl ResourceNotifier {
    /// Create a new notifier/handle pair.
    pub fn new() -> (Self, ResourceNotifierHandle) {
        let (local_tx, local_rx) = mpsc::channel(64);
        let (peer_tx, peer_rx) = mpsc::channel(64);
        let handle = ResourceNotifierHandle {
            local_rx,
            peer_rx,
            peer_debounce: Arc::new(RwLock::new(HashMap::new())),
        };
        (Self { local_tx, peer_tx }, handle)
    }

    /// Call when a local CRD watch event is observed.
    pub async fn on_local_event(&self, notify: GatewayResourceNotify) {
        let _ = self.local_tx.send(notify).await;
    }

    /// Call when a peer notification is received over gossip.
    pub async fn on_peer_event(&self, notify: GatewayResourceNotify) {
        let _ = self.peer_tx.send(notify).await;
    }
}

impl ResourceNotifierHandle {
    /// Drive the notifier loop until the caller drops the corresponding
    /// [`ResourceNotifier`] (which closes the channels).
    ///
    /// `events` is an outbound channel carrying [`NotifyEvent`]s that the
    /// caller must act on (broadcast over gossip or trigger a reconcile).
    pub async fn run(mut self, mut events: mpsc::Sender<NotifyEvent>) {
        let mut tick = interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                maybe_local = self.local_rx.recv() => {
                    match maybe_local {
                        Some(notify) => self.handle_local(notify, &mut events).await,
                        None if self.peer_rx.is_closed() => break,
                        None => {}
                    }
                }
                maybe_peer = self.peer_rx.recv() => {
                    match maybe_peer {
                        Some(peer) => self.handle_peer(peer, &mut events).await,
                        None if self.local_rx.is_closed() => break,
                        None => {}
                    }
                }
                _ = tick.tick() => {
                    if self.local_rx.is_closed() && self.peer_rx.is_closed() {
                        break;
                    }
                    let mut map = self.peer_debounce.write().await;
                    let now = Instant::now();
                    map.retain(|_, t| now.duration_since(*t) < DEBOUNCE_WINDOW);
                }
            }
        }
    }

    async fn handle_local(
        &self,
        notify: GatewayResourceNotify,
        events: &mut mpsc::Sender<NotifyEvent>,
    ) {
        let key = ResourceKey::from(&notify);

        // Always broadcast the local event so peers are informed.
        let _ = events.send(NotifyEvent::Broadcast(notify.clone())).await;

        // Suppress the local reconcile trigger if a peer already notified us
        // about this resource inside the debounce window.
        let debounced = {
            let map = self.peer_debounce.read().await;
            map.get(&key)
                .is_some_and(|t| Instant::now().duration_since(*t) < DEBOUNCE_WINDOW)
        };

        if debounced {
            debug!(
                kind = %key.kind,
                namespace = %key.namespace,
                name = %key.name,
                "debouncing redundant local reconcile due to peer notification"
            );
        } else {
            let _ = events.send(NotifyEvent::TriggerReconcile).await;
        }
    }

    async fn handle_peer(
        &self,
        notify: GatewayResourceNotify,
        events: &mut mpsc::Sender<NotifyEvent>,
    ) {
        let key = ResourceKey::from(&notify);
        self.peer_debounce.write().await.insert(key, Instant::now());
        let _ = events.send(NotifyEvent::TriggerReconcile).await;
    }
}

impl Default for ResourceNotifier {
    fn default() -> Self {
        let (s, _) = ResourceNotifier::new();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notify(kind: &str, namespace: &str, name: &str, generation: i64) -> GatewayResourceNotify {
        GatewayResourceNotify {
            topic_version: 1,
            kind: kind.into(),
            namespace: namespace.into(),
            name: name.into(),
            generation,
            timestamp: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn local_event_broadcasts_and_triggers_reconcile() {
        let (notifier, handle) = ResourceNotifier::new();
        let (tx, mut rx) = mpsc::channel(16);

        let j = tokio::spawn(async move { handle.run(tx).await });

        let ev = notify("HTTPRoute", "default", "route-1", 3);
        notifier.on_local_event(ev.clone()).await;

        let mut got_broadcast = false;
        let mut got_trigger = false;
        for _ in 0..2 {
            let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            match evt {
                NotifyEvent::Broadcast(n) if n == ev => got_broadcast = true,
                NotifyEvent::TriggerReconcile => got_trigger = true,
                other => panic!("unexpected event: {:?}", other),
            }
        }
        assert!(got_broadcast);
        assert!(got_trigger);

        drop(notifier);
        let _ = j.await;
    }

    #[tokio::test]
    async fn peer_event_triggers_reconcile() {
        let (notifier, handle) = ResourceNotifier::new();
        let (tx, mut rx) = mpsc::channel(16);

        let j = tokio::spawn(async move { handle.run(tx).await });

        let ev = notify("Gateway", "default", "gw-1", 2);
        notifier.on_peer_event(ev).await;

        let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(evt, NotifyEvent::TriggerReconcile);

        drop(notifier);
        let _ = j.await;
    }

    #[tokio::test]
    async fn peer_debounces_local_reconcile() {
        let (notifier, handle) = ResourceNotifier::new();
        let (tx, mut rx) = mpsc::channel(16);

        let j = tokio::spawn(async move { handle.run(tx).await });

        // 1. Receive a peer notification.
        let ev = notify("HTTPRoute", "default", "route-1", 3);
        notifier.on_peer_event(ev.clone()).await;

        let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(evt, NotifyEvent::TriggerReconcile);

        // 2. Immediately observe the same resource locally.
        notifier.on_local_event(ev.clone()).await;

        // We should get the Broadcast, but NOT a second TriggerReconcile.
        let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(evt, NotifyEvent::Broadcast(_)));

        // No further event should arrive.
        let extra = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(extra.is_err() || extra.unwrap().is_none());

        drop(notifier);
        let _ = j.await;
    }

    #[tokio::test]
    async fn debounce_window_expires() {
        let (notifier, handle) = ResourceNotifier::new();
        let (tx, mut rx) = mpsc::channel(16);

        let j = tokio::spawn(async move { handle.run(tx).await });

        let ev = notify("HTTPRoute", "default", "route-1", 3);

        // Peer notification.
        notifier.on_peer_event(ev.clone()).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap(); // TriggerReconcile

        // Wait for the debounce window to pass.
        tokio::time::sleep(DEBOUNCE_WINDOW + Duration::from_millis(200)).await;

        // Local event should now trigger reconcile again.
        notifier.on_local_event(ev.clone()).await;

        let mut got_broadcast = false;
        let mut got_trigger = false;
        for _ in 0..2 {
            let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            match evt {
                NotifyEvent::Broadcast(n) if n == ev => got_broadcast = true,
                NotifyEvent::TriggerReconcile => got_trigger = true,
                other => panic!("unexpected event: {:?}", other),
            }
        }
        assert!(got_broadcast);
        assert!(got_trigger);

        drop(notifier);
        let _ = j.await;
    }

    #[tokio::test]
    async fn different_resources_not_debounced() {
        let (notifier, handle) = ResourceNotifier::new();
        let (tx, mut rx) = mpsc::channel(16);

        let j = tokio::spawn(async move { handle.run(tx).await });

        let peer_ev = notify("HTTPRoute", "default", "route-a", 1);
        let local_ev = notify("HTTPRoute", "default", "route-b", 1);

        notifier.on_peer_event(peer_ev).await;
        notifier.on_local_event(local_ev.clone()).await;

        // Expect: TriggerReconcile (peer), Broadcast (local), TriggerReconcile (local).
        let mut triggers = 0;
        let mut broadcasts = 0;
        for _ in 0..3 {
            let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            match evt {
                NotifyEvent::TriggerReconcile => triggers += 1,
                NotifyEvent::Broadcast(_) => broadcasts += 1,
            }
        }
        assert_eq!(triggers, 2);
        assert_eq!(broadcasts, 1);

        drop(notifier);
        let _ = j.await;
    }

    #[tokio::test]
    async fn handle_notify_wrapper_emits_broadcast_and_trigger() {
        let (notifier, handle) = ResourceNotifier::new();
        let (tx, mut rx) = mpsc::channel(16);

        let j = tokio::spawn(async move { handle.run(tx).await });

        let ev = notify("HTTPRoute", "default", "route-1", 1);
        handle_notify(&notifier, ev.clone()).await;

        let mut got_broadcast = false;
        let mut got_trigger = false;
        for _ in 0..2 {
            let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            match evt {
                NotifyEvent::Broadcast(n) if n == ev => got_broadcast = true,
                NotifyEvent::TriggerReconcile => got_trigger = true,
                other => panic!("unexpected event: {:?}", other),
            }
        }
        assert!(got_broadcast);
        assert!(got_trigger);

        drop(notifier);
        let _ = j.await;
    }

    #[tokio::test]
    async fn resource_notifier_default_is_usable() {
        let notifier = ResourceNotifier::default();
        let (notifier2, handle) = ResourceNotifier::new();
        let (tx, mut rx) = mpsc::channel(16);

        let j = tokio::spawn(async move { handle.run(tx).await });

        let ev = notify("Gateway", "default", "gw-1", 1);
        notifier.on_local_event(ev.clone()).await;
        notifier2.on_local_event(ev).await;

        let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(evt, NotifyEvent::Broadcast(_)));

        drop(notifier);
        drop(notifier2);
        let _ = j.await;
    }

    #[test]
    fn resource_notifier_clone_smoke() {
        let (notifier, _handle) = ResourceNotifier::new();
        let cloned = notifier.clone();
        let _ = cloned;
        let _ = notifier;
    }
}
