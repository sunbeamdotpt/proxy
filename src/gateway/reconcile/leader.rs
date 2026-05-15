// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Leadership-aware reconcile loop.
//!
//! Spawns the per-resource controllers and periodically attempts to
//! obtain a [`LeaderToken`].  Only the leader writes status; standby
//! replicas still reconcile (computing the local view and digest) but
//! skip status writeback.
//!
//! Also wires the [`DigestPublisher`] and [`ResourceNotifier`] so that
//! every local reconcile produces a gossip digest and resource-change
//! notifications are broadcast to peers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;
use tokio::time::{interval, MissedTickBehavior};

use crate::cluster::gateway_topics::GatewayResourceNotify;
use crate::cluster::messages::{ClusterMessage, Payload};
use crate::cluster::ClusterHandle;
use crate::config::RouteConfig;
use crate::gateway::api::Gateway;
use crate::gateway::election::{Election, LeaderState};
use crate::gateway::gossip::digest_publisher::{DigestEvent, DigestPublisher, publish_digest};
use crate::gateway::gossip::resource_notify::{NotifyEvent, ResourceNotifier, handle_notify};
use crate::gateway::model::ReconciledView;
use crate::gateway::reconcile::gateway::run_gateway_controller;
use crate::gateway::reconcile::gatewayclass::run_gatewayclass_controller;
use crate::gateway::reconcile::httproute::run_httproute_controller;
use crate::gateway::reconcile::reconcile_tick;
use crate::gateway::translate::translate_view;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;

/// Run the full reconcile loop.
///
/// * Spawns `GatewayClass` and `Gateway` controllers with a shared
///   leadership flag derived from the [`Election`].
/// * Periodically tries to acquire a [`LeaderToken`] so that status
///   writeback is only performed by the leader.
/// * Standby replicas continue to run controllers (building the local
///   model) but do not patch status.
/// * Sends translated `RouteConfig`s to the proxy via `routes_tx`.
/// * When `cluster_handle` is provided, broadcasts gateway digests and
///   resource notifications over the cluster gossip topics.
pub async fn run_reconcile_loop(
    election: Election,
    client: Client,
    routes_tx: Sender<Vec<RouteConfig>>,
    cluster_handle: Option<Arc<ClusterHandle>>,
) {
    let is_leader = Arc::new(AtomicBool::new(election.state() == LeaderState::Leader));

    // Spawn controllers.  They check `is_leader` before patching status.
    let _gc_handle = run_gatewayclass_controller(client.clone(), is_leader.clone());
    let _gw_handle = run_gateway_controller(client.clone(), is_leader.clone());
    let _hr_handle = run_httproute_controller(client.clone(), is_leader.clone());

    // -- Digest publisher & resource notifier --------------------------------
    let node_id = cluster_handle
        .as_ref()
        .map(|c| *c.endpoint_id.as_bytes())
        .unwrap_or([0u8; 32]);

    let (digest_publisher, digest_handle) = DigestPublisher::new(node_id);
    let (resource_notifier, notify_handle) = ResourceNotifier::new();

    let (digest_events_tx, mut digest_events_rx) = tokio::sync::mpsc::channel::<DigestEvent>(16);
    let (notify_events_tx, mut notify_events_rx) = tokio::sync::mpsc::channel::<NotifyEvent>(64);

    let cluster_for_digest = cluster_handle.clone();
    tokio::spawn(async move {
        digest_handle.run(digest_events_tx).await;
    });

    let cluster_for_notify = cluster_handle.clone();
    tokio::spawn(async move {
        notify_handle.run(notify_events_tx).await;
    });

    // Task that forwards broadcast events onto the cluster gossip topics.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(evt) = digest_events_rx.recv() => {
                    match evt {
                        DigestEvent::Broadcast(digest) => {
                            if let Some(ref ch) = cluster_for_digest {
                                if let Some(ref tx) = ch.gateway_state_tx {
                                    let msg = ClusterMessage {
                                        version: 1,
                                        sender: node_id,
                                        payload: Payload::GatewayStateDigest(digest),
                                    };
                                    if let Ok(data) = msg.encode() {
                                        let _ = tx.try_send(data);
                                    }
                                }
                            }
                        }
                        DigestEvent::ForceReconcile => {
                            // Handled by the main loop via `force_notify`.
                        }
                    }
                }
                Some(evt) = notify_events_rx.recv() => {
                    match evt {
                        NotifyEvent::Broadcast(notify) => {
                            if let Some(ref ch) = cluster_for_notify {
                                if let Some(ref tx) = ch.gateway_notify_tx {
                                    let msg = ClusterMessage {
                                        version: 1,
                                        sender: node_id,
                                        payload: Payload::GatewayResourceNotify(notify),
                                    };
                                    if let Ok(data) = msg.encode() {
                                        let _ = tx.try_send(data);
                                    }
                                }
                            }
                        }
                        NotifyEvent::TriggerReconcile => {
                            // Handled by the main loop via `force_notify`.
                        }
                    }
                }
                else => break,
            }
        }
    });

    // -- Main reconcile loop -------------------------------------------------
    let mut token: Option<crate::gateway::election::LeaderToken> = None;
    let mut tick = interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let force_notify = Arc::new(Notify::new());
    let mut prev_view: Option<ReconciledView> = None;

    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = force_notify.notified() => {
                tracing::debug!("forced reconcile triggered by gossip event");
            }
        }

        let state = election.state();

        // State machine: acquire / release token on transitions.
        match (state, token.is_some()) {
            (LeaderState::Leader, false) => {
                token = election.token();
                if token.is_some() {
                    is_leader.store(true, Ordering::Relaxed);
                    tracing::info!("Became leader — status writeback enabled");
                }
            }
            (LeaderState::NotLeader, true) => {
                token = None;
                is_leader.store(false, Ordering::Relaxed);
                tracing::info!("Lost leadership — status writeback disabled");
            }
            _ => {}
        }

        // If we hold a token but the background lease task invalidated it,
        // drop it and update the flag immediately.
        if let Some(ref t) = token {
            if !t.is_leader() {
                token = None;
                is_leader.store(false, Ordering::Relaxed);
                tracing::info!("LeaderToken invalidated — status writeback disabled");
            }
        }

        // Full reconcile tick: fetch, translate, and send to proxy.
        if let Some(view) = reconcile_tick(&client).await {
            let routes = translate_view(&view);
            if !routes.is_empty() {
                let _ = routes_tx.send(routes);
            }

            // Publish digest for cross-replica validation.
            publish_digest(&digest_publisher, &view).await;

            // Emit resource notifications for anything that changed.
            for notify in diff_view(&prev_view, &view) {
                handle_notify(&resource_notifier, notify).await;
            }
            prev_view = Some(view.clone());

            // Update Gateway Programmed status when leader.
            if is_leader.load(Ordering::Relaxed) {
                for gw in &view.gateways {
                    let programmed = serde_json::json!({
                        "apiVersion": "gateway.networking.k8s.io/v1",
                        "kind": "Gateway",
                        "metadata": {
                            "name": gw.name.as_ref(),
                            "namespace": gw.namespace.as_ref(),
                        },
                        "status": {
                            "conditions": [
                                {
                                    "type": "Programmed",
                                    "status": "True",
                                    "reason": "Programmed",
                                    "message": "Routes programmed into proxy",
                                    "observedGeneration": gw.generation,
                                }
                            ]
                        }
                    });
                    let api: Api<Gateway> = Api::namespaced(client.clone(), gw.namespace.as_ref());
                    let pp = PatchParams::apply("sunbeam-proxy");
                    if let Err(e) = api.patch_status(gw.name.as_ref(), &pp, &Patch::Apply(&programmed)).await {
                        tracing::warn!(error = %e, name = %gw.name, "Gateway Programmed status patch failed");
                    }
                }
            }
        }
    }
}

/// Compare `new` against `old` and emit a [`GatewayResourceNotify`] for every
/// resource whose generation differs or that is newly present.
fn diff_view(
    old: &Option<ReconciledView>,
    new: &ReconciledView,
) -> Vec<GatewayResourceNotify> {
    let mut notifies = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for gw in &new.gateways {
        let changed = old.as_ref().map_or(true, |o| {
            !o.gateways.iter().any(|g| {
                g.namespace == gw.namespace && g.name == gw.name && g.generation == gw.generation
            })
        });
        if changed {
            notifies.push(GatewayResourceNotify {
                topic_version: 1,
                kind: "Gateway".into(),
                namespace: gw.namespace.to_string(),
                name: gw.name.to_string(),
                generation: gw.generation,
                timestamp: now,
            });
        }
    }

    for route in &new.http_routes {
        let changed = old.as_ref().map_or(true, |o| {
            !o.http_routes.iter().any(|r| {
                r.namespace == route.namespace
                    && r.name == route.name
                    && r.generation == route.generation
            })
        });
        if changed {
            notifies.push(GatewayResourceNotify {
                topic_version: 1,
                kind: "HTTPRoute".into(),
                namespace: route.namespace.to_string(),
                name: route.name.to_string(),
                generation: route.generation,
                timestamp: now,
            });
        }
    }

    for grant in &new.reference_grants {
        let changed = old.as_ref().map_or(true, |o| {
            !o.reference_grants.iter().any(|g| {
                g.namespace == grant.namespace
                    && g.name == grant.name
                    && g.generation == grant.generation
            })
        });
        if changed {
            notifies.push(GatewayResourceNotify {
                topic_version: 1,
                kind: "ReferenceGrant".into(),
                namespace: grant.namespace.to_string(),
                name: grant.name.to_string(),
                generation: grant.generation,
                timestamp: now,
            });
        }
    }

    notifies
}
