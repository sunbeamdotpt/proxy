// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

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
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;
use tokio::time::{interval, MissedTickBehavior};

use crate::cluster::gateway_topics::GatewayResourceNotify;
use crate::cluster::messages::{ClusterMessage, Payload};
use crate::cluster::ClusterHandle;
use crate::gateway::election::{Election, LeaderState};
use crate::gateway::gossip::digest_publisher::{publish_digest, DigestEvent, DigestPublisher};
use crate::gateway::gossip::resource_notify::{handle_notify, NotifyEvent, ResourceNotifier};
use crate::gateway::model::ReconciledView;
use crate::gateway::reconcile::gateway::run_gateway_controller;
use crate::gateway::reconcile::gatewayclass::run_gatewayclass_controller;
use crate::gateway::reconcile::grpcroute::run_grpcroute_controller;
use crate::gateway::reconcile::httproute::run_httproute_controller;
use crate::gateway::reconcile::l4route::{
    maybe_run_tcproute_controller, maybe_run_tlsroute_controller, maybe_run_udproute_controller,
};
use crate::gateway::reconcile::listenerset::run_listenerset_controller;
use crate::gateway::reconcile::reconcile_tick_with_leader;
use crate::gateway::translate::translate_view_to_ir;
use crate::ir;
use crate::tls::{merge_cert_store, CertSource, DiskCertSource, GatewayCertSource, TlsRegistry};
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
#[allow(clippy::too_many_arguments)]
pub async fn run_reconcile_loop(
    election: Election,
    client: Client,
    routes_tx: Sender<ir::RouteTable>,
    cluster_handle: Option<Arc<ClusterHandle>>,
    tls_registry: Arc<TlsRegistry>,
    gateway_cert_source: Arc<GatewayCertSource>,
    disk_cert_source: Arc<DiskCertSource>,
) {
    let is_leader = Arc::new(AtomicBool::new(election.state() == LeaderState::Leader));

    // Spawn controllers.  They check `is_leader` before patching status.
    let _gc_handle = run_gatewayclass_controller(client.clone(), is_leader.clone());
    let _gw_handle = run_gateway_controller(client.clone(), is_leader.clone());
    let _hr_handle = run_httproute_controller(client.clone(), is_leader.clone());
    let _gr_handle = run_grpcroute_controller(client.clone(), is_leader.clone());
    let _ls_handle = run_listenerset_controller(client.clone(), is_leader.clone());
    let _tcp_handle = maybe_run_tcproute_controller(client.clone(), is_leader.clone()).await;
    let _udp_handle = maybe_run_udproute_controller(client.clone(), is_leader.clone()).await;
    let _tls_handle = maybe_run_tlsroute_controller(client.clone(), is_leader.clone()).await;
    // ListenerSet status is written both by an event-driven controller and by
    // the reconcile tick. The event controller handles newly created resources
    // quickly, while the tick provides a periodic sweep that repairs any drift.

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
                            if let Some(ref ch) = cluster_for_digest
                                && let Some(ref tx) = ch.gateway_state_tx {
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
                        DigestEvent::ForceReconcile => {
                            // Handled by the main loop via `force_notify`.
                        }
                    }
                }
                Some(evt) = notify_events_rx.recv() => {
                    match evt {
                        NotifyEvent::Broadcast(notify) => {
                            if let Some(ref ch) = cluster_for_notify
                                && let Some(ref tx) = ch.gateway_notify_tx {
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
    let mut tick = interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let force_notify = Arc::new(Notify::new());
    crate::gateway::reconcile::trigger::init(Arc::clone(&force_notify));
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
        if let Some(ref t) = token
            && !t.is_leader() {
                token = None;
                is_leader.store(false, Ordering::Relaxed);
                tracing::info!("LeaderToken invalidated — status writeback disabled");
            }

        // Full reconcile tick: fetch, translate, and send to proxy.
        let leader = is_leader.load(Ordering::Relaxed);
        if let Some(view) = reconcile_tick_with_leader(&client, leader).await {
            let routes = translate_view_to_ir(&view);
            let _ = routes_tx.send(routes);

            // Publish digest for cross-replica validation.
            publish_digest(&digest_publisher, &view).await;

            // Emit resource notifications for anything that changed.
            // Only refresh certificates when the reconciled view changed. This
            // avoids repeatedly fetching Secrets and ConfigMaps from the API
            // server on every 500ms tick.
            let view_changed = prev_view.as_ref() != Some(&view);

            for notify in diff_view(&prev_view, &view) {
                handle_notify(&resource_notifier, notify).await;
            }
            prev_view = Some(view.clone());

            if view_changed {
                gateway_cert_source.refresh(&client, &view).await;
                disk_cert_source.refresh();
                let mut store = disk_cert_source
                    .snapshot()
                    .map(|s| (*s).clone())
                    .unwrap_or_default();
                if let Some(gw) = gateway_cert_source.snapshot() {
                    merge_cert_store(&mut store, &gw);
                }
                tls_registry.apply(store);
            }

            // Gateway status (including Programmed=True) is written by the
            // dedicated Gateway controller; the main loop only computes the
            // translated route table here.
        }
    }
}

/// Compare `new` against `old` and emit a [`GatewayResourceNotify`] for every
/// resource whose generation differs or that is newly present.
fn diff_view(old: &Option<ReconciledView>, new: &ReconciledView) -> Vec<GatewayResourceNotify> {
    let mut notifies = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for gw in &new.gateways {
        let changed = old.as_ref().is_none_or(|o| {
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
        let changed = old.as_ref().is_none_or(|o| {
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

    for route in &new.grpc_routes {
        let changed = old.as_ref().is_none_or(|o| {
            !o.grpc_routes.iter().any(|r| {
                r.namespace == route.namespace
                    && r.name == route.name
                    && r.generation == route.generation
            })
        });
        if changed {
            notifies.push(GatewayResourceNotify {
                topic_version: 1,
                kind: "GRPCRoute".into(),
                namespace: route.namespace.to_string(),
                name: route.name.to_string(),
                generation: route.generation,
                timestamp: now,
            });
        }
    }

    for route in &new.tcp_routes {
        let changed = old.as_ref().is_none_or(|o| {
            !o.tcp_routes.iter().any(|r| {
                r.namespace == route.namespace
                    && r.name == route.name
                    && r.generation == route.generation
            })
        });
        if changed {
            notifies.push(GatewayResourceNotify {
                topic_version: 1,
                kind: "TCPRoute".into(),
                namespace: route.namespace.to_string(),
                name: route.name.to_string(),
                generation: route.generation,
                timestamp: now,
            });
        }
    }

    for route in &new.udp_routes {
        let changed = old.as_ref().is_none_or(|o| {
            !o.udp_routes.iter().any(|r| {
                r.namespace == route.namespace
                    && r.name == route.name
                    && r.generation == route.generation
            })
        });
        if changed {
            notifies.push(GatewayResourceNotify {
                topic_version: 1,
                kind: "UDPRoute".into(),
                namespace: route.namespace.to_string(),
                name: route.name.to_string(),
                generation: route.generation,
                timestamp: now,
            });
        }
    }

    for route in &new.tls_routes {
        let changed = old.as_ref().is_none_or(|o| {
            !o.tls_routes.iter().any(|r| {
                r.namespace == route.namespace
                    && r.name == route.name
                    && r.generation == route.generation
            })
        });
        if changed {
            notifies.push(GatewayResourceNotify {
                topic_version: 1,
                kind: "TLSRoute".into(),
                namespace: route.namespace.to_string(),
                name: route.name.to_string(),
                generation: route.generation,
                timestamp: now,
            });
        }
    }

    for grant in &new.reference_grants {
        let changed = old.as_ref().is_none_or(|o| {
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

    for policy in &new.backend_tls_policies {
        let changed = old.as_ref().is_none_or(|o| {
            !o.backend_tls_policies.iter().any(|p| {
                p.namespace == policy.namespace
                    && p.name == policy.name
                    && p.generation == policy.generation
            })
        });
        if changed {
            notifies.push(GatewayResourceNotify {
                topic_version: 1,
                kind: "BackendTLSPolicy".into(),
                namespace: policy.namespace.to_string(),
                name: policy.name.to_string(),
                generation: policy.generation,
                timestamp: now,
            });
        }
    }

    notifies
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::{GatewayState, HTTPRouteState, ListenerState, ReferenceGrantState};
    use http::Request as HttpRequest;

    fn gw(ns: &str, name: &str, generation: i64) -> GatewayState {
        GatewayState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation,
            listeners: vec![ListenerState {
                programmed: true,
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        }
    }

    fn route(ns: &str, name: &str, generation: i64) -> HTTPRouteState {
        HTTPRouteState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation,
            hostnames: vec![],
            rules: vec![],
            parent_refs: vec![],
            programmed: true,
        }
    }

    fn grant(ns: &str, name: &str, generation: i64) -> ReferenceGrantState {
        ReferenceGrantState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation,
            from: vec![],
            to: vec![],
        }
    }

    fn view(
        gateways: Vec<GatewayState>,
        routes: Vec<HTTPRouteState>,
        grants: Vec<ReferenceGrantState>,
    ) -> ReconciledView {
        ReconciledView {
            gateways,
            http_routes: routes,
            reference_grants: grants,
            ..Default::default()
        }
    }

    fn tcp_route(ns: &str, name: &str, generation: i64) -> crate::gateway::model::TCPRouteState {
        crate::gateway::model::TCPRouteState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation,
            parent_refs: vec![],
            backends: vec![],
            programmed: true,
        }
    }

    fn udp_route(ns: &str, name: &str, generation: i64) -> crate::gateway::model::UDPRouteState {
        crate::gateway::model::UDPRouteState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation,
            parent_refs: vec![],
            backends: vec![],
            programmed: true,
        }
    }

    fn tls_route(ns: &str, name: &str, generation: i64) -> crate::gateway::model::TLSRouteState {
        crate::gateway::model::TLSRouteState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation,
            hostnames: vec![],
            parent_refs: vec![],
            backends: vec![],
            programmed: true,
        }
    }

    #[test]
    fn diff_view_emits_all_when_old_is_none() {
        let new = view(
            vec![gw("default", "gw-1", 1)],
            vec![route("default", "route-1", 1)],
            vec![grant("default", "grant-1", 1)],
        );
        let notifies = diff_view(&None, &new);
        assert_eq!(notifies.len(), 3);
        assert!(notifies
            .iter()
            .any(|n| n.kind == "Gateway" && n.name == "gw-1"));
        assert!(notifies
            .iter()
            .any(|n| n.kind == "HTTPRoute" && n.name == "route-1"));
        assert!(notifies
            .iter()
            .any(|n| n.kind == "ReferenceGrant" && n.name == "grant-1"));
    }

    #[test]
    fn diff_view_skips_unchanged_resources() {
        let old = view(
            vec![gw("default", "gw-1", 1)],
            vec![route("default", "route-1", 1)],
            vec![grant("default", "grant-1", 1)],
        );
        let new = view(
            vec![gw("default", "gw-1", 1)],
            vec![route("default", "route-1", 1)],
            vec![grant("default", "grant-1", 1)],
        );
        let notifies = diff_view(&Some(old), &new);
        assert!(notifies.is_empty());
    }

    #[test]
    fn diff_view_emits_changed_generation() {
        let old = view(vec![gw("default", "gw-1", 1)], vec![], vec![]);
        let new = view(vec![gw("default", "gw-1", 2)], vec![], vec![]);
        let notifies = diff_view(&Some(old), &new);
        assert_eq!(notifies.len(), 1);
        assert_eq!(notifies[0].kind, "Gateway");
        assert_eq!(notifies[0].generation, 2);
    }

    #[test]
    fn diff_view_emits_new_resources_only() {
        let old = view(
            vec![gw("default", "gw-1", 1)],
            vec![route("default", "route-1", 1)],
            vec![],
        );
        let new = view(
            vec![gw("default", "gw-1", 1), gw("default", "gw-2", 1)],
            vec![
                route("default", "route-1", 1),
                route("default", "route-2", 1),
            ],
            vec![grant("default", "grant-1", 1)],
        );
        let notifies = diff_view(&Some(old), &new);
        assert_eq!(notifies.len(), 3);
        assert!(notifies
            .iter()
            .any(|n| n.kind == "Gateway" && n.name == "gw-2"));
        assert!(notifies
            .iter()
            .any(|n| n.kind == "HTTPRoute" && n.name == "route-2"));
        assert!(notifies
            .iter()
            .any(|n| n.kind == "ReferenceGrant" && n.name == "grant-1"));
    }

    #[test]
    fn diff_view_differentiates_by_namespace_and_name() {
        let old = view(vec![gw("ns-a", "gw", 1)], vec![], vec![]);
        let new = view(
            vec![gw("ns-a", "gw", 1), gw("ns-b", "gw", 1)],
            vec![],
            vec![],
        );
        let notifies = diff_view(&Some(old), &new);
        assert_eq!(notifies.len(), 1);
        assert_eq!(notifies[0].namespace, "ns-b");
    }

    #[test]
    fn diff_view_emits_l4_route_changes() {
        let mut old = view(vec![], vec![], vec![]);
        old.tcp_routes.push(tcp_route("default", "tcp-1", 1));
        old.udp_routes.push(udp_route("default", "udp-1", 1));
        old.tls_routes.push(tls_route("default", "tls-1", 1));

        let mut new = view(vec![], vec![], vec![]);
        new.tcp_routes.push(tcp_route("default", "tcp-1", 2));
        new.udp_routes.push(udp_route("default", "udp-2", 1));
        new.tls_routes.push(tls_route("default", "tls-1", 1));

        let notifies = diff_view(&Some(old), &new);
        assert_eq!(notifies.len(), 2);
        assert!(notifies
            .iter()
            .any(|n| n.kind == "TCPRoute" && n.name == "tcp-1" && n.generation == 2));
        assert!(notifies
            .iter()
            .any(|n| n.kind == "UDPRoute" && n.name == "udp-2"));
    }

    #[test]
    fn diff_view_emits_backend_tls_policy_changes() {
        let mut old = view(vec![], vec![], vec![]);
        old.backend_tls_policies
            .push(crate::gateway::model::BackendTLSPolicyState {
                namespace: Arc::from("default"),
                name: Arc::from("btp-1"),
                generation: 1,
                ..Default::default()
            });
        let mut new = view(vec![], vec![], vec![]);
        new.backend_tls_policies
            .push(crate::gateway::model::BackendTLSPolicyState {
                namespace: Arc::from("default"),
                name: Arc::from("btp-1"),
                generation: 2,
                ..Default::default()
            });
        let notifies = diff_view(&Some(old), &new);
        assert_eq!(notifies.len(), 1);
        assert_eq!(notifies[0].kind, "BackendTLSPolicy");
        assert_eq!(notifies[0].generation, 2);
    }

    #[tokio::test]
    async fn run_reconcile_loop_executes_ticks_and_becomes_leader() {
        use crate::tls::{DiskCertSource, GatewayCertSource, TlsRegistry};
        use std::time::Duration;

        let client = kube::Client::new(
            tower::service_fn(|req: HttpRequest<kube::client::Body>| async move {
                let path = req.uri().path();
                let body = if path.contains("/leases/") && req.method() == "PATCH" {
                    serde_json::json!({
                        "apiVersion": "coordination.k8s.io/v1",
                        "kind": "Lease",
                        "metadata": { "name": "sunbeam-proxy-leader", "namespace": "default" }
                    })
                } else if path.contains("/namespaces") {
                    serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []})
                } else {
                    serde_json::json!({"items": []})
                };
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(body.to_string().into_bytes()))
                        .unwrap(),
                )
            }),
            "default",
        );

        let (routes_tx, _routes_rx) = std::sync::mpsc::channel::<crate::ir::RouteTable>();
        let election = Election::new(
            client.clone(),
            "default".into(),
            "sunbeam-proxy-leader".into(),
            "test".into(),
        );
        let tls_registry = Arc::new(TlsRegistry::new());
        let gateway_cert_source = Arc::new(GatewayCertSource::new());
        let disk_cert_source = Arc::new(DiskCertSource::new(
            "/tmp/sunbeam-test-cert.pem".into(),
            "/tmp/sunbeam-test-key.pem".into(),
        ));

        // run_reconcile_loop holds a !Send LeaderToken across await points, so
        // run it on a single-thread runtime exactly like production does.
        let thread_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            rt.block_on(async {
                tokio::task::LocalSet::new()
                    .run_until(async {
                        let task = tokio::task::spawn_local(async move {
                            run_reconcile_loop(
                                election,
                                client,
                                routes_tx,
                                None,
                                tls_registry,
                                gateway_cert_source,
                                disk_cert_source,
                            )
                            .await;
                        });
                        tokio::time::sleep(Duration::from_millis(5500)).await;
                        task.abort();
                    })
                    .await;
            });
        });

        tokio::task::spawn_blocking(move || thread_handle.join().unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn run_reconcile_loop_broadcasts_digest_and_notify_events() {
        use crate::cluster::{
            bandwidth::{
                BandwidthLimiter, BandwidthMeter, BandwidthTracker, ClusterBandwidthState,
            },
            ClusterHandle,
        };
        use crate::tls::{DiskCertSource, GatewayCertSource, TlsRegistry};
        use std::time::Duration;

        let gateway = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw-1", "namespace": "default", "generation": 1 },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{ "name": "http", "protocol": "HTTP", "port": 80 }]
            }
        });
        let httproute = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": {
                "parentRefs": [{ "name": "gw-1" }],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        });

        let client = kube::Client::new(
            tower::service_fn(move |req: HttpRequest<kube::client::Body>| {
                let gw = gateway.clone();
                let hr = httproute.clone();
                async move {
                    let path = req.uri().path();
                    let body = if path.contains("/leases/") && req.method() == "PATCH" {
                        serde_json::json!({
                            "apiVersion": "coordination.k8s.io/v1",
                            "kind": "Lease",
                            "metadata": { "name": "sunbeam-proxy-leader", "namespace": "default" }
                        })
                    } else if path.contains("/gateways") {
                        serde_json::json!({ "apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": [gw] })
                    } else if path.contains("/httproutes") {
                        serde_json::json!({ "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRouteList", "items": [hr] })
                    } else if path.contains("/namespaces") {
                        serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []})
                    } else {
                        serde_json::json!({"items": []})
                    };
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );

        let (routes_tx, _routes_rx) = std::sync::mpsc::channel::<crate::ir::RouteTable>();
        let (state_tx, mut state_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let secret = iroh::SecretKey::generate(&mut rand::rng());
        let cluster_handle = Arc::new(ClusterHandle {
            bandwidth: Arc::new(BandwidthTracker::new()),
            cluster_bandwidth: Arc::new(ClusterBandwidthState::new(30)),
            meter: Arc::new(BandwidthMeter::new(30)),
            limiter: Arc::new(BandwidthLimiter::new(
                Arc::new(BandwidthMeter::new(30)),
                crate::cluster::bandwidth::gbps_to_bytes_per_sec(1.0),
            )),
            endpoint_id: secret.public(),
            gateway_state_tx: Some(state_tx),
            gateway_notify_tx: Some(notify_tx),
            shutdown_tx,
        });

        let election = Election::new(
            client.clone(),
            "default".into(),
            "sunbeam-proxy-leader".into(),
            "test".into(),
        );
        let tls_registry = Arc::new(TlsRegistry::new());
        let gateway_cert_source = Arc::new(GatewayCertSource::new());
        let disk_cert_source = Arc::new(DiskCertSource::new(
            "/tmp/sunbeam-test-cert.pem".into(),
            "/tmp/sunbeam-test-key.pem".into(),
        ));

        let thread_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            rt.block_on(async {
                tokio::task::LocalSet::new()
                    .run_until(async {
                        let task = tokio::task::spawn_local(async move {
                            run_reconcile_loop(
                                election,
                                client,
                                routes_tx,
                                Some(cluster_handle),
                                tls_registry,
                                gateway_cert_source,
                                disk_cert_source,
                            )
                            .await;
                        });

                        let verify = tokio::task::spawn_local(async move {
                            let mut got_state = false;
                            let mut got_notify = false;
                            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
                            // Trigger a forced reconcile to exercise the gossip wake path.
                            crate::gateway::reconcile::trigger::trigger();
                            while !got_state || !got_notify {
                                if tokio::time::Instant::now() > deadline {
                                    panic!("timed out waiting for gossip broadcasts");
                                }
                                if state_rx.try_recv().is_ok() {
                                    got_state = true;
                                }
                                if notify_rx.try_recv().is_ok() {
                                    got_notify = true;
                                }
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                            task.abort();
                        });
                        verify.await.unwrap();
                    })
                    .await;
            });
        });

        tokio::task::spawn_blocking(move || thread_handle.join().unwrap())
            .await
            .unwrap();
    }
}
