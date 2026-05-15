// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Leadership-aware reconcile loop.
//!
//! Spawns the per-resource controllers and periodically attempts to
//! obtain a [`LeaderToken`].  Only the leader writes status; standby
//! replicas still reconcile (computing the local view and digest) but
//! skip status writeback.

use crate::gateway::api::Gateway;
use crate::gateway::election::{Election, LeaderState};
use crate::gateway::reconcile::gateway::run_gateway_controller;
use crate::gateway::reconcile::gatewayclass::run_gatewayclass_controller;
use crate::gateway::reconcile::httproute::run_httproute_controller;
use crate::gateway::reconcile::reconcile_tick;
use crate::gateway::translate::translate_view;
use crate::config::RouteConfig;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use tokio::time::{interval, Duration};

/// Run the full reconcile loop.
///
/// * Spawns `GatewayClass` and `Gateway` controllers with a shared
///   leadership flag derived from the [`Election`].
/// * Periodically tries to acquire a [`LeaderToken`] so that status
///   writeback is only performed by the leader.
/// * Standby replicas continue to run controllers (building the local
///   model) but do not patch status.
/// * Sends translated `RouteConfig`s to the proxy via `routes_tx`.
pub async fn run_reconcile_loop(
    election: Election,
    client: Client,
    routes_tx: Sender<Vec<RouteConfig>>,
) {
    let is_leader = Arc::new(AtomicBool::new(election.state() == LeaderState::Leader));

    // Spawn controllers.  They check `is_leader` before patching status.
    let _gc_handle = run_gatewayclass_controller(client.clone(), is_leader.clone());
    let _gw_handle = run_gateway_controller(client.clone(), is_leader.clone());
    let _hr_handle = run_httproute_controller(client.clone(), is_leader.clone());

    // Hold a LeaderToken for as long as we are leader.  When the token
    // is dropped (or invalidated by the background lease task) we
    // clear the shared flag so that controllers stop writing status.
    let mut token: Option<crate::gateway::election::LeaderToken> = None;
    let mut tick = interval(Duration::from_secs(5));

    loop {
        tick.tick().await;
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
