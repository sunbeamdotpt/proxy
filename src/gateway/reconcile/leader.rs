// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Leadership-aware reconcile loop.
//!
//! Spawns the per-resource controllers and periodically attempts to
//! obtain a [`LeaderToken`].  Only the leader writes status; standby
//! replicas still reconcile (computing the local view and digest) but
//! skip status writeback.

use crate::gateway::election::{Election, LeaderState};
use crate::gateway::reconcile::gateway::run_gateway_controller;
use crate::gateway::reconcile::gatewayclass::run_gatewayclass_controller;
use crate::gateway::reconcile::httproute::run_httproute_controller;
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Run the full reconcile loop.
///
/// * Spawns `GatewayClass` and `Gateway` controllers with a shared
///   leadership flag derived from the [`Election`].
/// * Periodically tries to acquire a [`LeaderToken`] so that status
///   writeback is only performed by the leader.
/// * Standby replicas continue to run controllers (building the local
///   model) but do not patch status.
pub async fn run_reconcile_loop(election: Election, client: Client) {
    let is_leader = Arc::new(AtomicBool::new(election.state() == LeaderState::Leader));

    // Spawn controllers.  They check `is_leader` before patching status.
    let _gc_handle = run_gatewayclass_controller(client.clone(), is_leader.clone());
    let _gw_handle = run_gateway_controller(client.clone(), is_leader.clone());
    let _hr_handle = run_httproute_controller(client.clone(), is_leader.clone());

    // Hold a LeaderToken for as long as we are leader.  When the token
    // is dropped (or invalidated by the background lease task) we
    // clear the shared flag so that controllers stop writing status.
    let mut token: Option<crate::gateway::election::LeaderToken> = None;
    let mut tick = interval(Duration::from_secs(1));

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
    }
}
