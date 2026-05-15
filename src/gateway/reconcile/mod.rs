// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Reconciler submodule.
//!
//! Watches Gateway API CRDs in the configured namespace, validates
//! cross-references (RefGrant, parentRefs, backendRefs), and produces
//! a `GatewayView` that is handed off to `translate`.

pub mod gateway;
pub mod gatewayclass;
pub mod httproute;
pub mod leader;
pub mod refgrant;

pub use leader::run_reconcile_loop;

use crate::gateway::api::{Gateway, HTTPRoute, ReferenceGrant};
use crate::gateway::model::{GatewayView, ReferenceGrantState, RouteState};
use crate::gateway::reconcile::gateway::build_gateway_state;
use crate::gateway::reconcile::httproute::{reconcile_httproutes, parse_httproute_state};
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use kube::api::Api;

/// Single reconcile tick: fetch all Gateway API objects and emit a view.
pub async fn reconcile_tick(client: &kube::Client) -> Option<GatewayView> {
    let gateways: Api<Gateway> = Api::all(client.clone());
    let httproutes: Api<HTTPRoute> = Api::all(client.clone());
    let grants: Api<ReferenceGrant> = Api::all(client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways");
            return None;
        }
    };

    let httproute_list = match httproutes.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list HTTPRoutes");
            return None;
        }
    };

    let grant_list = match grants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ReferenceGrants");
            return None;
        }
    };

    let gateway_states: Vec<_> = gateway_list.iter().map(build_gateway_state).collect();
    let grant_states = reconcile_reference_grants(&grant_list.items);
    let grant_index = GrantIndex::new(grant_states.clone());

    let reconciled_routes = reconcile_httproutes(&httproute_list.items, &gateway_states, &grant_index);

    let mut http_routes = Vec::new();
    for (raw, reconciled) in httproute_list.items.iter().zip(reconciled_routes.iter()) {
        let mut state = parse_httproute_state(raw);
        state.parent_refs = reconciled.route_state.parent_refs.clone();
        http_routes.push(state);
    }

    let routes: Vec<RouteState> = reconciled_routes
        .into_iter()
        .map(|r| r.route_state)
        .collect();

    let reference_grants = grant_states;

    Some(GatewayView {
        gateways: gateway_states,
        routes,
        http_routes,
        reference_grants,
    })
}
