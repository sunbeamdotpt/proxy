// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::gateway::api::listenerset::ListenerSet;
use crate::gateway::api::{Gateway, HTTPRoute, ReferenceGrant};
use crate::gateway::model::ListenerSetState;
use crate::gateway::reconcile::context::{ReconcilerContext, run_controller};
use crate::gateway::reconcile::gateway::build_gateway_state;
use crate::gateway::reconcile::gatewayclass::supported_features;
use crate::gateway::reconcile::listenerset::state::{
    attached_routes_per_listener, build_listener_set_allowed_map, build_listener_set_state,
    build_listener_set_status, resolve_listener_set_conflicts,
};
use crate::gateway::reconcile::refgrant::{GrantIndex, reconcile_reference_grants};
use crate::gateway::reconcile::trigger::trigger;
use crate::gateway::status::patch::patch_status_if_changed;
use kube::Client;
use kube::api::Api;
use kube::runtime::controller::Action;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Context shared across ListenerSet reconcile invocations.
pub type ListenerSetContext = ReconcilerContext;

/// Reconcile a single ListenerSet: validate against parent Gateway and patch status.
pub async fn reconcile_listenerset(
    ls: Arc<ListenerSet>,
    ctx: Arc<ListenerSetContext>,
) -> Result<Action, kube::Error> {
    let ns = ls.metadata.namespace.clone().unwrap_or_default();
    let name = ls.metadata.name.clone().unwrap_or_default();

    let gateways: Api<Gateway> = Api::all(ctx.client.clone());
    let listenersets: Api<ListenerSet> = Api::all(ctx.client.clone());
    let httproutes: Api<HTTPRoute> = Api::all(ctx.client.clone());
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(ctx.client.clone());
    let referencegrants: Api<ReferenceGrant> = Api::all(ctx.client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let listenerset_list = match listenersets.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ListenerSets for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let httproute_list = match httproutes.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list HTTPRoutes for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let namespace_list = match namespaces.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Namespaces for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let referencegrant_list = match referencegrants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ReferenceGrants for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };

    let grant_index = GrantIndex::new(reconcile_reference_grants(&referencegrant_list.items));

    let namespace_labels: HashMap<String, HashMap<String, String>> = namespace_list
        .iter()
        .map(|ns| {
            let name = ns.metadata.name.clone().unwrap_or_default();
            let labels: HashMap<String, String> = ns
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            (name, labels)
        })
        .collect();

    let gateway_states: Vec<crate::gateway::model::GatewayState> =
        gateway_list.iter().map(build_gateway_state).collect();
    let mut listener_set_states: Vec<ListenerSetState> = Vec::new();
    for ls in &listenerset_list.items {
        listener_set_states.push(
            build_listener_set_state(
                ls,
                &gateway_list.items,
                &namespace_labels,
                &ctx.client,
                &grant_index,
            )
            .await,
        );
    }
    resolve_listener_set_conflicts(&mut listener_set_states, &gateway_states);

    let listener_set_allowed =
        build_listener_set_allowed_map(&listenerset_list.items, &listener_set_states);
    let ls_state = match listener_set_states
        .iter()
        .find(|s| s.namespace.as_ref() == ns && s.name.as_ref() == name)
    {
        Some(s) => s.clone(),
        None => {
            build_listener_set_state(
                &ls,
                &gateway_list.items,
                &namespace_labels,
                &ctx.client,
                &grant_index,
            )
            .await
        }
    };
    let attached = attached_routes_per_listener(
        &ls_state,
        &httproute_list.items,
        &namespace_labels,
        &listener_set_allowed,
    );

    if ctx.is_leader.load(Ordering::Relaxed) {
        let features: HashSet<String> = supported_features().into_iter().collect();
        let new_status = build_listener_set_status(&ls_state, &attached, &features);

        let api: Api<ListenerSet> = Api::namespaced(ctx.client.clone(), &ns);
        if let Err(e) = patch_status_if_changed(
            &api,
            &ls,
            new_status,
            "gateway.networking.k8s.io/v1",
            "ListenerSet",
            "sunbeam-proxy",
        )
        .await
        {
            tracing::warn!(error = %e, name, namespace = ns, "ListenerSet status patch failed");
        }
    }

    trigger();
    Ok(Action::requeue(Duration::from_secs(30)))
}

pub fn error_policy_listenerset(
    _ls: Arc<ListenerSet>,
    _error: &kube::Error,
    _ctx: Arc<ListenerSetContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

/// Patch ListenerSet statuses from the reconcile tick.
///
/// This keeps status writeback out of the event-driven controller path so that
/// a burst of ListenerSet creations does not overload the API server.
pub async fn patch_listener_set_statuses(
    client: &Client,
    listener_sets: &[ListenerSet],
    states: &[ListenerSetState],
    httproutes: &[HTTPRoute],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    is_leader: bool,
) {
    if !is_leader {
        return;
    }

    let features: HashSet<String> = supported_features().into_iter().collect();
    let listener_set_allowed = build_listener_set_allowed_map(listener_sets, states);

    for state in states {
        let Some(raw) = listener_sets.iter().find(|ls| {
            ls.metadata.namespace.as_deref().unwrap_or("default") == state.namespace.as_ref()
                && ls.metadata.name.as_deref().unwrap_or("") == state.name.as_ref()
        }) else {
            continue;
        };

        let attached = attached_routes_per_listener(
            state,
            httproutes,
            namespace_labels,
            &listener_set_allowed,
        );
        let new_status = build_listener_set_status(state, &attached, &features);

        let ns = state.namespace.to_string();
        let name = state.name.to_string();
        let api: Api<ListenerSet> = Api::namespaced(client.clone(), &ns);
        if let Err(e) = patch_status_if_changed(
            &api,
            raw,
            new_status,
            "gateway.networking.k8s.io/v1",
            "ListenerSet",
            "sunbeam-proxy",
        )
        .await
        {
            tracing::warn!(error = %e, name, namespace = ns, "ListenerSet status patch failed");
        }
    }
}

/// Start the ListenerSet controller.
pub fn run_listenerset_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    run_controller::<ListenerSet, _, _, _>(
        client,
        is_leader,
        reconcile_listenerset,
        error_policy_listenerset,
        "ListenerSet",
    )
}
