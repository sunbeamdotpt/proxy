// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared helpers for building Gateway API status JSON.

use crate::gateway::model::ParentRef;
use crate::gateway::status::StatusCondition;
use serde_json::Value;

/// A per-parent reconcile status that can be turned into Gateway API status
/// JSON.
pub trait ParentStatusLike {
    fn parent_ref(&self) -> &ParentRef;
    fn conditions(&self) -> &[StatusCondition];
}

/// Build the Gateway API `parents` array from a slice of per-parent statuses.
pub fn build_status_parents<T: ParentStatusLike>(parent_statuses: &[T]) -> Vec<Value> {
    parent_statuses.iter().map(build_status_parent).collect()
}

/// Build a raw Gateway API status condition JSON object.
pub fn condition_json(
    condition_type: &str,
    status: &str,
    reason: &str,
    message: &str,
    observed_generation: i64,
    last_transition_time: &str,
) -> Value {
    serde_json::json!({
        "type": condition_type,
        "status": status,
        "reason": reason,
        "message": message,
        "observedGeneration": observed_generation,
        "lastTransitionTime": last_transition_time,
    })
}

fn build_status_parent<T: ParentStatusLike>(ps: &T) -> Value {
    let conditions: Vec<Value> = ps
        .conditions()
        .iter()
        .map(|c| {
            serde_json::json!({
                "type": c.condition_type.to_string(),
                "status": c.status.to_string(),
                "reason": c.reason,
                "message": c.message,
                "observedGeneration": c.observed_generation,
                "lastTransitionTime": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            })
        })
        .collect();

    let mut parent_ref = serde_json::Map::new();
    parent_ref.insert(
        "group".into(),
        serde_json::json!(ps.parent_ref().group.as_ref()),
    );
    parent_ref.insert(
        "kind".into(),
        serde_json::json!(ps.parent_ref().kind.as_ref()),
    );
    parent_ref.insert(
        "name".into(),
        serde_json::json!(ps.parent_ref().name.as_ref()),
    );
    parent_ref.insert(
        "namespace".into(),
        serde_json::json!(ps.parent_ref().namespace.as_deref().unwrap_or("")),
    );
    if let Some(section) = ps.parent_ref().section_name.as_deref() {
        parent_ref.insert("sectionName".into(), serde_json::json!(section));
    }
    serde_json::json!({
        "parentRef": parent_ref,
        "controllerName": crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME,
        "conditions": conditions,
    })
}
