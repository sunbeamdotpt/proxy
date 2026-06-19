// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Idempotent Kubernetes status patching helpers.

use kube::api::{Api, Patch, PatchParams};
use serde_json::Value;

/// Recursively strip `lastTransitionTime` from a JSON value so that two
/// status objects can be compared without regard to their timestamps.
pub fn strip_last_transition_time(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut new = serde_json::Map::new();
            for (k, v) in map {
                if k == "lastTransitionTime" {
                    continue;
                }
                new.insert(k.clone(), strip_last_transition_time(v));
            }
            Value::Object(new)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(strip_last_transition_time).collect()),
        other => other.clone(),
    }
}

/// Patch a resource's status only if it has meaningfully changed.
///
/// Returns `true` if a patch was sent, `false` if the status was unchanged.
pub async fn patch_status_if_changed<R>(
    api: &Api<R>,
    resource: &R,
    new_status: Value,
    api_version: &str,
    kind: &str,
    field_manager: &str,
) -> Result<bool, kube::Error>
where
    R: kube::Resource<DynamicType = ()>
        + kube::core::object::HasStatus
        + serde::de::DeserializeOwned,
    <R as kube::core::object::HasStatus>::Status: serde::Serialize,
{
    let meta = resource.meta();
    let name = meta.name.clone().unwrap_or_default();
    let ns = meta.namespace.clone().unwrap_or_default();

    let old_status_json = resource
        .status()
        .and_then(|s| serde_json::to_value(s).ok())
        .unwrap_or(Value::Null);
    let old_stripped = strip_last_transition_time(&old_status_json);
    let new_stripped = strip_last_transition_time(&new_status);

    if old_stripped == new_stripped {
        tracing::debug!(
            name,
            namespace = ns,
            kind,
            "status unchanged, skipping patch"
        );
        return Ok(false);
    }

    let patch_body = serde_json::json!({
        "apiVersion": api_version,
        "kind": kind,
        "metadata": {
            "name": name,
            "namespace": ns,
        },
        "status": new_status,
    });

    let pp = PatchParams::apply(field_manager);
    api.patch_status(&name, &pp, &Patch::Apply(&patch_body))
        .await?;
    tracing::debug!(name, namespace = ns, kind, "status patched");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_last_transition_time_removes_timestamp_recursively() {
        let value = serde_json::json!({
            "conditions": [
                {
                    "type": "Ready",
                    "lastTransitionTime": "2026-01-01T00:00:00Z",
                    "status": "True"
                }
            ],
            "nested": {
                "lastTransitionTime": "ignored",
                "value": 1
            }
        });
        let stripped = strip_last_transition_time(&value);
        let conditions = stripped["conditions"].as_array().unwrap();
        assert_eq!(conditions.len(), 1);
        assert!(
            !conditions[0]
                .as_object()
                .unwrap()
                .contains_key("lastTransitionTime")
        );
        assert!(
            !stripped["nested"]
                .as_object()
                .unwrap()
                .contains_key("lastTransitionTime")
        );
        assert_eq!(stripped["nested"]["value"], 1);
    }
}
