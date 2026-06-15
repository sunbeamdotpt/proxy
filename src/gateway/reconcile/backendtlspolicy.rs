// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! BackendTLSPolicy reconciler.
//!
//! Watches `BackendTLSPolicy` resources, validates that each policy targets a
//! single Service and that its CA certificate references resolve, resolves
//! conflicts when multiple policies target the same Service, and patches status
//! when running as leader.

use crate::gateway::api::BackendTLSPolicy;
use crate::gateway::model::{
    BackendTLSPolicyState, CaCertificateRef, GRPCRouteState, HTTPRouteState, ParentRef,
    ServiceTargetRef, SubjectAltName,
};
use crate::gateway::reconcile::gatewayclass::{to_k8s_condition, CONTROLLER_NAME};
use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, Patch, PatchParams};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Target service key used for conflict grouping.
type ServiceTargetKey = (Arc<str>, Arc<str>, Option<Arc<str>>);

/// Reconcile all `BackendTLSPolicy` resources in the cluster.
///
/// * Lists policies from the API server.
/// * Validates target refs and CA certificate refs.
/// * Resolves conflicts across policies that target the same Service.
/// * Patches status when `is_leader` is `true`.
pub async fn reconcile_backend_tls_policies(
    client: &kube::Client,
    http_routes: &[HTTPRouteState],
    grpc_routes: &[GRPCRouteState],
    _grant_index: &GrantIndex,
    is_leader: bool,
) -> Vec<BackendTLSPolicyState> {
    let api: Api<BackendTLSPolicy> = Api::all(client.clone());
    let policies = match api.list(&Default::default()).await {
        Ok(list) => list.items,
        Err(e) => {
            let is_missing = matches!(&e, kube::Error::Api(s) if s.code == 404);
            if is_missing {
                tracing::debug!("BackendTLSPolicy CRD is not installed; treating as empty");
                vec![]
            } else {
                tracing::warn!(error = %e, "failed to list BackendTLSPolicies");
                vec![]
            }
        }
    };

    let mut pre: Vec<PrePolicy<'_>> = Vec::with_capacity(policies.len());
    for policy in &policies {
        pre.push(prevalidate(policy, client).await);
    }

    // Group policies by target Service (namespace/name/section_name).
    let mut groups: HashMap<ServiceTargetKey, Vec<&PrePolicy<'_>>> = HashMap::new();
    for p in &pre {
        let key = (
            p.target.namespace.clone(),
            p.target.name.clone(),
            p.target.section_name.clone(),
        );
        groups.entry(key).or_default().push(p);
    }

    // Determine the winning policy for each target group.
    let mut winners: HashMap<ServiceTargetKey, Arc<str>> = HashMap::new();
    for (key, group) in &groups {
        let winner = group
            .iter()
            .min_by_key(|p| (p.created_at, format!("{}/{}", p.namespace, p.name)))
            .expect("non-empty group");
        winners.insert(key.clone(), winner.name.clone());
    }

    let service_to_gateways = build_service_to_gateways(http_routes, grpc_routes);

    let mut states = Vec::with_capacity(pre.len());
    for p in &pre {
        let key = (
            p.target.namespace.clone(),
            p.target.name.clone(),
            p.target.section_name.clone(),
        );
        let is_winner = winners
            .get(&key)
            .map(|n| n.as_ref() == p.name.as_ref())
            .unwrap_or(false);

        let state = build_state(p, is_winner);
        if is_leader {
            let ancestors = service_to_gateways
                .get(&(p.target.namespace.clone(), p.target.name.clone()))
                .cloned()
                .unwrap_or_default();
            patch_status(client, p.raw, &state, &ancestors).await;
        }
        states.push(state);
    }

    states
}

/// Build a map from Service (namespace/name) to the Gateway parent refs that
/// route to it through HTTPRoutes or GRPCRoutes.
///
/// BackendTLSPolicy status ancestors must reference the Gateway(s) that apply
/// the policy, not the Service target itself.
fn build_service_to_gateways(
    http_routes: &[HTTPRouteState],
    grpc_routes: &[GRPCRouteState],
) -> HashMap<(Arc<str>, Arc<str>), Vec<ParentRef>> {
    let mut map: HashMap<(Arc<str>, Arc<str>), Vec<ParentRef>> = HashMap::new();

    for route in http_routes {
        collect_gateways_for_route(route.parent_refs.clone(), &route.rules, &mut map);
    }
    for route in grpc_routes {
        collect_gateways_for_route(route.parent_refs.clone(), &route.rules, &mut map);
    }

    map
}

fn collect_gateways_for_route<R>(
    parents: Vec<ParentRef>,
    rules: &[R],
    map: &mut HashMap<(Arc<str>, Arc<str>), Vec<ParentRef>>,
) where
    R: RouteRuleLike,
{
    let gateway_parents: Vec<ParentRef> = parents
        .into_iter()
        .filter(|p| p.kind.as_ref() == "Gateway" && p.group.as_ref() == "gateway.networking.k8s.io")
        .collect();
    if gateway_parents.is_empty() {
        return;
    }

    let mut seen = BTreeSet::new();
    for rule in rules {
        for backend in rule.backends() {
            if let Some((ns, name)) = parse_backend_service(backend.backend.as_ref()) {
                let key = (Arc::from(ns), Arc::from(name));
                if !seen.insert(key.clone()) {
                    continue;
                }
                let entry = map.entry(key).or_default();
                for parent in &gateway_parents {
                    if !entry.iter().any(|p| same_parent(p, parent)) {
                        entry.push(parent.clone());
                    }
                }
            }
        }
    }
}

fn same_parent(a: &ParentRef, b: &ParentRef) -> bool {
    a.group == b.group
        && a.kind == b.kind
        && a.namespace == b.namespace
        && a.name == b.name
        && a.section_name == b.section_name
        && a.port == b.port
}

/// Parse the Service namespace/name from an internal backend address of the
/// form `name.namespace.svc.cluster.local.:port`.
fn parse_backend_service(backend: &str) -> Option<(&str, &str)> {
    let host = backend.split(':').next()?;
    let mut parts = host.split('.');
    let name = parts.next()?;
    let ns = parts.next()?;
    let svc = parts.next()?;
    let cluster = parts.next()?;
    if svc != "svc" || cluster != "cluster" {
        return None;
    }
    Some((name, ns))
}

/// Abstraction over HTTP and gRPC route rules so they can share the gateway
/// collection logic.
trait RouteRuleLike {
    fn backends(&self) -> &[crate::gateway::model::WeightedBackend];
}

impl RouteRuleLike for crate::gateway::model::HTTPRouteRule {
    fn backends(&self) -> &[crate::gateway::model::WeightedBackend] {
        &self.backends
    }
}

impl RouteRuleLike for crate::gateway::model::GRPCRouteRule {
    fn backends(&self) -> &[crate::gateway::model::WeightedBackend] {
        &self.backends
    }
}

/// Intermediate validation result for a single `BackendTLSPolicy`.
struct PrePolicy<'a> {
    raw: &'a BackendTLSPolicy,
    namespace: Arc<str>,
    name: Arc<str>,
    generation: i64,
    created_at: i64,
    target: ServiceTargetRef,
    hostname: Arc<str>,
    ca_certificate_refs: Vec<CaCertificateRef>,
    ca_bundle_pem: Arc<str>,
    subject_alt_names: Vec<SubjectAltName>,
    target_invalid: bool,
    ca_invalid_count: usize,
    ca_invalid_kind_count: usize,
    ca_invalid_ref_count: usize,
    ca_total_count: usize,
}

/// Validate a policy's target and CA certificate references.
async fn prevalidate<'a>(policy: &'a BackendTLSPolicy, client: &kube::Client) -> PrePolicy<'a> {
    let namespace: Arc<str> = Arc::from(policy.metadata.namespace.as_deref().unwrap_or("default"));
    let name: Arc<str> = Arc::from(policy.metadata.name.as_deref().unwrap_or(""));
    let generation = policy.metadata.generation.unwrap_or(0);
    let created_at = policy
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| t.0.as_second())
        .unwrap_or(0);

    let target_refs = &policy.spec.target_refs;
    let mut target_invalid = false;
    let mut target = ServiceTargetRef {
        group: Arc::from(""),
        kind: Arc::from(""),
        namespace: namespace.clone(),
        name: Arc::from(""),
        section_name: None,
    };
    if target_refs.len() != 1 {
        target_invalid = true;
    } else {
        let t = &target_refs[0];
        if !t.group.is_empty() || t.kind != "Service" {
            target_invalid = true;
        }
        target = ServiceTargetRef {
            group: Arc::from(t.group.as_str()),
            kind: Arc::from(t.kind.as_str()),
            namespace: namespace.clone(),
            name: Arc::from(t.name.as_str()),
            section_name: t.section_name.as_deref().map(Arc::from),
        };
    }

    let hostname = Arc::from(policy.spec.validation.hostname.as_str());

    let ca_refs_raw = policy
        .spec
        .validation
        .ca_certificate_refs
        .as_deref()
        .unwrap_or(&[]);
    let mut ca_certificate_refs = Vec::with_capacity(ca_refs_raw.len());
    let mut ca_bundle = String::new();
    let mut ca_invalid_count = 0usize;
    let mut ca_invalid_kind_count = 0usize;
    let mut ca_invalid_ref_count = 0usize;
    for r in ca_refs_raw {
        ca_certificate_refs.push(CaCertificateRef {
            group: Arc::from(r.group.as_str()),
            kind: Arc::from(r.kind.as_str()),
            name: Arc::from(r.name.as_str()),
        });
        if r.kind != "ConfigMap" || !r.group.is_empty() {
            ca_invalid_count += 1;
            ca_invalid_kind_count += 1;
            continue;
        }
        let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace.as_ref());
        match cm_api.get(&r.name).await {
            Ok(cm) => match cm.data.as_ref().and_then(|d| d.get("ca.crt")) {
                Some(ca) if !ca.is_empty() => {
                    ca_bundle.push_str(ca);
                    if !ca_bundle.ends_with('\n') {
                        ca_bundle.push('\n');
                    }
                }
                _ => {
                    ca_invalid_count += 1;
                    ca_invalid_ref_count += 1;
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    name = r.name.as_str(),
                    namespace = namespace.as_ref(),
                    "failed to resolve BackendTLSPolicy CA certificate ConfigMap"
                );
                ca_invalid_count += 1;
                ca_invalid_ref_count += 1;
            }
        }
    }

    let sans_raw = policy
        .spec
        .validation
        .subject_alt_names
        .as_deref()
        .unwrap_or(&[]);
    let mut subject_alt_names = Vec::with_capacity(sans_raw.len());
    for s in sans_raw {
        let value = match s.r#type {
            gateway_api::backendtlspolicies::BackendTlsPolicyValidationSubjectAltNamesType::Hostname => {
                s.hostname.as_deref().unwrap_or("")
            }
            gateway_api::backendtlspolicies::BackendTlsPolicyValidationSubjectAltNamesType::Uri => {
                s.uri.as_deref().unwrap_or("")
            }
        };
        let type_str = match s.r#type {
            gateway_api::backendtlspolicies::BackendTlsPolicyValidationSubjectAltNamesType::Hostname => "Hostname",
            gateway_api::backendtlspolicies::BackendTlsPolicyValidationSubjectAltNamesType::Uri => "URI",
        };
        subject_alt_names.push(SubjectAltName {
            r#type: Arc::from(type_str),
            value: Arc::from(value),
        });
    }

    PrePolicy {
        raw: policy,
        namespace,
        name,
        generation,
        created_at,
        target,
        hostname,
        ca_certificate_refs,
        ca_bundle_pem: Arc::from(ca_bundle),
        subject_alt_names,
        target_invalid,
        ca_invalid_count,
        ca_invalid_kind_count,
        ca_invalid_ref_count,
        ca_total_count: ca_refs_raw.len(),
    }
}

/// Build the reconciled state from a pre-validated policy.
fn build_state(p: &PrePolicy<'_>, is_winner: bool) -> BackendTLSPolicyState {
    let all_ca_invalid = p.ca_total_count > 0 && p.ca_invalid_count == p.ca_total_count;

    let (accepted, accepted_reason, accepted_message) = if !is_winner {
        (
            false,
            Arc::from("Conflicted"),
            Arc::from("BackendTLSPolicy conflicted by an older or alphabetically earlier policy"),
        )
    } else if p.target_invalid {
        (
            false,
            Arc::from("InvalidKind"),
            Arc::from(
                "targetRefs must contain exactly one reference to a Service in the core API group",
            ),
        )
    } else if all_ca_invalid {
        (
            false,
            Arc::from("NoValidCACertificate"),
            Arc::from("all CA certificate references are invalid"),
        )
    } else {
        (
            true,
            Arc::from("Accepted"),
            Arc::from("BackendTLSPolicy accepted"),
        )
    };

    let (resolved_refs, resolved_refs_reason, resolved_refs_message) =
        if p.ca_invalid_kind_count > 0 {
            (
                false,
                Arc::from("InvalidKind"),
                Arc::from(format!(
                    "{} CA certificate reference(s) have an unsupported kind",
                    p.ca_invalid_kind_count
                )),
            )
        } else if p.ca_invalid_ref_count > 0 {
            (
                false,
                Arc::from("InvalidCACertificateRef"),
                Arc::from(format!(
                    "{} CA certificate reference(s) are invalid",
                    p.ca_invalid_ref_count
                )),
            )
        } else {
            (
                true,
                Arc::from("ResolvedRefs"),
                Arc::from("all references resolved"),
            )
        };

    let programmed = accepted && resolved_refs;

    BackendTLSPolicyState {
        namespace: p.namespace.clone(),
        name: p.name.clone(),
        generation: p.generation,
        created_at: p.created_at,
        target: p.target.clone(),
        hostname: p.hostname.clone(),
        ca_certificate_refs: p.ca_certificate_refs.clone(),
        ca_bundle_pem: p.ca_bundle_pem.clone(),
        subject_alt_names: p.subject_alt_names.clone(),
        accepted,
        accepted_reason,
        accepted_message,
        resolved_refs,
        resolved_refs_reason,
        resolved_refs_message,
        programmed,
    }
}

/// Patch a single `BackendTLSPolicy` status when running as leader.
async fn patch_status(
    client: &kube::Client,
    raw: &BackendTLSPolicy,
    state: &BackendTLSPolicyState,
    ancestors: &[ParentRef],
) {
    let ns = state.namespace.to_string();
    let name = state.name.to_string();
    let observed_generation = state.generation;

    let accepted = StatusCondition {
        condition_type: ConditionType::Accepted,
        status: if state.accepted {
            ConditionStatus::True
        } else {
            ConditionStatus::False
        },
        reason: state.accepted_reason.to_string(),
        message: state.accepted_message.to_string(),
        observed_generation,
    };
    let resolved_refs = StatusCondition {
        condition_type: ConditionType::ResolvedRefs,
        status: if state.resolved_refs {
            ConditionStatus::True
        } else {
            ConditionStatus::False
        },
        reason: state.resolved_refs_reason.to_string(),
        message: state.resolved_refs_message.to_string(),
        observed_generation,
    };
    let programmed = StatusCondition {
        condition_type: ConditionType::Programmed,
        status: if state.programmed {
            ConditionStatus::True
        } else {
            ConditionStatus::False
        },
        reason: if state.programmed {
            "Programmed".to_string()
        } else {
            "NotProgrammed".to_string()
        },
        message: if state.programmed {
            "BackendTLSPolicy programmed".to_string()
        } else {
            "BackendTLSPolicy not programmed".to_string()
        },
        observed_generation,
    };

    let ancestor_entries: Vec<serde_json::Value> = if ancestors.is_empty() {
        vec![serde_json::json!({
            "ancestorRef": {
                "group": "",
                "kind": "Service",
                "name": state.target.name.to_string(),
                "namespace": state.target.namespace.to_string(),
            },
            "controllerName": CONTROLLER_NAME,
            "conditions": vec![
                to_k8s_condition(&accepted),
                to_k8s_condition(&resolved_refs),
                to_k8s_condition(&programmed),
            ],
        })]
    } else {
        ancestors
            .iter()
            .map(|p| {
                let mut ancestor_ref = serde_json::Map::new();
                ancestor_ref.insert("group".to_string(), serde_json::json!(p.group.as_ref()));
                ancestor_ref.insert("kind".to_string(), serde_json::json!(p.kind.as_ref()));
                ancestor_ref.insert("name".to_string(), serde_json::json!(p.name.as_ref()));
                if let Some(ns) = &p.namespace {
                    ancestor_ref.insert("namespace".to_string(), serde_json::json!(ns.as_ref()));
                }
                if let Some(section) = &p.section_name {
                    ancestor_ref.insert(
                        "sectionName".to_string(),
                        serde_json::json!(section.as_ref()),
                    );
                }
                if let Some(port) = &p.port {
                    ancestor_ref.insert("port".to_string(), serde_json::json!(port));
                }
                serde_json::json!({
                    "ancestorRef": ancestor_ref,
                    "controllerName": CONTROLLER_NAME,
                    "conditions": vec![
                        to_k8s_condition(&accepted),
                        to_k8s_condition(&resolved_refs),
                        to_k8s_condition(&programmed),
                    ],
                })
            })
            .collect()
    };

    let new_status = serde_json::json!({
        "ancestors": ancestor_entries
    });

    let old_status_json = raw
        .status
        .as_ref()
        .and_then(|s| serde_json::to_value(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let old_stripped = crate::gateway::reconcile::strip_last_transition_time(&old_status_json);
    let new_stripped = crate::gateway::reconcile::strip_last_transition_time(&new_status);
    if old_stripped == new_stripped {
        tracing::debug!(
            name,
            namespace = ns,
            "BackendTLSPolicy status unchanged, skipping patch"
        );
        return;
    }

    let patch_body = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "BackendTLSPolicy",
        "metadata": { "name": &name, "namespace": &ns },
        "status": new_status,
    });

    let api: Api<BackendTLSPolicy> = Api::namespaced(client.clone(), &ns);
    let pp = PatchParams::apply("sunbeam-proxy");
    if let Err(e) = api
        .patch_status(&name, &pp, &Patch::Apply(&patch_body))
        .await
    {
        tracing::warn!(
            error = %e,
            name,
            namespace = ns,
            "failed to patch BackendTLSPolicy status"
        );
    } else {
        tracing::debug!(name, namespace = ns, "patched BackendTLSPolicy status");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::reconcile::refgrant::GrantIndex;
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn backend_tls_policy(
        name: &str,
        namespace: &str,
        generation: i64,
        created_at: &str,
        target_name: &str,
        target_kind: &str,
        ca_names: &[&str],
    ) -> serde_json::Value {
        let ca_refs: Vec<serde_json::Value> = ca_names
            .iter()
            .map(|n| {
                serde_json::json!({
                    "group": "",
                    "kind": "ConfigMap",
                    "name": n
                })
            })
            .collect();
        serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "BackendTLSPolicy",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "generation": generation,
                "creationTimestamp": created_at
            },
            "spec": {
                "targetRefs": [{
                    "group": if target_kind == "Service" { "" } else { "example.com" },
                    "kind": target_kind,
                    "name": target_name
                }],
                "validation": {
                    "hostname": "svc.example.com",
                    "caCertificateRefs": ca_refs,
                    "subjectAltNames": [
                        { "type": "Hostname", "hostname": "alt.example.com" }
                    ]
                }
            }
        })
    }

    fn configmap(name: &str, namespace: &str, has_ca: bool) -> serde_json::Value {
        let data = if has_ca {
            serde_json::json!({ "ca.crt": "cert" })
        } else {
            serde_json::json!({})
        };
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": name, "namespace": namespace },
            "data": data
        })
    }

    fn ok_response(body: serde_json::Value) -> http::Response<kube::client::Body> {
        http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(kube::client::Body::from(body.to_string().into_bytes()))
            .unwrap()
    }

    fn not_found() -> http::Response<kube::client::Body> {
        http::Response::builder()
            .status(404)
            .body(kube::client::Body::empty())
            .unwrap()
    }

    fn mock_client(
        policies: Vec<serde_json::Value>,
        configmaps: HashMap<(String, String), serde_json::Value>,
        patch_capture: Option<Arc<Mutex<Vec<(String, serde_json::Value)>>>>,
    ) -> kube::Client {
        let policies = Arc::new(policies);
        let configmaps = Arc::new(configmaps);
        kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let policies = policies.clone();
                let configmaps = configmaps.clone();
                let patch_capture = patch_capture.clone();
                async move {
                    let path = req.uri().path().to_string();

                    if path == "/apis/gateway.networking.k8s.io/v1/backendtlspolicies" {
                        let body = serde_json::json!({
                            "apiVersion": "gateway.networking.k8s.io/v1",
                            "kind": "BackendTLSPolicyList",
                            "metadata": { "resourceVersion": "1" },
                            "items": policies.as_ref()
                        });
                        return Ok::<_, std::convert::Infallible>(ok_response(body));
                    }

                    if path.starts_with("/api/v1/namespaces/") && path.contains("/configmaps/") {
                        let rest = path.strip_prefix("/api/v1/namespaces/").unwrap();
                        let (ns, name_part) = rest.split_once("/configmaps/").unwrap();
                        let key = (ns.to_string(), name_part.to_string());
                        if let Some(cm) = configmaps.get(&key) {
                            return Ok::<_, std::convert::Infallible>(ok_response(cm.clone()));
                        }
                        return Ok::<_, std::convert::Infallible>(not_found());
                    }

                    if req.method() == http::Method::PATCH
                        && path.contains("/backendtlspolicies/")
                        && path.ends_with("/status")
                    {
                        let collected = req.into_body().collect().await.unwrap();
                        let bytes = collected.to_bytes();
                        let body: serde_json::Value =
                            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
                        let status_body = body.clone();
                        if let Some(capture) = patch_capture.as_ref() {
                            capture.lock().unwrap().push((path, body));
                        }
                        return Ok::<_, std::convert::Infallible>(ok_response(serde_json::json!({
                            "apiVersion": "gateway.networking.k8s.io/v1",
                            "kind": "BackendTLSPolicy",
                            "metadata": { "name": "ignored", "namespace": "ignored" },
                            "status": status_body.get("status").cloned().unwrap_or(serde_json::Value::Null)
                        })));
                    }

                    Ok::<_, std::convert::Infallible>(ok_response(serde_json::json!({"items": []})))
                }
            }),
            "default",
        )
    }

    #[tokio::test]
    async fn valid_policy_is_accepted_programmed_and_resolved() {
        let policy = backend_tls_policy(
            "tls-policy",
            "default",
            1,
            "2026-01-01T00:00:00Z",
            "svc",
            "Service",
            &["ca-map"],
        );
        let mut cms = HashMap::new();
        cms.insert(
            ("default".into(), "ca-map".into()),
            configmap("ca-map", "default", true),
        );
        let client = mock_client(vec![policy], cms, None);
        let grant_index = GrantIndex::default();

        let states = reconcile_backend_tls_policies(&client, &[], &[], &grant_index, false).await;
        assert_eq!(states.len(), 1);
        let s = &states[0];
        assert!(s.accepted);
        assert_eq!(s.accepted_reason.as_ref(), "Accepted");
        assert!(s.resolved_refs);
        assert!(s.programmed);
        assert_eq!(s.target.kind.as_ref(), "Service");
        assert_eq!(s.target.name.as_ref(), "svc");
        assert_eq!(s.ca_certificate_refs.len(), 1);
        assert_eq!(s.subject_alt_names.len(), 1);
        assert_eq!(s.subject_alt_names[0].r#type.as_ref(), "Hostname");
    }

    #[tokio::test]
    async fn invalid_target_kind_is_rejected() {
        let policy = backend_tls_policy(
            "tls-policy",
            "default",
            1,
            "2026-01-01T00:00:00Z",
            "svc",
            "Secret",
            &[],
        );
        let client = mock_client(vec![policy], HashMap::new(), None);
        let grant_index = GrantIndex::default();

        let states = reconcile_backend_tls_policies(&client, &[], &[], &grant_index, false).await;
        assert_eq!(states.len(), 1);
        let s = &states[0];
        assert!(!s.accepted);
        assert_eq!(s.accepted_reason.as_ref(), "InvalidKind");
        assert!(s.resolved_refs);
        assert!(!s.programmed);
    }

    #[tokio::test]
    async fn invalid_ca_configmap_is_rejected() {
        let policy = backend_tls_policy(
            "tls-policy",
            "default",
            1,
            "2026-01-01T00:00:00Z",
            "svc",
            "Service",
            &["ca-map"],
        );
        let mut cms = HashMap::new();
        cms.insert(
            ("default".into(), "ca-map".into()),
            configmap("ca-map", "default", false),
        );
        let client = mock_client(vec![policy], cms, None);
        let grant_index = GrantIndex::default();

        let states = reconcile_backend_tls_policies(&client, &[], &[], &grant_index, false).await;
        assert_eq!(states.len(), 1);
        let s = &states[0];
        assert!(!s.accepted);
        assert_eq!(s.accepted_reason.as_ref(), "NoValidCACertificate");
        assert!(!s.resolved_refs);
        assert_eq!(s.resolved_refs_reason.as_ref(), "InvalidCACertificateRef");
        assert!(!s.programmed);
    }

    #[tokio::test]
    async fn conflict_resolution_prefers_older_policy() {
        let older = backend_tls_policy(
            "older",
            "default",
            1,
            "2026-01-01T00:00:00Z",
            "svc",
            "Service",
            &["ca-map"],
        );
        let newer = backend_tls_policy(
            "newer",
            "default",
            1,
            "2026-01-02T00:00:00Z",
            "svc",
            "Service",
            &["ca-map"],
        );
        let mut cms = HashMap::new();
        cms.insert(
            ("default".into(), "ca-map".into()),
            configmap("ca-map", "default", true),
        );
        let client = mock_client(vec![older, newer], cms, None);
        let grant_index = GrantIndex::default();

        let states = reconcile_backend_tls_policies(&client, &[], &[], &grant_index, false).await;
        let older_state = states.iter().find(|s| s.name.as_ref() == "older").unwrap();
        let newer_state = states.iter().find(|s| s.name.as_ref() == "newer").unwrap();
        assert!(older_state.accepted);
        assert!(!newer_state.accepted);
        assert_eq!(newer_state.accepted_reason.as_ref(), "Conflicted");
    }

    #[tokio::test]
    async fn conflict_resolution_tie_breaks_alphabetically() {
        let p1 = backend_tls_policy(
            "policy-b",
            "default",
            1,
            "2026-01-01T00:00:00Z",
            "svc",
            "Service",
            &["ca-map"],
        );
        let p2 = backend_tls_policy(
            "policy-a",
            "default",
            1,
            "2026-01-01T00:00:00Z",
            "svc",
            "Service",
            &["ca-map"],
        );
        let mut cms = HashMap::new();
        cms.insert(
            ("default".into(), "ca-map".into()),
            configmap("ca-map", "default", true),
        );
        let client = mock_client(vec![p1, p2], cms, None);
        let grant_index = GrantIndex::default();

        let states = reconcile_backend_tls_policies(&client, &[], &[], &grant_index, false).await;
        let winner = states
            .iter()
            .find(|s| s.name.as_ref() == "policy-a")
            .unwrap();
        let loser = states
            .iter()
            .find(|s| s.name.as_ref() == "policy-b")
            .unwrap();
        assert!(winner.accepted);
        assert!(!loser.accepted);
        assert_eq!(loser.accepted_reason.as_ref(), "Conflicted");
    }

    #[tokio::test]
    async fn leader_patches_status_with_ancestors_and_conditions() {
        let policy = backend_tls_policy(
            "tls-policy",
            "default",
            7,
            "2026-01-01T00:00:00Z",
            "svc",
            "Service",
            &["ca-map"],
        );
        let mut cms = HashMap::new();
        cms.insert(
            ("default".into(), "ca-map".into()),
            configmap("ca-map", "default", true),
        );
        let capture = Arc::new(Mutex::new(Vec::new()));
        let client = mock_client(vec![policy], cms, Some(capture.clone()));
        let grant_index = GrantIndex::default();

        let states = reconcile_backend_tls_policies(&client, &[], &[], &grant_index, true).await;
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].generation, 7);

        let captured = capture.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (path, body) = &captured[0];
        assert!(path.contains("/backendtlspolicies/tls-policy/status"));
        let status = body.get("status").expect("status present");
        let ancestors = status.get("ancestors").unwrap().as_array().unwrap();
        assert_eq!(ancestors.len(), 1);
        let ancestor = &ancestors[0];
        assert_eq!(
            ancestor.get("controllerName").unwrap().as_str().unwrap(),
            CONTROLLER_NAME
        );
        let ancestor_ref = ancestor.get("ancestorRef").unwrap();
        assert_eq!(ancestor_ref.get("group").unwrap().as_str().unwrap(), "");
        assert_eq!(
            ancestor_ref.get("kind").unwrap().as_str().unwrap(),
            "Service"
        );
        assert_eq!(ancestor_ref.get("name").unwrap().as_str().unwrap(), "svc");
        assert_eq!(
            ancestor_ref.get("namespace").unwrap().as_str().unwrap(),
            "default"
        );
        let conditions = ancestor.get("conditions").unwrap().as_array().unwrap();
        assert_eq!(conditions.len(), 3);
        for c in conditions {
            assert_eq!(c.get("observedGeneration").unwrap().as_i64().unwrap(), 7);
        }
    }

    #[tokio::test]
    async fn non_leader_skips_status_patch() {
        let policy = backend_tls_policy(
            "tls-policy",
            "default",
            1,
            "2026-01-01T00:00:00Z",
            "svc",
            "Service",
            &["ca-map"],
        );
        let mut cms = HashMap::new();
        cms.insert(
            ("default".into(), "ca-map".into()),
            configmap("ca-map", "default", true),
        );
        let capture = Arc::new(Mutex::new(Vec::new()));
        let client = mock_client(vec![policy], cms, Some(capture.clone()));
        let grant_index = GrantIndex::default();

        reconcile_backend_tls_policies(&client, &[], &[], &grant_index, false).await;
        assert!(capture.lock().unwrap().is_empty());
    }
}
