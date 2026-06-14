// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Expand headless / manually-endpointed Service backends into concrete
//! endpoint addresses using Kubernetes EndpointSlices.
//!
//! Regular ClusterIP Services are left as DNS names so that kube-proxy can
//! continue to load-balance them. Headless Services (`clusterIP: None`) and
//! Services without a selector (manually managed EndpointSlices) are resolved
//! to the ready endpoint addresses and the matching EndpointSlice port. This
//! avoids the classic headless-service pitfall where the service port is
//! different from the pod target port.

use crate::gateway::model::{
    BackendTLSPolicyState, BackendTlsAttachment, GRPCRouteRule, GRPCRouteState, HTTPRouteRule,
    HTTPRouteState, WeightedBackend,
};
use k8s_openapi::api::core::v1::{Service, ServicePort};
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointPort, EndpointSlice};
use kube::api::Api;
use std::collections::HashMap;
use std::sync::Arc;

/// Key used to look up a `BackendTLSPolicy` for a Service backend.
type TlsPolicyKey = (Arc<str>, Arc<str>, Option<Arc<str>>);

/// Parsed cluster-internal service address produced by [`parse_backend_ref`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct ServiceTarget {
    name: Arc<str>,
    namespace: Arc<str>,
    port: i32,
}

/// Cached information about a Service needed for endpoint resolution.
#[derive(Clone, Debug, Default)]
struct ServiceInfo {
    cluster_ip: Option<String>,
    selector: Option<HashMap<String, String>>,
    ports: Vec<ServicePort>,
}

fn service_port_protocol(port: &ServicePort) -> crate::ir::BackendProtocol {
    match port.app_protocol.as_deref() {
        Some("kubernetes.io/h2c") => crate::ir::BackendProtocol::H2c,
        Some("kubernetes.io/ws") => crate::ir::BackendProtocol::WebSocket,
        Some("kubernetes.io/wss") => crate::ir::BackendProtocol::WebSocketSecure,
        _ => crate::ir::BackendProtocol::Http,
    }
}

/// A single ready endpoint together with its EndpointSlice ports.
#[derive(Clone, Debug)]
struct EndpointInfo {
    address: String,
    ports: Vec<EndpointPort>,
}

/// Rule types that expose a mutable backend list for endpoint expansion.
pub trait RuleWithBackends {
    fn backends_mut(&mut self) -> &mut Vec<WeightedBackend>;
}

impl RuleWithBackends for HTTPRouteRule {
    fn backends_mut(&mut self) -> &mut Vec<WeightedBackend> {
        &mut self.backends
    }
}

impl RuleWithBackends for GRPCRouteRule {
    fn backends_mut(&mut self) -> &mut Vec<WeightedBackend> {
        &mut self.backends
    }
}

/// Route types whose rules contain backends that may need endpoint expansion.
pub trait RouteWithBackends {
    type Rule: RuleWithBackends;
    fn rules_mut(&mut self) -> &mut [Self::Rule];
}

impl RouteWithBackends for HTTPRouteState {
    type Rule = HTTPRouteRule;
    fn rules_mut(&mut self) -> &mut [Self::Rule] {
        &mut self.rules
    }
}

impl RouteWithBackends for GRPCRouteState {
    type Rule = GRPCRouteRule;
    fn rules_mut(&mut self) -> &mut [Self::Rule] {
        &mut self.rules
    }
}

/// Resolve Service backend references into concrete endpoint addresses where
/// required, mutating `routes` in place.
pub async fn resolve_service_endpoints<R: RouteWithBackends>(
    client: &kube::Client,
    routes: &mut [R],
    backend_tls_policies: &[BackendTLSPolicyState],
) {
    let services: Api<Service> = Api::all(client.clone());
    let endpoint_slices: Api<EndpointSlice> = Api::all(client.clone());

    let service_list = match services.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Services for endpoint resolution");
            return;
        }
    };

    let endpoint_list = match endpoint_slices.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list EndpointSlices for endpoint resolution");
            return;
        }
    };

    let service_map = build_service_map(service_list.items);
    let endpoint_map = build_endpoint_map(endpoint_list.items);
    let tls_policy_map = build_tls_policy_map(backend_tls_policies);

    for route in routes {
        for rule in route.rules_mut() {
            expand_rule_backends(rule, &service_map, &endpoint_map, &tls_policy_map);
        }
    }
}

fn build_service_map(services: Vec<Service>) -> HashMap<(String, String), ServiceInfo> {
    let mut map = HashMap::new();
    for svc in services {
        let ns = svc.metadata.namespace.clone().unwrap_or_default();
        let name = svc.metadata.name.clone().unwrap_or_default();
        let spec = svc.spec.unwrap_or_default();
        map.insert(
            (ns, name),
            ServiceInfo {
                cluster_ip: spec.cluster_ip,
                selector: spec.selector.map(|s| s.into_iter().collect()),
                ports: spec.ports.unwrap_or_default(),
            },
        );
    }
    map
}

fn build_endpoint_map(slices: Vec<EndpointSlice>) -> HashMap<(String, String), Vec<EndpointInfo>> {
    let mut map: HashMap<(String, String), Vec<EndpointInfo>> = HashMap::new();
    for slice in slices {
        let labels = slice.metadata.labels.clone().unwrap_or_default();
        let Some(svc_name) = labels.get("kubernetes.io/service-name").cloned() else {
            continue;
        };
        let ns = slice.metadata.namespace.clone().unwrap_or_default();
        let ports = slice.ports.unwrap_or_default();
        for ep in slice.endpoints {
            if !endpoint_is_ready(&ep) {
                continue;
            }
            for addr in &ep.addresses {
                map.entry((ns.clone(), svc_name.clone()))
                    .or_default()
                    .push(EndpointInfo {
                        address: addr.clone(),
                        ports: ports.clone(),
                    });
            }
        }
    }
    map
}

fn endpoint_is_ready(ep: &Endpoint) -> bool {
    let cond = ep.conditions.as_ref();
    // A nil ready condition is interpreted as true by Kubernetes.
    let ready = cond.and_then(|c| c.ready).unwrap_or(true);
    // Avoid sending traffic to terminating endpoints unless explicitly desired.
    let terminating = cond.and_then(|c| c.terminating).unwrap_or(false);
    ready && !terminating
}

fn build_tls_policy_map(
    policies: &[BackendTLSPolicyState],
) -> HashMap<TlsPolicyKey, BackendTlsAttachment> {
    let mut map = HashMap::new();
    for policy in policies {
        if !policy.accepted || !policy.programmed {
            continue;
        }
        let attachment = BackendTlsAttachment {
            hostname: Arc::clone(&policy.hostname),
            ca_bundle_pem: policy
                .ca_certificate_refs
                .first()
                .map(|_| Arc::from(""))
                .unwrap_or_default(),
            subject_alt_names: policy
                .subject_alt_names
                .iter()
                .map(|s| Arc::clone(&s.value))
                .collect(),
        };
        map.insert(
            (
                Arc::clone(&policy.target.namespace),
                Arc::clone(&policy.target.name),
                policy.target.section_name.clone(),
            ),
            attachment,
        );
    }
    map
}

fn expand_rule_backends<R: RuleWithBackends>(
    rule: &mut R,
    service_map: &HashMap<(String, String), ServiceInfo>,
    endpoint_map: &HashMap<(String, String), Vec<EndpointInfo>>,
    tls_policy_map: &HashMap<TlsPolicyKey, BackendTlsAttachment>,
) {
    let backends = rule.backends_mut();
    let mut expanded = Vec::with_capacity(backends.len());
    for backend in backends.drain(..) {
        let Some(target) = parse_service_target(&backend.backend) else {
            expanded.push(backend);
            continue;
        };
        let key = (target.namespace.to_string(), target.name.to_string());
        let Some(info) = service_map.get(&key) else {
            expanded.push(backend);
            continue;
        };

        let port_name = info
            .ports
            .iter()
            .find(|p| p.port == target.port)
            .and_then(|p| p.name.as_deref());
        let tls_attachment = tls_policy_map
            .get(&(
                Arc::clone(&target.namespace),
                Arc::clone(&target.name),
                None,
            ))
            .cloned()
            .or_else(|| {
                let name = Arc::from(port_name.unwrap_or(""));
                tls_policy_map
                    .get(&(Arc::clone(&target.namespace), Arc::clone(&target.name), Some(name)))
                    .cloned()
            });

        let protocol = if tls_attachment.is_some() {
            crate::ir::BackendProtocol::Https
        } else {
            info.ports
                .iter()
                .find(|p| p.port == target.port)
                .map(service_port_protocol)
                .unwrap_or(crate::ir::BackendProtocol::Http)
        };

        if !needs_endpoint_resolution(info) {
            expanded.push(WeightedBackend {
                protocol,
                tls: tls_attachment.clone().or_else(|| backend.tls.clone()),
                ..backend
            });
            continue;
        }

        let Some(endpoints) = endpoint_map.get(&key) else {
            expanded.push(WeightedBackend {
                protocol,
                tls: tls_attachment.clone().or_else(|| backend.tls.clone()),
                ..backend
            });
            continue;
        };

        let mut added = false;
        for ep in endpoints {
            let Some(port) = resolve_endpoint_port(target.port, info, ep) else {
                continue;
            };
            let address = format_backend_address(&ep.address, port);
            expanded.push(WeightedBackend {
                backend: Arc::from(address),
                weight: backend.weight,
                filters: backend.filters.clone(),
                protocol,
                tls: tls_attachment.clone(),
            });
            added = true;
        }

        // If no ready endpoints could be translated, fall back to the DNS name
        // rather than dropping the backend and returning a 500/503 immediately.
        if !added {
            expanded.push(WeightedBackend {
                protocol,
                tls: tls_attachment.clone().or_else(|| backend.tls.clone()),
                ..backend
            });
        }
    }
    *rule.backends_mut() = expanded;
}

fn needs_endpoint_resolution(info: &ServiceInfo) -> bool {
    // Headless services and services with an external endpoint manager both need
    // direct endpoint addresses because DNS-based resolution does not reliably
    // expose the correct pod target port.
    if info.cluster_ip.as_deref() == Some("None") {
        return true;
    }
    match &info.selector {
        None => true,
        Some(s) => s.is_empty(),
    }
}

fn resolve_endpoint_port(service_port: i32, info: &ServiceInfo, ep: &EndpointInfo) -> Option<i32> {
    // Find the ServicePort that matches the backendRef port number.
    let svc_port = info
        .ports
        .iter()
        .find(|p| p.port == service_port)
        .or_else(|| info.ports.first())?;
    let port_name = svc_port.name.as_deref().unwrap_or("");

    // Prefer the EndpointSlice port with the same name as the service port.
    let matched = ep
        .ports
        .iter()
        .find(|p| p.name.as_deref().unwrap_or("") == port_name);

    if let Some(matched) = matched {
        return matched.port;
    }

    // If there is only one EndpointSlice port, use it as a fallback.
    if ep.ports.len() == 1 {
        return ep.ports[0].port;
    }

    // Otherwise try to use the ServicePort's numeric targetPort.
    if let Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(target)) =
        svc_port.target_port
    {
        return Some(target);
    }

    None
}

fn parse_service_target(backend: &str) -> Option<ServiceTarget> {
    // Strip an optional scheme; the reconciler currently always emits FQDNs
    // without a scheme, but tolerate both forms for robustness.
    let addr = backend
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let (host, port_str) = addr.rsplit_once(':')?;
    let port: i32 = port_str.parse().ok()?;
    let host = host.strip_suffix('.').unwrap_or(host);

    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 4 {
        return None;
    }
    let len = parts.len();
    if parts[len - 3] != "svc" || parts[len - 2] != "cluster" || parts[len - 1] != "local" {
        return None;
    }

    let namespace = parts[len - 4];
    let name = parts[..len - 4].join(".");

    Some(ServiceTarget {
        name: Arc::from(name),
        namespace: Arc::from(namespace),
        port,
    })
}

fn format_backend_address(address: &str, port: i32) -> String {
    // IPv6 addresses must be bracketed so that downstream host:port parsing
    // is unambiguous.
    if address.contains(':') {
        format!("[{}]:{}", address, port)
    } else {
        format!("{}:{}", address, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

    fn svc_headless() -> Service {
        Service {
            metadata: ObjectMeta {
                namespace: Some("ns".to_string()),
                name: Some("headless".to_string()),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::core::v1::ServiceSpec {
                cluster_ip: Some("None".to_string()),
                selector: Some(
                    [("app".to_string(), "web".to_string())]
                        .into_iter()
                        .collect(),
                ),
                ports: Some(vec![ServicePort {
                    name: Some("http".to_string()),
                    port: 8080,
                    target_port: Some(IntOrString::Int(3000)),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn svc_manual() -> Service {
        Service {
            metadata: ObjectMeta {
                namespace: Some("ns".to_string()),
                name: Some("manual".to_string()),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::core::v1::ServiceSpec {
                cluster_ip: Some("10.0.0.1".to_string()),
                selector: None,
                ports: Some(vec![ServicePort {
                    name: Some("http".to_string()),
                    port: 8080,
                    target_port: Some(IntOrString::Int(3000)),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn svc_clusterip() -> Service {
        Service {
            metadata: ObjectMeta {
                namespace: Some("ns".to_string()),
                name: Some("regular".to_string()),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::core::v1::ServiceSpec {
                cluster_ip: Some("10.0.0.2".to_string()),
                selector: Some(
                    [("app".to_string(), "web".to_string())]
                        .into_iter()
                        .collect(),
                ),
                ports: Some(vec![ServicePort {
                    name: Some("http".to_string()),
                    port: 8080,
                    target_port: Some(IntOrString::Int(3000)),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn endpoint_slice(
        svc: &str,
        addresses: Vec<&str>,
        ready: bool,
        ports: Vec<EndpointPort>,
    ) -> EndpointSlice {
        EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some("ns".to_string()),
                labels: Some(
                    [("kubernetes.io/service-name".to_string(), svc.to_string())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
            address_type: "IPv4".to_string(),
            endpoints: addresses
                .into_iter()
                .map(|a| Endpoint {
                    addresses: vec![a.to_string()],
                    conditions: Some(k8s_openapi::api::discovery::v1::EndpointConditions {
                        ready: Some(ready),
                        serving: Some(ready),
                        terminating: Some(false),
                    }),
                    ..Default::default()
                })
                .collect(),
            ports: Some(ports),
        }
    }

    fn make_rule(backend: &str) -> HTTPRouteRule {
        HTTPRouteRule {
            matches: vec![],
            backends: vec![WeightedBackend {
                backend: Arc::from(backend),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,
                filters: vec![],
                tls: None,
            }],
            filters: vec![],
            timeout_ms: None,
            request_timeout_ms: None,
            programmed: true,
        }
    }

    #[test]
    fn parse_service_target_extracts_name_namespace_port() {
        let t = parse_service_target("svc.ns.svc.cluster.local.:8080").unwrap();
        assert_eq!(t.name.as_ref(), "svc");
        assert_eq!(t.namespace.as_ref(), "ns");
        assert_eq!(t.port, 8080);
    }

    #[test]
    fn parse_service_target_accepts_dotted_service_name() {
        let t = parse_service_target("my.svc.name.ns.svc.cluster.local.:80").unwrap();
        assert_eq!(t.name.as_ref(), "my.svc.name");
        assert_eq!(t.namespace.as_ref(), "ns");
    }

    #[test]
    fn parse_service_target_rejects_ip_backend() {
        assert!(parse_service_target("10.0.0.1:8080").is_none());
    }

    #[test]
    fn needs_endpoint_resolution_true_for_headless() {
        assert!(needs_endpoint_resolution(&ServiceInfo::from(
            &svc_headless()
        )));
    }

    #[test]
    fn needs_endpoint_resolution_true_for_no_selector() {
        assert!(needs_endpoint_resolution(&ServiceInfo::from(&svc_manual())));
    }

    #[test]
    fn needs_endpoint_resolution_false_for_regular_clusterip() {
        assert!(!needs_endpoint_resolution(&ServiceInfo::from(
            &svc_clusterip()
        )));
    }

    #[test]
    fn expand_headless_service_to_endpoints() {
        let mut rule = make_rule("headless.ns.svc.cluster.local.:8080");
        let services = build_service_map(vec![svc_headless()]);
        let endpoints = build_endpoint_map(vec![endpoint_slice(
            "headless",
            vec!["10.42.0.10", "10.42.0.11"],
            true,
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(3000),
                ..Default::default()
            }],
        )]);

        expand_rule_backends(&mut rule, &services, &endpoints, &HashMap::new());

        assert_eq!(rule.backends.len(), 2);
        let addrs: Vec<&str> = rule.backends.iter().map(|b| b.backend.as_ref()).collect();
        assert!(addrs.contains(&"10.42.0.10:3000"));
        assert!(addrs.contains(&"10.42.0.11:3000"));
    }

    #[test]
    fn expand_manual_endpoints_service() {
        let mut rule = make_rule("manual.ns.svc.cluster.local.:8080");
        let services = build_service_map(vec![svc_manual()]);
        let endpoints = build_endpoint_map(vec![endpoint_slice(
            "manual",
            vec!["10.42.0.20"],
            true,
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(3000),
                ..Default::default()
            }],
        )]);

        expand_rule_backends(&mut rule, &services, &endpoints, &HashMap::new());

        assert_eq!(rule.backends.len(), 1);
        assert_eq!(rule.backends[0].backend.as_ref(), "10.42.0.20:3000");
    }

    #[test]
    fn regular_clusterip_left_as_dns() {
        let mut rule = make_rule("regular.ns.svc.cluster.local.:8080");
        let services = build_service_map(vec![svc_clusterip()]);
        let endpoints = build_endpoint_map(vec![endpoint_slice(
            "regular",
            vec!["10.42.0.30"],
            true,
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(3000),
                ..Default::default()
            }],
        )]);

        expand_rule_backends(&mut rule, &services, &endpoints, &HashMap::new());

        assert_eq!(rule.backends.len(), 1);
        assert_eq!(
            rule.backends[0].backend.as_ref(),
            "regular.ns.svc.cluster.local.:8080"
        );
    }

    #[test]
    fn not_ready_endpoints_are_ignored_and_fallback_to_dns() {
        let mut rule = make_rule("headless.ns.svc.cluster.local.:8080");
        let services = build_service_map(vec![svc_headless()]);
        let endpoints = build_endpoint_map(vec![endpoint_slice(
            "headless",
            vec!["10.42.0.10"],
            false,
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(3000),
                ..Default::default()
            }],
        )]);

        expand_rule_backends(&mut rule, &services, &endpoints, &HashMap::new());

        assert_eq!(rule.backends.len(), 1);
        assert_eq!(
            rule.backends[0].backend.as_ref(),
            "headless.ns.svc.cluster.local.:8080"
        );
    }

    #[test]
    fn ipv6_endpoint_is_bracketed() {
        let mut rule = make_rule("headless.ns.svc.cluster.local.:8080");
        let services = build_service_map(vec![svc_headless()]);
        let endpoints = build_endpoint_map(vec![endpoint_slice(
            "headless",
            vec!["2001:db8::1"],
            true,
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(3000),
                ..Default::default()
            }],
        )]);

        expand_rule_backends(&mut rule, &services, &endpoints, &HashMap::new());

        assert_eq!(rule.backends[0].backend.as_ref(), "[2001:db8::1]:3000");
    }

    #[test]
    fn clusterip_backend_inherits_app_protocol() {
        let mut svc = svc_clusterip();
        svc.spec.as_mut().unwrap().ports.as_mut().unwrap()[0].app_protocol =
            Some("kubernetes.io/ws".to_string());
        let mut rule = make_rule("regular.ns.svc.cluster.local.:8080");
        let services = build_service_map(vec![svc]);
        let endpoints = build_endpoint_map(vec![]);

        expand_rule_backends(&mut rule, &services, &endpoints, &HashMap::new());

        assert_eq!(rule.backends.len(), 1);
        assert_eq!(
            rule.backends[0].backend.as_ref(),
            "regular.ns.svc.cluster.local.:8080"
        );
        assert_eq!(
            rule.backends[0].protocol,
            crate::ir::BackendProtocol::WebSocket
        );
    }

    #[test]
    fn headless_backend_inherits_h2c_app_protocol() {
        let mut svc = svc_headless();
        svc.spec.as_mut().unwrap().ports.as_mut().unwrap()[0].app_protocol =
            Some("kubernetes.io/h2c".to_string());
        let mut rule = make_rule("headless.ns.svc.cluster.local.:8080");
        let services = build_service_map(vec![svc]);
        let endpoints = build_endpoint_map(vec![endpoint_slice(
            "headless",
            vec!["10.42.0.10"],
            true,
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(3000),
                ..Default::default()
            }],
        )]);

        expand_rule_backends(&mut rule, &services, &endpoints, &HashMap::new());

        assert_eq!(rule.backends.len(), 1);
        assert_eq!(rule.backends[0].backend.as_ref(), "10.42.0.10:3000");
        assert_eq!(rule.backends[0].protocol, crate::ir::BackendProtocol::H2c);
    }

    impl From<&Service> for ServiceInfo {
        fn from(svc: &Service) -> Self {
            let spec = svc.spec.clone().unwrap_or_default();
            Self {
                cluster_ip: spec.cluster_ip,
                selector: spec.selector.map(|s| s.into_iter().collect()),
                ports: spec.ports.unwrap_or_default(),
            }
        }
    }
}
