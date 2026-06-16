// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attached-route counting for Gateway listeners.

use crate::gateway::api::{HTTPRoute, TCPRoute, TLSRoute, UDPRoute};
use crate::gateway::model::HostnameMatch;
use crate::gateway::reconcile::gateway::listeners::ListenerMatch;
use crate::gateway::reconcile::httproute::parse_route_hostnames;
use crate::gateway::reconcile::parent::{
    listener_allows_kind, listener_hostname_intersects, namespace_allowed,
};
use kube::api::Api;
use kube::Client;
use std::collections::HashMap;
use std::sync::Arc;

/// Common shape for a route parentRef so HTTPRoute and L4 routes can share
/// attachment counting logic.
struct ParentRefInfo {
    group: Option<String>,
    kind: Option<String>,
    namespace: Option<String>,
    name: String,
    section_name: Option<String>,
    port: Option<i32>,
}

impl ParentRefInfo {
    fn is_gateway(&self) -> bool {
        self.group.as_deref().unwrap_or("gateway.networking.k8s.io") == "gateway.networking.k8s.io"
            && self.kind.as_deref().unwrap_or("Gateway") == "Gateway"
    }
}

struct AttachmentCounter<'a> {
    listeners: &'a [ListenerMatch],
    gw_ns: &'a str,
    gw_name: &'a str,
    namespace_labels: &'a HashMap<String, HashMap<String, String>>,
    counts: &'a mut [i64],
}

impl<'a> AttachmentCounter<'a> {
    fn increment(
        &mut self,
        parent: &ParentRefInfo,
        route_ns: &str,
        route_hostnames: &[HostnameMatch],
        route_kind: &str,
        expected_protocol: &str,
    ) {
        if !parent.is_gateway() {
            return;
        }
        let parent_ns = parent.namespace.as_deref().unwrap_or(route_ns);
        if parent_ns != self.gw_ns || parent.name != self.gw_name {
            return;
        }
        let parent_section = parent.section_name.as_deref();
        let parent_port = parent.port.map(|p| p as u16);
        for (idx, listener) in self.listeners.iter().enumerate() {
            let section_matches = parent_section.map(|s| s == listener.name).unwrap_or(true);
            let port_matches = parent_port.map(|p| p == listener.port).unwrap_or(true);
            if !section_matches || !port_matches {
                continue;
            }
            if listener.protocol != expected_protocol {
                continue;
            }
            if !listener_allows_kind(&listener.allowed, "gateway.networking.k8s.io", route_kind) {
                continue;
            }
            if !namespace_allowed(
                &listener.allowed.namespaces,
                route_ns,
                self.gw_ns,
                self.namespace_labels,
            ) {
                continue;
            }
            if listener_hostname_intersects(listener.hostname.as_deref(), route_hostnames) {
                self.counts[idx] += 1;
            }
        }
    }
}

/// Count how many routes of each supported kind are attached to each Gateway
/// listener.
pub(crate) async fn count_attached_routes(
    client: &Client,
    gw_ns: &str,
    gw_name: &str,
    listeners: &[ListenerMatch],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
) -> Vec<i64> {
    let mut counts = vec![0i64; listeners.len()];
    let mut counter = AttachmentCounter {
        listeners,
        gw_ns,
        gw_name,
        namespace_labels,
        counts: &mut counts,
    };

    // HTTPRoutes
    if let Ok(list) = Api::<HTTPRoute>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for route in list {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
            let route_hostnames = parse_route_hostnames(&route);
            let parents = route.spec.parent_refs.as_deref().unwrap_or(&[]);
            for parent in parents {
                let info = ParentRefInfo {
                    group: parent.group.clone(),
                    kind: parent.kind.clone(),
                    namespace: parent.namespace.clone(),
                    name: parent.name.clone(),
                    section_name: parent.section_name.clone(),
                    port: parent.port,
                };
                counter.increment(&info, route_ns, &route_hostnames, "HTTPRoute", "HTTPS");
                counter.increment(&info, route_ns, &route_hostnames, "HTTPRoute", "HTTP");
            }
        }
    }

    // TCPRoutes
    if let Ok(list) = Api::<TCPRoute>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for route in list {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
            let parents = route.spec.parent_refs.as_deref().unwrap_or(&[]);
            for parent in parents {
                let info = ParentRefInfo {
                    group: parent.group.clone(),
                    kind: parent.kind.clone(),
                    namespace: parent.namespace.clone(),
                    name: parent.name.clone(),
                    section_name: parent.section_name.clone(),
                    port: parent.port,
                };
                counter.increment(&info, route_ns, &[], "TCPRoute", "TCP");
            }
        }
    }

    // UDPRoutes
    if let Ok(list) = Api::<UDPRoute>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for route in list {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
            let parents = route.spec.parent_refs.as_deref().unwrap_or(&[]);
            for parent in parents {
                let info = ParentRefInfo {
                    group: parent.group.clone(),
                    kind: parent.kind.clone(),
                    namespace: parent.namespace.clone(),
                    name: parent.name.clone(),
                    section_name: parent.section_name.clone(),
                    port: parent.port,
                };
                counter.increment(&info, route_ns, &[], "UDPRoute", "UDP");
            }
        }
    }

    // TLSRoutes
    if let Ok(list) = Api::<TLSRoute>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for route in list {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
            let hostnames: Vec<HostnameMatch> = route
                .spec
                .hostnames
                .iter()
                .map(|s| {
                    if let Some(rest) = s.strip_prefix("*.") {
                        HostnameMatch::Wildcard(Arc::from(rest))
                    } else {
                        HostnameMatch::Exact(Arc::from(s.as_str()))
                    }
                })
                .collect();
            let parents = route.spec.parent_refs.as_deref().unwrap_or(&[]);
            for parent in parents {
                let info = ParentRefInfo {
                    group: parent.group.clone(),
                    kind: parent.kind.clone(),
                    namespace: parent.namespace.clone(),
                    name: parent.name.clone(),
                    section_name: parent.section_name.clone(),
                    port: parent.port,
                };
                counter.increment(&info, route_ns, &hostnames, "TLSRoute", "TLS");
            }
        }
    }

    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::api::gateway::Gateway;

    #[tokio::test]
    async fn count_attached_routes_counts_accepted_routes() {
        let route_yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-1
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              hostnames:
                - example.com
            status:
              parents:
                - parentRef:
                    name: gw-1
                    namespace: default
                  controllerName: sunbeam.io/gateway-controller
                  conditions:
                    - type: Accepted
                      status: "True"
                      reason: Accepted
                      lastTransitionTime: "2026-01-01T00:00:00Z"
        "#;
        let route: HTTPRoute = serde_yaml::from_str(route_yaml).unwrap();
        let client = kube::Client::new(
            tower::service_fn(move |_req: http::Request<kube::client::Body>| {
                let body = serde_json::json!({
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "HTTPRouteList",
                    "items": [serde_json::to_value(&route).unwrap()]
                });
                async move {
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
        let listeners = vec![ListenerMatch {
            name: "http".to_string(),
            port: 80,
            hostname: None,
            protocol: "HTTP".to_string(),
            allowed: crate::gateway::model::AllowedRoutes::default(),
        }];
        let namespace_labels =
            std::collections::HashMap::<String, std::collections::HashMap<String, String>>::new();
        let counts =
            count_attached_routes(&client, "default", "gw-1", &listeners, &namespace_labels).await;
        assert_eq!(counts, vec![1]);
    }

    #[tokio::test]
    async fn count_attached_routes_filters_by_section_name() {
        let route: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-1
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  sectionName: http
        "#,
        )
        .unwrap();
        let client = kube::Client::new(
            tower::service_fn(move |_req: http::Request<kube::client::Body>| {
                let body = serde_json::json!({
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "HTTPRouteList",
                    "items": [serde_json::to_value(&route).unwrap()]
                });
                async move {
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
        let listeners = vec![
            ListenerMatch {
                name: "http".to_string(),
                port: 80,
                hostname: None,
                protocol: "HTTP".to_string(),
                allowed: crate::gateway::model::AllowedRoutes::default(),
            },
            ListenerMatch {
                name: "https".to_string(),
                port: 443,
                hostname: None,
                protocol: "HTTPS".to_string(),
                allowed: crate::gateway::model::AllowedRoutes::default(),
            },
        ];
        let namespace_labels =
            std::collections::HashMap::<String, std::collections::HashMap<String, String>>::new();
        let counts =
            count_attached_routes(&client, "default", "gw-1", &listeners, &namespace_labels).await;
        assert_eq!(counts, vec![1, 0]);
    }

    #[tokio::test]
    async fn count_attached_routes_filters_and_counts_all_kinds() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
                  hostname: example.com
                  allowedRoutes:
                    namespaces:
                      from: All
                - name: https
                  protocol: HTTPS
                  port: 443
                  hostname: secure.example.com
                  allowedRoutes:
                    namespaces:
                      from: All
                - name: tcp
                  protocol: TCP
                  port: 8080
                  allowedRoutes:
                    namespaces:
                      from: All
                - name: tls
                  protocol: TLS
                  port: 8443
                  hostname: tls.example.com
                  allowedRoutes:
                    namespaces:
                      from: All
                - name: http-same
                  protocol: HTTP
                  port: 8081
                  hostname: same.example.com
                - name: http-kinds
                  protocol: HTTP
                  port: 8082
                  hostname: kinds.example.com
                  allowedRoutes:
                    kinds:
                      - kind: TCPRoute
                - name: udp
                  protocol: UDP
                  port: 9090
                  allowedRoutes:
                    namespaces:
                      from: All
        "#,
        )
        .unwrap();

        let http_route_ok: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-ok
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  sectionName: http
                  port: 80
              hostnames:
                - example.com
        "#,
        )
        .unwrap();
        let http_route_port_mismatch: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-port
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 9999
        "#,
        )
        .unwrap();
        let http_route_section_mismatch: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-section
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  sectionName: other
        "#,
        )
        .unwrap();
        let http_route_wrong_name: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-wrong-name
              namespace: default
            spec:
              parentRefs:
                - name: other-gw
        "#,
        )
        .unwrap();
        let http_route_not_gateway: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-not-gw
              namespace: default
            spec:
              parentRefs:
                - group: example.com
                  kind: Gateway
                  name: gw-1
        "#,
        )
        .unwrap();
        let http_route_other_ns: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-other-ns
              namespace: other
            spec:
              parentRefs:
                - name: gw-1
                  port: 8081
        "#,
        )
        .unwrap();
        let http_route_kind_not_allowed: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-kind
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 8082
              hostnames:
                - kinds.example.com
        "#,
        )
        .unwrap();
        let http_route_no_hostname: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-no-hostname
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 80
              hostnames:
                - other.com
        "#,
        )
        .unwrap();
        let http_routes = vec![
            http_route_ok,
            http_route_port_mismatch,
            http_route_section_mismatch,
            http_route_wrong_name,
            http_route_not_gateway,
            http_route_other_ns,
            http_route_kind_not_allowed,
            http_route_no_hostname,
        ];

        let tcp_route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 8080
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
        "#,
        )
        .unwrap();
        let udp_route: UDPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 9090
              rules:
                - backendRefs:
                    - name: svc
                      port: 53
        "#,
        )
        .unwrap();
        let tls_route: TLSRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 8443
              hostnames:
                - tls.example.com
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
        )
        .unwrap();

        let http_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRouteList",
            "metadata": {},
            "items": serde_json::to_value(&http_routes).unwrap()
        })
        .to_string();
        let tcp_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "TCPRouteList",
            "metadata": {},
            "items": [serde_json::to_value(&tcp_route).unwrap()]
        })
        .to_string();
        let udp_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "UDPRouteList",
            "metadata": {},
            "items": [serde_json::to_value(&udp_route).unwrap()]
        })
        .to_string();
        let tls_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "TLSRouteList",
            "metadata": {},
            "items": [serde_json::to_value(&tls_route).unwrap()]
        })
        .to_string();
        let empty_body =
            serde_json::json!({"apiVersion": "v1", "kind": "List", "metadata": {}, "items": []})
                .to_string();

        let client = kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let http_body = http_body.clone();
                let tcp_body = tcp_body.clone();
                let udp_body = udp_body.clone();
                let tls_body = tls_body.clone();
                let empty_body = empty_body.clone();
                async move {
                    let body = if path.contains("/httproutes") {
                        http_body
                    } else if path.contains("/tcproutes") {
                        tcp_body
                    } else if path.contains("/udproutes") {
                        udp_body
                    } else if path.contains("/tlsroutes") {
                        tls_body
                    } else {
                        empty_body
                    };
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(bytes::Bytes::from(body)))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );
        let listeners = crate::gateway::reconcile::gateway::listeners::listener_matches(&gw);
        let namespace_labels = HashMap::<String, HashMap<String, String>>::new();
        let counts =
            count_attached_routes(&client, "default", "gw-1", &listeners, &namespace_labels).await;
        assert_eq!(counts, vec![1, 0, 1, 1, 0, 0, 1]);
    }
}
