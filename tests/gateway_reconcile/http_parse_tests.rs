// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTPRoute reconciler tests.

use std::sync::Arc;
use sunbeam_proxy::gateway::api::HTTPRoute;
use sunbeam_proxy::gateway::model::{
    Fraction, HeaderMatchValue, HostnameMatch, PathMatch, PathRewrite, QueryParamMatchValue,
    RouteFilter,
};
use sunbeam_proxy::gateway::reconcile::httproute::parse_httproute_state;

use crate::route_test_helpers::route_from_json;

// -----------------------------------------------------------------------------
// Parse tests
// -----------------------------------------------------------------------------

#[test]
fn parse_httproute_state_populates_hostnames_and_rules() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 2 },
        "spec": {
            "hostnames": ["example.com", "*.wildcard.test"],
            "rules": [
                {
                    "matches": [
                        {
                            "path": { "type": "PathPrefix", "value": "/api" },
                            "method": "GET"
                        }
                    ],
                    "backendRefs": [
                        { "name": "svc-1", "port": 8080, "weight": 3 }
                    ]
                }
            ]
        }
    }));

    let state = parse_httproute_state(&route);
    assert_eq!(state.namespace.as_ref(), "default");
    assert_eq!(state.name.as_ref(), "route-1");
    assert_eq!(state.generation, 2);
    assert_eq!(state.hostnames.len(), 2);
    assert_eq!(
        state.hostnames[0],
        HostnameMatch::Exact(Arc::from("example.com"))
    );
    assert_eq!(
        state.hostnames[1],
        HostnameMatch::Wildcard(Arc::from("wildcard.test"))
    );
    assert_eq!(state.rules.len(), 1);
    assert_eq!(state.rules[0].matches.len(), 1);
    assert_eq!(
        state.rules[0].matches[0].path,
        Some(PathMatch::Prefix(Arc::from("/api")))
    );
    assert_eq!(state.rules[0].matches[0].method.as_deref(), Some("GET"));
    assert_eq!(state.rules[0].backends.len(), 1);
    assert_eq!(
        state.rules[0].backends[0].backend.as_ref(),
        "svc-1.default.svc.cluster.local.:8080"
    );
    assert_eq!(state.rules[0].backends[0].weight, 3);
}

#[test]
fn parse_httproute_state_empty_spec() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "empty", "namespace": "ns" },
        "spec": {}
    }));
    let state = parse_httproute_state(&route);
    assert_eq!(state.namespace.as_ref(), "ns");
    assert!(state.hostnames.is_empty());
    assert!(state.rules.is_empty());
    assert!(state.parent_refs.is_empty());
}

#[test]
fn parse_path_match_all_types() {
    let exact = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{"matches": [{"path": {"type": "Exact", "value": "/foo"}}]}]
        }
    }));
    let prefix = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/bar"}}]}]
        }
    }));
    let regex = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{"matches": [{"path": {"type": "RegularExpression", "value": "^/baz$"}}]}]
        }
    }));
    let default_type = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{"matches": [{"path": {"value": "/ defaulted"}}]}]
        }
    }));

    assert_eq!(
        parse_httproute_state(&exact).rules[0].matches[0].path,
        Some(PathMatch::Exact(Arc::from("/foo")))
    );
    assert_eq!(
        parse_httproute_state(&prefix).rules[0].matches[0].path,
        Some(PathMatch::Prefix(Arc::from("/bar")))
    );
    assert_eq!(
        parse_httproute_state(&regex).rules[0].matches[0].path,
        Some(PathMatch::Regex(Arc::from("^/baz$")))
    );
    assert_eq!(
        parse_httproute_state(&default_type).rules[0].matches[0].path,
        Some(PathMatch::Prefix(Arc::from("/ defaulted")))
    );
}

#[test]
fn parse_method_all_variants() {
    for (method, expected) in [
        ("GET", "GET"),
        ("HEAD", "HEAD"),
        ("POST", "POST"),
        ("PUT", "PUT"),
        ("DELETE", "DELETE"),
        ("CONNECT", "CONNECT"),
        ("OPTIONS", "OPTIONS"),
        ("TRACE", "TRACE"),
        ("PATCH", "PATCH"),
    ] {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{"matches": [{"method": method}]}]
            }
        }));
        assert_eq!(
            parse_httproute_state(&route).rules[0].matches[0]
                .method
                .as_deref(),
            Some(expected),
            "method {method}"
        );
    }
}

#[test]
fn parse_backend_ref_defaults() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "rules": [{"backendRefs": [{"name": "svc"}]}]
        }
    }));
    let backend = &parse_httproute_state(&route).rules[0].backends[0];
    assert_eq!(
        backend.backend.as_ref(),
        "svc.default.svc.cluster.local.:80"
    );
    assert_eq!(backend.weight, 1);
}

#[test]
fn parse_backend_ref_cross_namespace_uses_fqdn() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "rules": [{"backendRefs": [{"name": "svc", "namespace": "other", "port": 9090}]}]
        }
    }));
    let backend = &parse_httproute_state(&route).rules[0].backends[0];
    assert_eq!(
        backend.backend.as_ref(),
        "svc.other.svc.cluster.local.:9090"
    );
    assert_eq!(backend.weight, 1);
}

#[test]
fn parse_url_rewrite_filter_replace_prefix_match() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "URLRewrite",
                    "urlRewrite": {
                        "path": {
                            "type": "ReplacePrefixMatch",
                            "replacePrefixMatch": "/v2"
                        }
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::UrlRewrite {
            hostname: None,
            path: Some(PathRewrite::PrefixReplace {
                prefix: Arc::from("/"),
                replacement: Arc::from("/v2"),
            }),
        }
    );
}

#[test]
fn parse_url_rewrite_filter_replace_full_path() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "URLRewrite",
                    "urlRewrite": {
                        "path": {
                            "type": "ReplaceFullPath",
                            "replaceFullPath": "/new"
                        }
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::UrlRewrite {
            hostname: None,
            path: Some(PathRewrite::FullReplace(Arc::from("/new"))),
        }
    );
}

#[test]
fn parse_request_header_modifier_filter() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "RequestHeaderModifier",
                    "requestHeaderModifier": {
                        "set": [{"name": "X-Custom", "value": "val"}]
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::RequestHeaderSet {
            name: Arc::from("X-Custom"),
            value: Arc::from("val"),
        }
    );
}

#[test]
fn parse_response_header_modifier_filter() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "ResponseHeaderModifier",
                    "responseHeaderModifier": {
                        "set": [{"name": "X-Out", "value": "out"}]
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::ResponseHeaderSet {
            name: Arc::from("X-Out"),
            value: Arc::from("out"),
        }
    );
}

#[test]
fn parse_backend_ref_request_header_modifier_filter() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "backendRefs": [{
                    "name": "svc",
                    "port": 8080,
                    "filters": [{
                        "type": "RequestHeaderModifier",
                        "requestHeaderModifier": {
                            "set": [{"name": "X-Backend", "value": "yes"}]
                        }
                    }]
                }]
            }]
        }
    }));
    let backend = &parse_httproute_state(&route).rules[0].backends[0];
    assert_eq!(
        backend.backend.as_ref(),
        "svc.default.svc.cluster.local.:8080"
    );
    assert_eq!(
        backend.filters[0],
        RouteFilter::RequestHeaderSet {
            name: Arc::from("X-Backend"),
            value: Arc::from("yes"),
        }
    );
}

#[test]
fn parse_request_redirect_filter() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "RequestRedirect",
                    "requestRedirect": {
                        "scheme": "https",
                        "hostname": "new.example.com",
                        "port": 8443,
                        "statusCode": 301,
                        "path": {
                            "type": "ReplaceFullPath",
                            "replaceFullPath": "/redirected"
                        }
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::RequestRedirect {
            scheme: Some(Arc::from("https")),
            hostname: Some(Arc::from("new.example.com")),
            port: Some(8443),
            status_code: 301,
            path: Some(PathRewrite::FullReplace(Arc::from("/redirected"))),
        }
    );
}

#[test]
fn parse_request_redirect_filter_defaults() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{"type": "RequestRedirect", "requestRedirect": {}}]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::RequestRedirect {
            scheme: None,
            hostname: None,
            port: None,
            status_code: 302,
            path: None,
        }
    );
}

#[test]
fn parse_request_redirect_replace_prefix() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "RequestRedirect",
                    "requestRedirect": {
                        "path": {
                            "type": "ReplacePrefixMatch",
                            "replacePrefixMatch": "/new-prefix"
                        }
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    match filter {
        RouteFilter::RequestRedirect {
            path:
                Some(PathRewrite::PrefixReplace {
                    prefix,
                    replacement,
                }),
            ..
        } => {
            assert_eq!(prefix.as_ref(), "/");
            assert_eq!(replacement.as_ref(), "/new-prefix");
        }
        _ => panic!("unexpected filter: {filter:?}"),
    }
}

#[test]
fn parse_unknown_filter_type_is_skipped() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "ExtensionRef",
                    "extensionRef": {
                        "group": "example.com",
                        "kind": "Foo",
                        "name": "bar"
                    }
                }]
            }]
        }
    }));
    assert!(parse_httproute_state(&route).rules[0].filters.is_empty());
}

#[test]
fn parse_cors_filter() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "CORS",
                    "cors": {
                        "allowOrigins": ["https://example.com"],
                        "allowMethods": ["GET", "POST"],
                        "allowHeaders": ["X-Custom"],
                        "exposeHeaders": ["X-Response"],
                        "maxAge": 3600,
                        "allowCredentials": true
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::Cors {
            allow_origins: vec![Arc::from("https://example.com")],
            allow_methods: vec![Arc::from("GET"), Arc::from("POST")],
            allow_headers: vec![Arc::from("X-Custom")],
            expose_headers: vec![Arc::from("X-Response")],
            max_age: Some(3600),
            allow_credentials: true,
        }
    );
}

#[test]
fn parse_cors_filter_defaults() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "CORS",
                    "cors": {}
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert!(
        matches!(filter, RouteFilter::Cors { allow_origins, allow_methods, allow_headers, expose_headers, max_age, allow_credentials }
            if allow_origins.is_empty() && allow_methods.is_empty() && allow_headers.is_empty() && expose_headers.is_empty() && max_age.is_none() && !allow_credentials)
    );
}

#[test]
fn parse_request_mirror_filter() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "RequestMirror",
                    "requestMirror": {
                        "backendRef": {
                            "namespace": "mirror-ns",
                            "name": "mirror-svc",
                            "port": 8080
                        }
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::RequestMirror {
            backend: Arc::from("mirror-svc.mirror-ns.svc.cluster.local.:8080"),
            fraction: None,
        }
    );
}

#[test]
fn parse_backend_request_timeout() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "timeouts": { "backendRequest": "30s" },
                "backendRefs": [{"name": "svc"}]
            }]
        }
    }));
    let rule = &parse_httproute_state(&route).rules[0];
    assert_eq!(rule.timeout_ms, Some(30_000));
}

#[test]
fn parse_invalid_backend_request_timeout_is_ignored() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "timeouts": { "backendRequest": "not-a-duration" },
                "backendRefs": [{"name": "svc"}]
            }]
        }
    }));
    let rule = &parse_httproute_state(&route).rules[0];
    assert_eq!(rule.timeout_ms, None);
}

#[test]
fn parse_header_and_query_param_matches() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default", "generation": 1 },
        "spec": {
            "rules": [{
                "matches": [
                    {
                        "headers": [
                            { "name": "X-Version", "value": "v1" },
                            { "name": "X-Debug", "type": "RegularExpression", "value": "on|off" }
                        ],
                        "queryParams": [
                            { "name": "page", "value": "1" },
                            { "name": "filter", "type": "RegularExpression", "value": ".*" }
                        ]
                    }
                ]
            }]
        }
    }))
    .expect("valid HTTPRoute");

    let state = parse_httproute_state(&route);
    let m = &state.rules[0].matches[0];
    assert_eq!(m.headers.len(), 2);
    assert_eq!(m.headers[0].name.as_ref(), "X-Version");
    assert_eq!(m.headers[0].value, HeaderMatchValue::Exact(Arc::from("v1")));
    assert_eq!(m.headers[1].name.as_ref(), "X-Debug");
    assert_eq!(
        m.headers[1].value,
        HeaderMatchValue::Regex(Arc::from("on|off"))
    );

    assert_eq!(m.query_params.len(), 2);
    assert_eq!(m.query_params[0].name.as_ref(), "page");
    assert_eq!(
        m.query_params[0].value,
        QueryParamMatchValue::Exact(Arc::from("1"))
    );
    assert_eq!(m.query_params[1].name.as_ref(), "filter");
    assert_eq!(
        m.query_params[1].value,
        QueryParamMatchValue::Regex(Arc::from(".*"))
    );
}

#[test]
fn parse_url_rewrite_hostname_only() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "URLRewrite",
                    "urlRewrite": { "hostname": "new.example.com" }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::UrlRewrite {
            hostname: Some(Arc::from("new.example.com")),
            path: None,
        }
    );
}

#[test]
fn parse_url_rewrite_empty_returns_none() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "URLRewrite",
                    "urlRewrite": {}
                }]
            }]
        }
    }));
    assert!(parse_httproute_state(&route).rules[0].filters.is_empty());
}

#[test]
fn parse_request_header_modifier_add_remove() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "RequestHeaderModifier",
                    "requestHeaderModifier": {
                        "set": [{"name": "X-Set", "value": "set"}],
                        "add": [{"name": "X-Add", "value": "add"}],
                        "remove": ["X-Remove"]
                    }
                }]
            }]
        }
    }));
    let filters = &parse_httproute_state(&route).rules[0].filters;
    assert_eq!(filters.len(), 3);
    assert_eq!(
        filters[0],
        RouteFilter::RequestHeaderSet {
            name: Arc::from("X-Set"),
            value: Arc::from("set"),
        }
    );
    assert_eq!(
        filters[1],
        RouteFilter::RequestHeaderAdd {
            name: Arc::from("X-Add"),
            value: Arc::from("add"),
        }
    );
    assert_eq!(
        filters[2],
        RouteFilter::RequestHeaderRemove {
            name: Arc::from("X-Remove"),
        }
    );
}

#[test]
fn parse_response_header_modifier_add_remove() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "ResponseHeaderModifier",
                    "responseHeaderModifier": {
                        "set": [{"name": "X-Set", "value": "set"}],
                        "add": [{"name": "X-Add", "value": "add"}],
                        "remove": ["X-Remove"]
                    }
                }]
            }]
        }
    }));
    let filters = &parse_httproute_state(&route).rules[0].filters;
    assert_eq!(filters.len(), 3);
    assert_eq!(
        filters[1],
        RouteFilter::ResponseHeaderAdd {
            name: Arc::from("X-Add"),
            value: Arc::from("add"),
        }
    );
    assert_eq!(
        filters[2],
        RouteFilter::ResponseHeaderRemove {
            name: Arc::from("X-Remove"),
        }
    );
}

#[test]
fn parse_request_mirror_with_fraction() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "RequestMirror",
                    "requestMirror": {
                        "backendRef": { "namespace": "mirror", "name": "svc", "port": 8080 },
                        "fraction": { "numerator": 1, "denominator": 10 }
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::RequestMirror {
            backend: Arc::from("svc.mirror.svc.cluster.local.:8080"),
            fraction: Some(Fraction {
                numerator: 1,
                denominator: 10
            }),
        }
    );
}

#[test]
fn parse_request_mirror_with_percent() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "rules": [{
                "filters": [{
                    "type": "RequestMirror",
                    "requestMirror": {
                        "backendRef": { "name": "svc" },
                        "percent": 50
                    }
                }]
            }]
        }
    }));
    let filter = &parse_httproute_state(&route).rules[0].filters[0];
    assert_eq!(
        *filter,
        RouteFilter::RequestMirror {
            backend: Arc::from("svc.default.svc.cluster.local.:80"),
            fraction: Some(Fraction {
                numerator: 50,
                denominator: 100
            }),
        }
    );
}

#[test]
fn parse_request_timeout() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "timeouts": { "request": "5s" },
                "backendRefs": [{"name": "svc"}]
            }]
        }
    }));
    let rule = &parse_httproute_state(&route).rules[0];
    assert_eq!(rule.request_timeout_ms, Some(5_000));
}

#[test]
fn parse_invalid_request_timeout_is_ignored() {
    let route = route_from_json(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r" },
        "spec": {
            "rules": [{
                "timeouts": { "request": "bad" },
                "backendRefs": [{"name": "svc"}]
            }]
        }
    }));
    let rule = &parse_httproute_state(&route).rules[0];
    assert_eq!(rule.request_timeout_ms, None);
}

// -----------------------------------------------------------------------------
