// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `impl From<gateway_model::T> for ir::T` conversions.
//!
//! These keep the translation layer free of repetitive match arms and let the
//! IR types be constructed directly from the Gateway API model types.

use crate::gateway::model as gw;
use crate::ir;
use std::sync::Arc;

impl From<&gw::PathMatch> for ir::PathMatch {
    fn from(value: &gw::PathMatch) -> Self {
        match value {
            gw::PathMatch::Prefix(p) => ir::PathMatch::Prefix(Arc::clone(p)),
            gw::PathMatch::Exact(p) => ir::PathMatch::Exact(Arc::clone(p)),
            gw::PathMatch::Regex(p) => ir::PathMatch::Regex(Arc::clone(p)),
        }
    }
}

impl From<&gw::PathRewrite> for ir::PathRewrite {
    fn from(value: &gw::PathRewrite) -> Self {
        match value {
            gw::PathRewrite::FullReplace(t) => ir::PathRewrite::FullReplace(Arc::clone(t)),
            gw::PathRewrite::PrefixReplace {
                prefix,
                replacement,
            } => ir::PathRewrite::PrefixReplace {
                prefix: Arc::clone(prefix),
                replacement: Arc::clone(replacement),
            },
        }
    }
}

impl From<&gw::HeaderMatchValue> for ir::HeaderMatchValue {
    fn from(value: &gw::HeaderMatchValue) -> Self {
        match value {
            gw::HeaderMatchValue::Exact(v) => ir::HeaderMatchValue::Exact(Arc::clone(v)),
            gw::HeaderMatchValue::Regex(v) => ir::HeaderMatchValue::Regex(Arc::clone(v)),
            gw::HeaderMatchValue::Present => ir::HeaderMatchValue::Present,
            gw::HeaderMatchValue::Absent => ir::HeaderMatchValue::Absent,
        }
    }
}

impl From<&gw::HeaderMatch> for ir::HeaderMatch {
    fn from(value: &gw::HeaderMatch) -> Self {
        ir::HeaderMatch {
            name: Arc::clone(&value.name),
            value: ir::HeaderMatchValue::from(&value.value),
        }
    }
}

impl From<&gw::QueryParamMatchValue> for ir::QueryParamMatchValue {
    fn from(value: &gw::QueryParamMatchValue) -> Self {
        match value {
            gw::QueryParamMatchValue::Exact(v) => ir::QueryParamMatchValue::Exact(Arc::clone(v)),
            gw::QueryParamMatchValue::Regex(v) => ir::QueryParamMatchValue::Regex(Arc::clone(v)),
        }
    }
}

impl From<&gw::QueryParamMatch> for ir::QueryParamMatch {
    fn from(value: &gw::QueryParamMatch) -> Self {
        ir::QueryParamMatch {
            name: Arc::clone(&value.name),
            value: ir::QueryParamMatchValue::from(&value.value),
        }
    }
}

impl From<&gw::RouteMatch> for ir::RequestMatch {
    fn from(value: &gw::RouteMatch) -> Self {
        ir::RequestMatch {
            path: value.path.as_ref().map(ir::PathMatch::from),
            method: value.method.as_ref().map(Arc::clone),
            headers: value.headers.iter().map(ir::HeaderMatch::from).collect(),
            query_params: value
                .query_params
                .iter()
                .map(ir::QueryParamMatch::from)
                .collect(),
        }
    }
}

impl From<&gw::WeightedBackend> for ir::WeightedBackend {
    fn from(value: &gw::WeightedBackend) -> Self {
        ir::WeightedBackend {
            backend: Arc::clone(&value.backend),
            weight: value.weight,
            request_filters: value
                .filters
                .iter()
                .flat_map(route_filter_to_request_filters)
                .collect(),
            protocol: value.protocol,
            tls: value.tls.as_ref().map(|t| ir::BackendTlsConfig {
                sni: Arc::clone(&t.hostname),
                verify_hostname: true,
                alternative_cn: None,
                client_cert_id: None,
                ca_bundle_pem: if t.ca_bundle_pem.is_empty() {
                    None
                } else {
                    Some(Arc::clone(&t.ca_bundle_pem))
                },
                subject_alt_names: t.subject_alt_names.clone(),
            }),
        }
    }
}

fn route_filter_to_request_filters(filter: &gw::RouteFilter) -> Vec<ir::RequestFilter> {
    match filter {
        gw::RouteFilter::RequestHeaderSet { name, value } => vec![ir::RequestFilter::SetHeader {
            name: Arc::clone(name),
            value: Arc::clone(value),
        }],
        gw::RouteFilter::RequestHeaderAdd { name, value } => vec![ir::RequestFilter::AddHeader {
            name: Arc::clone(name),
            value: Arc::clone(value),
        }],
        gw::RouteFilter::RequestHeaderRemove { name } => {
            vec![ir::RequestFilter::RemoveHeader(Arc::clone(name))]
        }
        gw::RouteFilter::UrlRewrite { hostname, path } => {
            let mut out = Vec::new();
            if let Some(hostname) = hostname {
                out.push(ir::RequestFilter::RewriteHostname(Arc::clone(hostname)));
            }
            if let Some(path) = path {
                out.push(ir::RequestFilter::RewritePath(ir::PathRewrite::from(path)));
            }
            out
        }
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_match_from_model() {
        assert_eq!(
            ir::PathMatch::from(&gw::PathMatch::Prefix("/api".into())),
            ir::PathMatch::Prefix("/api".into())
        );
        assert_eq!(
            ir::PathMatch::from(&gw::PathMatch::Exact("/health".into())),
            ir::PathMatch::Exact("/health".into())
        );
    }

    #[test]
    fn request_match_from_model() {
        let gw_match = gw::RouteMatch {
            path: Some(gw::PathMatch::Prefix("/v1".into())),
            method: Some("GET".into()),
            headers: vec![gw::HeaderMatch {
                name: "Accept".into(),
                value: gw::HeaderMatchValue::Exact("application/json".into()),
            }],
            query_params: vec![gw::QueryParamMatch {
                name: "page".into(),
                value: gw::QueryParamMatchValue::Exact("1".into()),
            }],
        };
        let ir_match = ir::RequestMatch::from(&gw_match);
        assert_eq!(ir_match.path, Some(ir::PathMatch::Prefix("/v1".into())));
        assert_eq!(ir_match.method, Some("GET".into()));
        assert_eq!(ir_match.headers.len(), 1);
        assert_eq!(ir_match.query_params.len(), 1);
    }

    #[test]
    fn weighted_backend_from_model() {
        let wb = gw::WeightedBackend {
            backend: "http://svc:8080".into(),
            weight: 3,
            protocol: crate::ir::BackendProtocol::Http,
            filters: vec![],
            tls: None,
        };
        let ir_wb = ir::WeightedBackend::from(&wb);
        assert_eq!(ir_wb.backend.as_ref(), "http://svc:8080");
        assert_eq!(ir_wb.weight, 3);
    }

    #[test]
    fn weighted_backend_request_filters_from_model() {
        let wb = gw::WeightedBackend {
            backend: "http://svc:8080".into(),
            weight: 1,
            protocol: crate::ir::BackendProtocol::Http,
            filters: vec![
                gw::RouteFilter::RequestHeaderSet {
                    name: "X-Backend".into(),
                    value: "yes".into(),
                },
                gw::RouteFilter::ResponseHeaderSet {
                    name: "X-Out".into(),
                    value: "yes".into(),
                },
            ],
            tls: None,
        };
        let ir_wb = ir::WeightedBackend::from(&wb);
        assert_eq!(ir_wb.request_filters.len(), 1);
        assert_eq!(
            ir_wb.request_filters[0],
            ir::RequestFilter::SetHeader {
                name: "X-Backend".into(),
                value: "yes".into(),
            }
        );
    }

    #[test]
    fn path_match_regex_from_model() {
        assert_eq!(
            ir::PathMatch::from(&gw::PathMatch::Regex("/api/.*".into())),
            ir::PathMatch::Regex("/api/.*".into())
        );
    }

    #[test]
    fn path_rewrite_from_model() {
        assert_eq!(
            ir::PathRewrite::from(&gw::PathRewrite::FullReplace("/new".into())),
            ir::PathRewrite::FullReplace("/new".into())
        );
        assert_eq!(
            ir::PathRewrite::from(&gw::PathRewrite::PrefixReplace {
                prefix: "/old".into(),
                replacement: "/new".into(),
            }),
            ir::PathRewrite::PrefixReplace {
                prefix: "/old".into(),
                replacement: "/new".into(),
            }
        );
    }

    #[test]
    fn header_match_value_from_model() {
        assert_eq!(
            ir::HeaderMatchValue::from(&gw::HeaderMatchValue::Exact("v".into())),
            ir::HeaderMatchValue::Exact("v".into())
        );
        assert_eq!(
            ir::HeaderMatchValue::from(&gw::HeaderMatchValue::Regex("v.*".into())),
            ir::HeaderMatchValue::Regex("v.*".into())
        );
        assert_eq!(
            ir::HeaderMatchValue::from(&gw::HeaderMatchValue::Present),
            ir::HeaderMatchValue::Present
        );
        assert_eq!(
            ir::HeaderMatchValue::from(&gw::HeaderMatchValue::Absent),
            ir::HeaderMatchValue::Absent
        );
    }

    #[test]
    fn query_param_match_value_regex_from_model() {
        assert_eq!(
            ir::QueryParamMatchValue::from(&gw::QueryParamMatchValue::Regex(".*".into())),
            ir::QueryParamMatchValue::Regex(".*".into())
        );
    }

    #[test]
    fn route_match_empty_optional_from_model() {
        let gw_match = gw::RouteMatch {
            path: None,
            method: None,
            headers: vec![],
            query_params: vec![],
        };
        let ir_match = ir::RequestMatch::from(&gw_match);
        assert!(ir_match.path.is_none());
        assert!(ir_match.method.is_none());
        assert!(ir_match.headers.is_empty());
        assert!(ir_match.query_params.is_empty());
    }

    #[test]
    fn weighted_backend_tls_from_model() {
        let empty_ca = gw::WeightedBackend {
            backend: "https://svc:8443".into(),
            weight: 5,
            protocol: crate::ir::BackendProtocol::Https,
            filters: vec![],
            tls: Some(gw::BackendTlsAttachment {
                hostname: "svc.example.com".into(),
                ca_bundle_pem: "".into(),
                subject_alt_names: vec!["svc.example.com".into()],
            }),
        };
        let ir_wb = ir::WeightedBackend::from(&empty_ca);
        assert_eq!(ir_wb.backend.as_ref(), "https://svc:8443");
        assert!(ir_wb.tls.is_some());
        let tls = ir_wb.tls.unwrap();
        assert_eq!(tls.sni.as_ref(), "svc.example.com");
        assert!(tls.verify_hostname);
        assert!(tls.ca_bundle_pem.is_none());
        assert_eq!(tls.subject_alt_names.len(), 1);

        let with_ca = gw::WeightedBackend {
            backend: "https://svc:8443".into(),
            weight: 5,
            protocol: crate::ir::BackendProtocol::Https,
            filters: vec![],
            tls: Some(gw::BackendTlsAttachment {
                hostname: "svc.example.com".into(),
                ca_bundle_pem: "PEM".into(),
                subject_alt_names: vec![],
            }),
        };
        let ir_wb = ir::WeightedBackend::from(&with_ca);
        assert_eq!(
            ir_wb.tls.as_ref().unwrap().ca_bundle_pem.as_deref(),
            Some("PEM")
        );
        assert!(ir_wb.tls.as_ref().unwrap().subject_alt_names.is_empty());
    }

    #[test]
    fn route_filter_to_request_filters_all_request_arms() {
        let filters = vec![
            gw::RouteFilter::RequestHeaderSet {
                name: "X-Set".into(),
                value: "a".into(),
            },
            gw::RouteFilter::RequestHeaderAdd {
                name: "X-Add".into(),
                value: "b".into(),
            },
            gw::RouteFilter::RequestHeaderRemove {
                name: "X-Remove".into(),
            },
            gw::RouteFilter::UrlRewrite {
                hostname: Some("example.com".into()),
                path: Some(gw::PathRewrite::FullReplace("/path".into())),
            },
            gw::RouteFilter::UrlRewrite {
                hostname: Some("host-only.example.com".into()),
                path: None,
            },
            gw::RouteFilter::UrlRewrite {
                hostname: None,
                path: Some(gw::PathRewrite::PrefixReplace {
                    prefix: "/old".into(),
                    replacement: "/new".into(),
                }),
            },
            gw::RouteFilter::ResponseHeaderSet {
                name: "X-Out".into(),
                value: "c".into(),
            },
            gw::RouteFilter::RequestRedirect {
                scheme: None,
                hostname: None,
                path: None,
                port: None,
                status_code: 301,
            },
            gw::RouteFilter::RequestMirror {
                backend: "http://mirror".into(),
                fraction: None,
            },
            gw::RouteFilter::Cors {
                allow_origins: vec![],
                allow_methods: vec![],
                allow_headers: vec![],
                expose_headers: vec![],
                max_age: None,
                allow_credentials: false,
            },
        ];
        let ir_filters: Vec<_> = filters
            .iter()
            .flat_map(route_filter_to_request_filters)
            .collect();
        assert_eq!(
            ir_filters,
            vec![
                ir::RequestFilter::SetHeader {
                    name: "X-Set".into(),
                    value: "a".into(),
                },
                ir::RequestFilter::AddHeader {
                    name: "X-Add".into(),
                    value: "b".into(),
                },
                ir::RequestFilter::RemoveHeader("X-Remove".into()),
                ir::RequestFilter::RewriteHostname("example.com".into()),
                ir::RequestFilter::RewritePath(ir::PathRewrite::FullReplace("/path".into())),
                ir::RequestFilter::RewriteHostname("host-only.example.com".into()),
                ir::RequestFilter::RewritePath(ir::PathRewrite::PrefixReplace {
                    prefix: "/old".into(),
                    replacement: "/new".into(),
                }),
            ]
        );
    }
}
