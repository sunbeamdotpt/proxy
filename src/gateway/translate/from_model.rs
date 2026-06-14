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
}
