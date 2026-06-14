// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Routing model types — the output of the Gateway API reconcile/translate
//! pipeline, consumed by the proxy hot path.

use std::sync::Arc;

/// A compiled route table ready for the proxy hot path.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RouteTable {
    /// Routes indexed by hostname match.
    pub routes: Vec<HostRoute>,
}

/// All rules that share a hostname matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRoute {
    pub hostname: HostnameMatch,
    pub rules: Vec<RouteRule>,
}

/// Hostname matching strategy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HostnameMatch {
    /// Exact hostname (e.g. `www.example.com`).
    Exact(Arc<str>),
    /// Wildcard prefix (e.g. `*.example.com`).
    Wildcard(Arc<str>),
    /// Matches any hostname.
    Any,
}

/// A single rule (matches + action).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRule {
    /// AND of all matchers in this vec (OR across rules is handled by
    /// ordering / iteration in the proxy).
    pub matches: Vec<RouteMatch>,
    /// Weighted backends.  If empty the rule returns 404.
    pub backends: Vec<WeightedBackend>,
    /// Request/response filters to apply.
    pub filters: Vec<RouteFilter>,
}

/// Match criteria for a single rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct RouteMatch {
    pub path: Option<PathMatch>,
    pub headers: Vec<HeaderMatch>,
    pub query_params: Vec<QueryParamMatch>,
    pub method: Option<Arc<str>>,
}

/// Path match type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathMatch {
    Prefix(Arc<str>),
    Exact(Arc<str>),
    Regex(Arc<str>),
}

/// Header match type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HeaderMatch {
    pub name: Arc<str>,
    pub value: HeaderMatchValue,
}

/// Header match value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HeaderMatchValue {
    Exact(Arc<str>),
    Regex(Arc<str>),
    Present,
    Absent,
}

/// Query parameter match type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QueryParamMatch {
    pub name: Arc<str>,
    pub value: QueryParamMatchValue,
}

/// Query parameter match value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum QueryParamMatchValue {
    Exact(Arc<str>),
    Regex(Arc<str>),
}

/// Backend with a traffic-split weight.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WeightedBackend {
    /// Resolved backend target.
    pub backend: Arc<str>,
    /// Weight relative to other backends in the same rule.
    pub weight: u32,
    /// Filters applied only when this backend is selected.
    pub filters: Vec<RouteFilter>,
    /// Protocol to use when communicating with the backend.
    pub protocol: crate::ir::BackendProtocol,
    /// TLS configuration attached by a BackendTLSPolicy or Gateway backend
    /// client certificate.
    pub tls: Option<BackendTlsAttachment>,
}

/// TLS configuration attached to a model backend before translation to IR.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendTlsAttachment {
    /// SNI / validation hostname.
    pub hostname: Arc<str>,
    /// PEM-encoded CA bundle used to verify the backend certificate.
    pub ca_bundle_pem: Arc<str>,
    /// Allowed Subject Alternative Names.
    pub subject_alt_names: Vec<Arc<str>>,
}

/// A fractional value (numerator / denominator) used by RequestMirror.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fraction {
    pub numerator: u32,
    pub denominator: u32,
}

/// A filter applied to a request or response.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RouteFilter {
    /// Set (replace) a request header.
    RequestHeaderSet { name: Arc<str>, value: Arc<str> },
    /// Add (append) a request header.
    RequestHeaderAdd { name: Arc<str>, value: Arc<str> },
    /// Remove a request header.
    RequestHeaderRemove { name: Arc<str> },
    /// Set (replace) a response header.
    ResponseHeaderSet { name: Arc<str>, value: Arc<str> },
    /// Add (append) a response header.
    ResponseHeaderAdd { name: Arc<str>, value: Arc<str> },
    /// Remove a response header.
    ResponseHeaderRemove { name: Arc<str> },
    /// Rewrite the URL path and/or hostname.
    UrlRewrite {
        hostname: Option<Arc<str>>,
        path: Option<PathRewrite>,
    },
    /// Redirect the request.
    RequestRedirect {
        scheme: Option<Arc<str>>,
        hostname: Option<Arc<str>>,
        path: Option<PathRewrite>,
        port: Option<u16>,
        status_code: u16,
    },
    /// Mirror requests to a backend (fire-and-forget).
    RequestMirror {
        backend: Arc<str>,
        fraction: Option<Fraction>,
    },
    /// CORS response header configuration.
    Cors {
        allow_origins: Vec<Arc<str>>,
        allow_methods: Vec<Arc<str>>,
        allow_headers: Vec<Arc<str>>,
        expose_headers: Vec<Arc<str>>,
        max_age: Option<i32>,
        allow_credentials: bool,
    },
}

/// Path rewrite action.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathRewrite {
    FullReplace(Arc<str>),
    PrefixReplace {
        prefix: Arc<str>,
        replacement: Arc<str>,
    },
}

/// HTTP-specific route state produced by the reconciler.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HTTPRouteState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub hostnames: Vec<HostnameMatch>,
    pub rules: Vec<HTTPRouteRule>,
    pub parent_refs: Vec<crate::gateway::model::ParentRef>,
    /// True only when the route is accepted and all backend references resolve.
    pub programmed: bool,
}

/// A rule from an HTTPRoute CRD, pre-parsed but not yet compiled into the
/// proxy's `RouteTable`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HTTPRouteRule {
    pub matches: Vec<RouteMatch>,
    pub backends: Vec<WeightedBackend>,
    pub filters: Vec<RouteFilter>,
    /// Upstream backend request timeout in milliseconds (from `rules.timeouts.backendRequest`).
    pub timeout_ms: Option<u64>,
    /// Total request timeout in milliseconds (from `rules.timeouts.request`).
    pub request_timeout_ms: Option<u64>,
    /// False when one or more backendRefs for this rule could not be resolved.
    pub programmed: bool,
}

/// TCP route state produced by the reconciler.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TCPRouteState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub parent_refs: Vec<crate::gateway::model::ParentRef>,
    pub backends: Vec<WeightedBackend>,
    pub programmed: bool,
}

/// UDP route state produced by the reconciler.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UDPRouteState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub parent_refs: Vec<crate::gateway::model::ParentRef>,
    pub backends: Vec<WeightedBackend>,
    pub programmed: bool,
}

/// TLS route state produced by the reconciler.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSRouteState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub hostnames: Vec<HostnameMatch>,
    pub parent_refs: Vec<crate::gateway::model::ParentRef>,
    pub backends: Vec<WeightedBackend>,
    pub programmed: bool,
}

/// gRPC method match type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MethodMatchType {
    /// Match the exact service/method string.
    Exact,
    /// Match any method within the service.
    Regular,
}

/// gRPC method match criteria.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MethodMatch {
    pub match_type: MethodMatchType,
    /// Fully qualified gRPC service name.
    pub service: Arc<str>,
    /// Method name within the service. None matches any method when type is
    /// Regular; required for Exact.
    pub method: Option<Arc<str>>,
    pub case_sensitive: bool,
}

impl MethodMatch {
    /// Render the match as an exact `:path` pseudo-header value for the proxy.
    /// Returns `None` for non-exact matches.
    pub fn exact_path(&self) -> Option<Arc<str>> {
        if !matches!(self.match_type, MethodMatchType::Exact) {
            return None;
        }
        let method = self.method.as_deref()?;
        Some(Arc::from(format!("/{}/{}", self.service, method)))
    }
}

/// GRPC route state produced by the reconciler.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GRPCRouteState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub hostnames: Vec<HostnameMatch>,
    pub rules: Vec<GRPCRouteRule>,
    pub parent_refs: Vec<crate::gateway::model::ParentRef>,
    /// True only when the route is accepted and all backend references resolve.
    pub programmed: bool,
}

/// A rule from a GRPCRoute CRD, pre-parsed but not yet compiled into the
/// proxy's `RouteTable`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GRPCRouteRule {
    pub name: Option<Arc<str>>,
    pub matches: Vec<GRPCRouteMatch>,
    pub backends: Vec<WeightedBackend>,
    pub filters: Vec<RouteFilter>,
    /// False when one or more backendRefs for this rule could not be resolved.
    pub programmed: bool,
}

/// Match criteria for a single GRPCRoute rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct GRPCRouteMatch {
    pub method: Option<MethodMatch>,
    pub headers: Vec<HeaderMatch>,
}
