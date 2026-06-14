// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-Rust Gateway API model layer.

pub mod digest;
pub mod routing;
pub mod types;
pub mod view;

pub use digest::compute_digest;
pub use routing::{
    Fraction, GRPCRouteMatch, GRPCRouteRule, GRPCRouteState, HTTPRouteRule, HTTPRouteState,
    HeaderMatch, HeaderMatchValue, HostRoute, HostnameMatch, MethodMatch, MethodMatchType,
    PathMatch, PathRewrite, QueryParamMatch, QueryParamMatchValue, RouteFilter, RouteMatch,
    RouteRule, RouteTable, TCPRouteState, TLSRouteState, UDPRouteState, WeightedBackend,
};
pub use types::{
    BackendTarget, ListenerKey, RefResolution, ResolvedRoute, RouteTableDigest, StatusPatch,
};
pub use view::{
    AllowedRoutes, GatewayState, GatewayView, GrantSubject, ListenerAllowedMap, ListenerModel,
    ListenerSetState, ListenerState, NamespaceFrom, NamespaceLabels, ParentRef, ReconciledView,
    ReferenceGrantState, RouteGroupKind, RouteNamespaces, RouteState, TlsMode,
};
