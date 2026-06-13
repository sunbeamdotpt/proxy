// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust Gateway API model layer.

pub mod digest;
pub mod routing;
pub mod types;
pub mod view;

pub use digest::compute_digest;
pub use routing::{
    HTTPRouteRule, HTTPRouteState, HeaderMatch, HeaderMatchValue, HostRoute, HostnameMatch,
    PathMatch, PathRewrite, QueryParamMatch, QueryParamMatchValue, RouteFilter, RouteMatch,
    RouteRule, RouteTable, WeightedBackend,
};
pub use types::{
    BackendTarget, ListenerKey, RefResolution, ResolvedRoute, RouteTableDigest, StatusPatch,
};
pub use view::{
    AllowedRoutes, GatewayState, GatewayView, GrantSubject, ListenerModel, ListenerState,
    NamespaceFrom, ParentRef, ReconciledView, ReferenceGrantState, RouteGroupKind, RouteNamespaces,
    RouteState,
};
