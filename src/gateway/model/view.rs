// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical reconciled view of the Gateway API object graph.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::routing::{HTTPRouteState, TCPRouteState, TLSRouteState, UDPRouteState};

/// Alias used by the reconcile and translate modules.
pub type GatewayView = ReconciledView;

/// The full reconciled state produced by the Gateway API controller.
///
/// This struct is intentionally cheap to clone (all strings are
/// [`Arc<str>`]) and is the input to both the hot-reload path and
/// the cluster-gossip digest computation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReconciledView {
    pub gateways: Vec<GatewayState>,
    pub routes: Vec<RouteState>,
    pub http_routes: Vec<HTTPRouteState>,
    pub tcp_routes: Vec<TCPRouteState>,
    pub udp_routes: Vec<UDPRouteState>,
    pub tls_routes: Vec<TLSRouteState>,
    pub reference_grants: Vec<ReferenceGrantState>,
}

/// Stub for the reconciled state of a single Gateway resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GatewayState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub listeners: Vec<ListenerState>,
}

/// Alias used by the listener integration module.
pub type ListenerModel = ListenerState;

/// TLS termination mode for a TLS or HTTPS listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum TlsMode {
    /// TLS is terminated at the gateway and the plaintext stream is routed.
    #[default]
    Terminate,
    /// TLS is forwarded verbatim to the backend (SNI-based routing).
    Passthrough,
}

/// Stub for a listener attached to a [`GatewayState`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerState {
    pub name: Arc<str>,
    pub protocol: Arc<str>,
    pub port: u16,
    /// Hostname configured on the listener (e.g. `example.org` or
    /// `*.example.org`).  When a route has no hostnames of its own this
    /// value becomes the effective hostname.
    pub hostname: Option<Arc<str>>,
    /// TLS termination mode. `None` for plain HTTP/TCP/UDP listeners.
    pub tls_mode: Option<TlsMode>,
}

/// Stub for the reconciled state of a single HTTPRoute / TLSRoute /
/// TCPRoute / UDPRoute resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub kind: Arc<str>,
    pub generation: i64,
    pub parent_refs: Vec<ParentRef>,
}

/// A reference from a route to its parent gateway/listener.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ParentRef {
    pub namespace: Option<Arc<str>>,
    pub name: Arc<str>,
    pub section_name: Option<Arc<str>>,
}

/// Allowed route kinds and namespaces for a Gateway listener.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct AllowedRoutes {
    pub kinds: Vec<RouteGroupKind>,
    pub namespaces: RouteNamespaces,
}

/// A route kind allowed by a listener's `allowedRoutes.kinds` list.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteGroupKind {
    pub group: Arc<str>,
    pub kind: Arc<str>,
}

/// Namespace scope from a listener's `allowedRoutes.namespaces` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum NamespaceFrom {
    #[default]
    Same,
    All,
    Selector,
}

/// Namespace selector from a listener's `allowedRoutes.namespaces` field.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct RouteNamespaces {
    pub from: NamespaceFrom,
    pub selector: Option<BTreeMap<String, String>>,
}

/// Stub for the reconciled state of a single ReferenceGrant resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReferenceGrantState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub from: Vec<GrantSubject>,
    pub to: Vec<GrantSubject>,
}

/// Subject used inside a [`ReferenceGrantState`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GrantSubject {
    pub group: Arc<str>,
    pub kind: Arc<str>,
    pub namespace: Option<Arc<str>>,
    pub name: Option<Arc<str>>,
}
