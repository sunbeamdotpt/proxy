// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical reconciled view of the Gateway API object graph.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::routing::{GRPCRouteState, HTTPRouteState, TCPRouteState, TLSRouteState, UDPRouteState};

/// Alias used by the reconcile and translate modules.
pub type GatewayView = ReconciledView;

/// Map from (namespace, name, listener_name) to the `AllowedRoutes` configured
/// on that listener (Gateway or ListenerSet).
pub type ListenerAllowedMap = BTreeMap<(Arc<str>, Arc<str>, Arc<str>), AllowedRoutes>;

/// Labels on every namespace, used by `allowedRoutes.namespaces` selectors.
pub type NamespaceLabels = BTreeMap<Arc<str>, BTreeMap<Arc<str>, Arc<str>>>;

/// The full reconciled state produced by the Gateway API controller.
///
/// This struct is intentionally cheap to clone (all strings are
/// [`Arc<str>`]) and is the input to both the hot-reload path and
/// the cluster-gossip digest computation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReconciledView {
    pub gateways: Vec<GatewayState>,
    pub listener_sets: Vec<ListenerSetState>,
    pub routes: Vec<RouteState>,
    pub http_routes: Vec<HTTPRouteState>,
    pub grpc_routes: Vec<GRPCRouteState>,
    pub tcp_routes: Vec<TCPRouteState>,
    pub udp_routes: Vec<UDPRouteState>,
    pub tls_routes: Vec<TLSRouteState>,
    pub reference_grants: Vec<ReferenceGrantState>,
    pub backend_tls_policies: Vec<BackendTLSPolicyState>,
    /// Labels on each namespace, used by `allowedRoutes.namespaces` selectors.
    pub namespace_labels: NamespaceLabels,
    /// Allowed routes configured on each Gateway listener, keyed by
    /// (namespace, name, listener_name).
    pub listener_allowed: ListenerAllowedMap,
    /// Allowed routes configured on each ListenerSet listener, keyed by
    /// (namespace, name, listener_name).
    pub listener_set_allowed: ListenerAllowedMap,
}

/// Frontend client-certificate validation configuration attached to a listener.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FrontendValidation {
    /// PEM-encoded CA certificate bundle used to validate client certificates.
    pub ca_bundle_pem: Arc<str>,
    /// When true, clients without a valid certificate are still allowed.
    pub allow_insecure_fallback: bool,
}

/// Stub for the reconciled state of a single Gateway resource.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GatewayState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub listeners: Vec<ListenerState>,
    /// Optional identifier for a Gateway-wide backend client certificate.
    pub backend_client_cert_id: Option<Arc<str>>,
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    /// Optional frontend client-certificate validation configuration.
    pub frontend_validation: Option<FrontendValidation>,
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
    pub group: Arc<str>,
    pub kind: Arc<str>,
    pub namespace: Option<Arc<str>>,
    pub name: Arc<str>,
    pub section_name: Option<Arc<str>>,
    /// Listener port requested by the parentRef, if any.
    pub port: Option<u16>,
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
    /// No namespaces are allowed (used for Gateway `allowedListeners` default).
    None,
}

/// Namespace selector from a listener's `allowedRoutes.namespaces` field.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct RouteNamespaces {
    pub from: NamespaceFrom,
    pub selector: Option<BTreeMap<String, String>>,
}

/// Stub for the reconciled state of a single ListenerSet resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ListenerSetState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    /// Creation timestamp as Unix seconds; used for ListenerSet precedence
    /// ordering during conflict resolution (oldest first).
    pub created_at: i64,
    pub parent_ref: ParentRef,
    pub listeners: Vec<ListenerState>,
    /// Map of listener name -> conflict reason ("HostnameConflict" or
    /// "ProtocolConflict") for listeners that overlap with a higher-precedence
    /// listener on the same parent Gateway.
    pub conflicts: BTreeMap<Arc<str>, Arc<str>>,
    pub accepted: bool,
    pub programmed: bool,
    pub reason: Arc<str>,
    /// Per-listener certificate validation errors. When present, the listener's
    /// `ResolvedRefs` condition is False with this reason.
    pub listener_cert_errors: Vec<Option<Arc<str>>>,
    /// Per-listener route kind validation errors. When present, the listener's
    /// `ResolvedRefs` condition is False with this reason.
    pub listener_kind_errors: Vec<Option<Arc<str>>>,
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

/// Reconciled state of a single `BackendTLSPolicy` resource.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BackendTLSPolicyState {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub created_at: i64,
    pub target: ServiceTargetRef,
    pub hostname: Arc<str>,
    pub ca_certificate_refs: Vec<CaCertificateRef>,
    pub ca_bundle_pem: Arc<str>,
    pub subject_alt_names: Vec<SubjectAltName>,
    pub accepted: bool,
    pub accepted_reason: Arc<str>,
    pub accepted_message: Arc<str>,
    pub resolved_refs: bool,
    pub resolved_refs_reason: Arc<str>,
    pub resolved_refs_message: Arc<str>,
    pub programmed: bool,
}

/// Target Service reference extracted from a `BackendTLSPolicy` `targetRef`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceTargetRef {
    pub group: Arc<str>,
    pub kind: Arc<str>,
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub section_name: Option<Arc<str>>,
}

/// Normalized CA certificate reference from a `BackendTLSPolicy`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CaCertificateRef {
    pub group: Arc<str>,
    pub kind: Arc<str>,
    pub name: Arc<str>,
}

/// Normalized SubjectAltName entry from a `BackendTLSPolicy`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubjectAltName {
    pub r#type: Arc<str>,
    pub value: Arc<str>,
}
