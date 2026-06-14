// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway API ListenerSet bindings (v1.5.1).
//!
//! The upstream `gateway-api` crate already generates a strongly-typed
//! `ListenerSet` resource, so we re-export it here for consistency with the
//! other API modules.

pub use gateway_api::apis::standard::listenersets::{
    ListenerSet, ListenerSetListeners, ListenerSetListenersAllowedRoutes,
    ListenerSetListenersAllowedRoutesKinds, ListenerSetListenersAllowedRoutesNamespaces,
    ListenerSetParentRef, ListenerSetSpec, ListenerSetStatus, ListenerSetStatusListeners,
    ListenerSetStatusListenersSupportedKinds,
};
