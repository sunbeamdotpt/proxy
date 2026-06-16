// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Route / listener translation layer.
//!
//! Converts a `GatewayView` into Pingora-native configuration.

mod from_model;
pub(crate) mod grpc;
pub(crate) mod hostnames;
pub(crate) mod http;
pub(crate) mod ir;
pub(crate) mod l4;

#[cfg(test)]
mod grpc_tests;
#[cfg(test)]
mod hostnames_tests;
#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod ir_tests;
#[cfg(test)]
mod l4_tests;

use crate::gateway::model::HostnameMatch;
use std::sync::Arc;

pub use hostnames::{
    hostname_intersects, intersect_hostname_pair, intersect_hostnames, is_hostname_subset,
};
pub use ir::{translate_view, translate_view_to_ir};

pub(crate) fn parse_listener_hostname(hostname: &str) -> HostnameMatch {
    if let Some(rest) = hostname.strip_prefix("*.") {
        HostnameMatch::Wildcard(Arc::from(rest))
    } else {
        HostnameMatch::Exact(Arc::from(hostname))
    }
}

pub(crate) fn hostname_to_prefix(hostname: &HostnameMatch) -> String {
    match hostname {
        HostnameMatch::Exact(h) => h.to_string(),
        HostnameMatch::Wildcard(h) => format!("*.{}", h),
        HostnameMatch::Any => "*".to_string(),
    }
}

pub(crate) fn to_ir_hostname(h: &HostnameMatch) -> crate::ir::HostnameMatch {
    match h {
        HostnameMatch::Exact(s) => crate::ir::HostnameMatch::Exact(Arc::clone(s)),
        HostnameMatch::Wildcard(s) => crate::ir::HostnameMatch::Wildcard(Arc::clone(s)),
        HostnameMatch::Any => crate::ir::HostnameMatch::Any,
    }
}
