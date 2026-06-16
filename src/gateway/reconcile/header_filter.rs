// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared header-modifier filter parsing for HTTPRoute and GRPCRoute.

/// Expand into the loops that convert a raw *request* header modifier into
/// `RouteFilter::RequestHeader{Set,Add,Remove}` entries.
#[macro_export]
macro_rules! parse_request_header_modifier {
    ($modifier:expr) => {{
        let mut out = ::std::vec::Vec::new();
        if let Some(set) = &$modifier.set {
            for h in set {
                out.push($crate::gateway::model::RouteFilter::RequestHeaderSet {
                    name: ::std::sync::Arc::from(h.name.as_str()),
                    value: ::std::sync::Arc::from(h.value.as_str()),
                });
            }
        }
        if let Some(add) = &$modifier.add {
            for h in add {
                out.push($crate::gateway::model::RouteFilter::RequestHeaderAdd {
                    name: ::std::sync::Arc::from(h.name.as_str()),
                    value: ::std::sync::Arc::from(h.value.as_str()),
                });
            }
        }
        if let Some(remove) = &$modifier.remove {
            for h in remove {
                out.push($crate::gateway::model::RouteFilter::RequestHeaderRemove {
                    name: ::std::sync::Arc::from(h.as_str()),
                });
            }
        }
        out
    }};
}

/// Expand into the loops that convert a raw *response* header modifier into
/// `RouteFilter::ResponseHeader{Set,Add,Remove}` entries.
#[macro_export]
macro_rules! parse_response_header_modifier {
    ($modifier:expr) => {{
        let mut out = ::std::vec::Vec::new();
        if let Some(set) = &$modifier.set {
            for h in set {
                out.push($crate::gateway::model::RouteFilter::ResponseHeaderSet {
                    name: ::std::sync::Arc::from(h.name.as_str()),
                    value: ::std::sync::Arc::from(h.value.as_str()),
                });
            }
        }
        if let Some(add) = &$modifier.add {
            for h in add {
                out.push($crate::gateway::model::RouteFilter::ResponseHeaderAdd {
                    name: ::std::sync::Arc::from(h.name.as_str()),
                    value: ::std::sync::Arc::from(h.value.as_str()),
                });
            }
        }
        if let Some(remove) = &$modifier.remove {
            for h in remove {
                out.push($crate::gateway::model::RouteFilter::ResponseHeaderRemove {
                    name: ::std::sync::Arc::from(h.as_str()),
                });
            }
        }
        out
    }};
}
