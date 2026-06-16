// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GRPCRoute reconciler.
//!
//! This is a thin re-export module. The implementation now lives in
//! [`crate::gateway::reconcile::route`] and its `grpc_parse` submodule.

pub use crate::gateway::reconcile::route::grpc_parse::parse_grpcroute_state;
pub use crate::gateway::reconcile::route::{
    reconcile_grpcroute, reconcile_grpcroutes, reconcile_grpcroutes_with_context,
    reconcile_single_grpcroute as reconcile_single, run_grpcroute_controller, GRPCRouteContext,
    GRPCRouteParentStatus, ReconciledGRPCRoute,
};

pub mod controller {
    pub use crate::gateway::reconcile::route::{reconcile_grpcroute, run_grpcroute_controller};
}

pub mod model {
    pub use crate::gateway::reconcile::route::{
        GRPCRouteContext, GRPCRouteParentStatus, ReconciledGRPCRoute,
    };
}

pub mod parse {
    pub use crate::gateway::reconcile::route::grpc_parse::parse_grpcroute_state;
}

pub mod reconcile {
    pub use crate::gateway::reconcile::route::{
        reconcile_grpcroutes, reconcile_grpcroutes_with_context,
        reconcile_single_grpcroute as reconcile_single,
    };
}
