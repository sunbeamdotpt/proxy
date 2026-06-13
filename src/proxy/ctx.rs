// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request context and route snapshot types.

use crate::ir::compile::CompiledPlan;
use std::sync::Arc;
use std::time::Instant;

/// Request context — mutable state carried through all Pingora phases.
pub struct RequestCtx {
    /// Compiled execution plan for this request, set by `request_filter`.
    pub plan: Option<Arc<CompiledPlan>>,
    /// Start time.
    pub start_time: Instant,
    /// Unique request identifier (UUID v4).
    pub request_id: String,
    /// Tracing span for this request.
    pub span: tracing::Span,
    /// Resolved solver backend address for this ACME challenge, if applicable.
    pub acme_backend: Option<String>,
    /// Original downstream scheme ("http" or "https"), captured in request_filter.
    pub downstream_scheme: &'static str,
    /// Original downstream TCP port, captured in request_filter.
    pub downstream_port: u16,
    /// Whether this request was served from static files (skip upstream).
    pub served_static: bool,
    /// Captured auth subrequest headers to forward upstream.
    pub auth_headers: Vec<(String, String)>,
    /// Index of the selected backend within `CompiledPlan.upstream.backends`.
    pub backend_index: Option<usize>,
    /// Buffered response body for body rewriting.
    pub body_buffer: Option<Vec<u8>>,
}
