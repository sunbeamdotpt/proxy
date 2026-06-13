// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize structured logging. If `otlp_endpoint` is set, tracing output
/// would be shipped to an OTLP collector, but this path is currently TODO —
/// `opentelemetry-otlp` 0.27 changed the `SpanExporter::builder()` API surface
/// and the previous `.with_http()` call no longer compiles. Until the OTLP
/// exporter plumbing is rewritten for 0.27, we emit JSON logs only, even when
/// an OTLP endpoint is provided. Tracked separately.
pub fn init(_otlp_endpoint: &str) {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_target(true);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
}
