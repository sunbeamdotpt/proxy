// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
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

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if otlp_endpoint.is_empty() {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    } else {
        // Build the OTLP exporter gracefully — if it fails (bad URL, missing
        // deps, etc.) log a warning and fall back to JSON-only logging so the
        // proxy keeps serving traffic instead of panicking.
        match opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(otlp_endpoint)
            .build()
        {
            Ok(exporter) => {
                let provider = opentelemetry_sdk::trace::TracerProvider::builder()
                    .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
                    .build();

                opentelemetry::global::set_tracer_provider(provider.clone());
                let tracer = provider.tracer("sunbeam-proxy");
                let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(fmt_layer)
                    .with(otel_layer)
                    .init();
            }
            Err(err) => {
                // Fall back to fmt-only so the proxy still starts.
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(fmt_layer)
                    .init();
                eprintln!(
                    "WARNING: OTLP exporter failed to initialise, tracing disabled: {err}"
                );
            }
        }
    }
}
