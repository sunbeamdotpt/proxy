// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Wrapper around a JSON formatter that appends the source line number to the
/// `target` field as `module::path:line`.
struct TargetLineFormat<F>(F);

impl<F, C, N> FormatEvent<C, N> for TargetLineFormat<F>
where
    F: FormatEvent<C, N>,
    C: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, C, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let mut buf = String::new();
        {
            let buf_writer = Writer::new(&mut buf);
            self.0.format_event(ctx, buf_writer, event)?;
        }

        let mut value: serde_json::Value =
            serde_json::from_str(&buf).map_err(|_| std::fmt::Error)?;

        if let Some(obj) = value.as_object_mut()
            && let Some(target) = obj.get("target").and_then(|v| v.as_str())
        {
            let line = event.metadata().line().unwrap_or(0);
            obj.insert(
                "target".to_string(),
                serde_json::Value::String(format!("{}:{}", target, line)),
            );
        }

        write!(
            writer,
            "{}",
            serde_json::to_string(&value).map_err(|_| std::fmt::Error)?
        )?;
        writeln!(writer)
    }
}

/// Keeps the OTLP tracer provider alive. On drop, the provider flushes and
/// shuts down the batch span processor.
pub struct OtelGuard {
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
}

impl OtelGuard {
    /// Force-flush buffered spans to the collector.
    pub fn force_flush(&self) {
        let _ = self.provider.force_flush();
    }
}

/// The OTLP/HTTP exporter in opentelemetry-otlp 0.32 posts to the configured
/// endpoint verbatim — it does not append the signal path. Users configure
/// the collector base URL (`http://host:4318`), so append `/v1/traces`
/// unless it's already there.
fn normalize_otlp_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    if trimmed.ends_with("/v1/traces") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1/traces")
    }
}

/// Build the OTLP tracer provider on a dedicated OS thread with its own
/// current-thread Tokio runtime. The batch span processor spawns its flush
/// task onto the runtime that was entered when the provider was built, so the
/// runtime must outlive the provider — the thread parks inside `block_on`
/// forever. Neither Pingora's runtime nor the shared application runtime is
/// touched, so exporter failures can never take down request handling.
fn build_otlp_provider(
    endpoint: &str,
) -> Result<opentelemetry_sdk::trace::SdkTracerProvider, String> {
    use opentelemetry_otlp::WithExportConfig;

    let (tx, rx) = std::sync::mpsc::channel();
    let endpoint = normalize_otlp_endpoint(endpoint);
    std::thread::Builder::new()
        .name("otlp-exporter".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(format!("failed to build OTLP runtime: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let result = (|| {
                    let exporter = opentelemetry_otlp::SpanExporter::builder()
                        .with_http()
                        .with_endpoint(&endpoint)
                        .build()
                        .map_err(|e| format!("failed to build OTLP exporter: {e}"))?;
                    let resource = opentelemetry_sdk::Resource::builder()
                        .with_service_name("sunbeam-proxy")
                        .build();
                    Ok::<_, String>(
                        opentelemetry_sdk::trace::SdkTracerProvider::builder()
                            .with_resource(resource)
                            .with_batch_exporter(exporter)
                            .build(),
                    )
                })();
                let ok = result.is_ok();
                if tx.send(result).is_err() || !ok {
                    return;
                }
                // Keep the runtime alive so the batch processor's flush task
                // keeps running for the lifetime of the process.
                std::future::pending::<()>().await
            });
        })
        .map_err(|e| format!("failed to spawn OTLP exporter thread: {e}"))?;
    rx.recv()
        .map_err(|e| format!("OTLP exporter thread died: {e}"))?
}

/// The JSON fmt layer used by [`init`]. `Layer::json()` sets `JsonFields` so
/// span fields are stored as JSON — required because the event format embeds
/// the current span (`with_current_span`) and parses stored span fields as
/// JSON; with the plain-text default formatter, debug builds panic and release
/// builds emit `field_error` junk for every event logged inside a span.
fn json_fmt_layer<S, W>(writer: W) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt::layer()
        .json()
        .event_format(TargetLineFormat(
            tracing_subscriber::fmt::format::Format::default()
                .json()
                .with_current_span(true)
                .with_target(true),
        ))
        .with_writer(writer)
}

/// Initialize structured logging. JSON logs are always emitted. When
/// `otlp_endpoint` is non-empty, spans are additionally exported over
/// OTLP/HTTP protobuf (the collector's 4318 port; `/v1/traces` is appended
/// automatically). Any exporter initialization failure degrades to JSON-only
/// logging — telemetry must never crash the proxy.
///
/// Returns a guard that keeps the tracer provider alive; `None` when OTLP is
/// disabled or failed to initialize.
pub fn init(otlp_endpoint: &str) -> Option<OtelGuard> {
    let fmt_layer = json_fmt_layer(std::io::stdout);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    let provider = if otlp_endpoint.is_empty() {
        None
    } else {
        Some(build_otlp_provider(otlp_endpoint))
    };

    match provider {
        Some(Ok(provider)) => {
            use opentelemetry::trace::TracerProvider as _;
            let tracer = provider.tracer("sunbeam-proxy");
            registry
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .init();
            tracing::info!(endpoint = %otlp_endpoint, "OTLP tracing enabled");
            Some(OtelGuard { provider })
        }
        Some(Err(msg)) => {
            registry.init();
            tracing::warn!(error = %msg, "OTLP initialization failed; JSON logs only");
            None
        }
        None => {
            registry.init();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn otlp_endpoint_gets_traces_path() {
        assert_eq!(
            normalize_otlp_endpoint("http://collector:4318"),
            "http://collector:4318/v1/traces"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://collector:4318/"),
            "http://collector:4318/v1/traces"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://collector:4318/v1/traces"),
            "http://collector:4318/v1/traces"
        );
    }

    /// Regression test for the span-fields panic: events logged inside a span
    /// must embed the span context as valid JSON. Mirrors the production
    /// request span created in `proxy::request_filter`. With the plain-text
    /// default field formatter this panics in debug builds.
    #[test]
    fn json_layer_embeds_span_context_as_valid_json() {
        let buf = SharedBuf::default();
        let subscriber = tracing_subscriber::registry().with(json_fmt_layer(buf.clone()));

        tracing::subscriber::with_default(subscriber, || {
            // Same fields as the production request span.
            let span = tracing::info_span!(
                "request",
                request_id = "r-1",
                method = "GET",
                host = "example.com",
                path = "/",
            );
            span.in_scope(|| tracing::info!(status = 200u16, "request"));
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let line: serde_json::Value =
            serde_json::from_str(out.trim()).expect("log line must be valid JSON");
        let span = &line["span"];
        assert_eq!(
            span["request_id"], "r-1",
            "span fields must be embedded as JSON, got: {out}"
        );
        assert_eq!(span["name"], "request", "got: {out}");
    }
}
