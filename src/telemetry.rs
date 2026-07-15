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

/// Initialize structured logging. If `otlp_endpoint` is set, tracing output
/// would be shipped to an OTLP collector, but this path is currently TODO —
/// `opentelemetry-otlp` 0.27 changed the `SpanExporter::builder()` API surface
/// and the previous `.with_http()` call no longer compiles. Until the OTLP
/// exporter plumbing is rewritten for 0.27, we emit JSON logs only, even when
/// an OTLP endpoint is provided. Tracked separately.
pub fn init(_otlp_endpoint: &str) {
    let fmt_layer = json_fmt_layer(std::io::stdout);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
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
