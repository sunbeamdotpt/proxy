// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

        if let Some(obj) = value.as_object_mut() {
            if let Some(target) = obj.get("target").and_then(|v| v.as_str()) {
                let line = event.metadata().line().unwrap_or(0);
                obj.insert(
                    "target".to_string(),
                    serde_json::Value::String(format!("{}:{}", target, line)),
                );
            }
        }

        write!(
            writer,
            "{}",
            serde_json::to_string(&value).map_err(|_| std::fmt::Error)?
        )?;
        writeln!(writer)
    }
}

/// Initialize structured logging. If `otlp_endpoint` is set, tracing output
/// would be shipped to an OTLP collector, but this path is currently TODO —
/// `opentelemetry-otlp` 0.27 changed the `SpanExporter::builder()` API surface
/// and the previous `.with_http()` call no longer compiles. Until the OTLP
/// exporter plumbing is rewritten for 0.27, we emit JSON logs only, even when
/// an OTLP endpoint is provided. Tracked separately.
pub fn init(_otlp_endpoint: &str) {
    let fmt_layer = tracing_subscriber::fmt::layer().event_format(TargetLineFormat(
        tracing_subscriber::fmt::format::Format::default()
            .json()
            .with_current_span(true)
            .with_target(true),
    ));

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
}
