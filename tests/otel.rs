// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration test: spans emitted through `telemetry::init` must reach a real
//! OpenTelemetry collector over OTLP/HTTP. The span under test mirrors the
//! production request span from `src/proxy/request_filter.rs`. Requires
//! Docker; skipped otherwise.

use sdk::testing::OtelCollector;
use sunbeam_proxy::telemetry;

/// Checks the Docker API the same way testcontainers will (bollard honors
/// `DOCKER_HOST`, not docker CLI contexts), and prints setup guidance when
/// the daemon is unreachable.
async fn docker_api_available() -> bool {
    match testcontainers::core::client::docker_client_instance().await {
        Ok(client) => client.ping().await.is_ok(),
        Err(_) => false,
    }
}

/// Poll until the container's published port accepts TCP connections. On
/// lima/colima the macOS-side port forwarder lags behind container start by a
/// moment; exporting during that window drops the batch.
async fn wait_for_port(port: u16, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn otlp_spans_reach_collector() {
    if !docker_api_available().await {
        eprintln!(
            "skipping otlp_spans_reach_collector: Docker API unreachable \
             (set DOCKER_HOST, e.g. unix://$HOME/.lima/docker/sock/docker.sock)"
        );
        return;
    }

    let collector = OtelCollector::new()
        .publish_ports()
        .start()
        .await
        .expect("failed to start otel collector container");
    let endpoint = OtelCollector::endpoint(&collector)
        .await
        .expect("collector endpoint unavailable");
    let port: u16 = endpoint
        .rsplit(':')
        .next()
        .and_then(|p| p.trim_end_matches('/').parse().ok())
        .expect("collector endpoint has no port");
    assert!(
        wait_for_port(port, std::time::Duration::from_secs(30)).await,
        "collector port {port} did not accept TCP connections within 30s"
    );

    let guard = telemetry::init(&endpoint)
        .expect("OTLP exporter should initialize against a reachable collector");

    let span_name = "request";
    {
        // Mirrors the production request span (src/proxy/request_filter.rs).
        let span = tracing::info_span!(
            "request",
            request_id = "otel-integration-test",
            method = "GET",
            host = "otel.test",
            path = "/v1/traces",
        );
        let _enter = span.enter();
        tracing::info!(target = "audit", "integration test event");
    }
    guard.force_flush();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        // The collector logs (including the debug exporter's span dump) to stderr.
        let logs = collector
            .stderr_to_vec()
            .await
            .expect("failed to read collector logs");
        let logs = String::from_utf8_lossy(&logs);
        if logs.contains(span_name) && logs.contains("otel-integration-test") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "collector did not receive span within 30s; logs:\n{logs}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
