// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::sync::LazyLock;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Global Prometheus registry shared across all proxy workers.
pub(crate) static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::default);

pub static REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new("sunbeam_requests_total", "Total HTTP requests processed"),
        &["method", "host", "status", "backend"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static REQUEST_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    let h = Histogram::with_opts(
        HistogramOpts::new(
            "sunbeam_request_duration_seconds",
            "Request duration in seconds",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]),
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

pub static DDOS_DECISIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new("sunbeam_ddos_decisions_total", "DDoS detection decisions"),
        &["decision"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static SCANNER_DECISIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "sunbeam_scanner_decisions_total",
            "Scanner detection decisions",
        ),
        &["decision", "reason"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static RATE_LIMIT_DECISIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new("sunbeam_rate_limit_decisions_total", "Rate limit decisions"),
        &["decision"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static CACHE_STATUS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new("sunbeam_cache_status_total", "Cache hit/miss counts"),
        &["status"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static ACTIVE_CONNECTIONS: LazyLock<Gauge> = LazyLock::new(|| {
    let g = Gauge::new(
        "sunbeam_active_connections",
        "Number of active connections being processed",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static CLUSTER_PEERS: LazyLock<Gauge> = LazyLock::new(|| {
    let g = Gauge::new("sunbeam_cluster_peers", "Number of active cluster peers").unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static CLUSTER_BANDWIDTH_IN: LazyLock<Gauge> = LazyLock::new(|| {
    let g = Gauge::new(
        "sunbeam_cluster_bandwidth_in_bytes",
        "Total cluster-wide inbound bytes",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static CLUSTER_BANDWIDTH_OUT: LazyLock<Gauge> = LazyLock::new(|| {
    let g = Gauge::new(
        "sunbeam_cluster_bandwidth_out_bytes",
        "Total cluster-wide outbound bytes",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static CLUSTER_GOSSIP_MESSAGES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "sunbeam_cluster_gossip_messages_total",
            "Gossip messages sent and received",
        ),
        &["channel"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static CLUSTER_AGGREGATE_IN_RATE: LazyLock<Gauge> = LazyLock::new(|| {
    let g = Gauge::new(
        "sunbeam_cluster_aggregate_in_bytes_per_sec",
        "Cluster-wide aggregate inbound bandwidth (bytes/sec, sliding window)",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static CLUSTER_AGGREGATE_OUT_RATE: LazyLock<Gauge> = LazyLock::new(|| {
    let g = Gauge::new(
        "sunbeam_cluster_aggregate_out_bytes_per_sec",
        "Cluster-wide aggregate outbound bandwidth (bytes/sec, sliding window)",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static CLUSTER_AGGREGATE_TOTAL_RATE: LazyLock<Gauge> = LazyLock::new(|| {
    let g = Gauge::new(
        "sunbeam_cluster_aggregate_total_bytes_per_sec",
        "Cluster-wide aggregate total bandwidth (bytes/sec, sliding window)",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static BANDWIDTH_LIMIT_DECISIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "sunbeam_bandwidth_limit_decisions_total",
            "Cluster bandwidth limit enforcement decisions",
        ),
        &["decision"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static CLUSTER_MODEL_UPDATES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "sunbeam_cluster_model_updates_total",
            "Model distribution events",
        ),
        &["model_type", "result"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static SCANNER_ENSEMBLE_PATH: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "sunbeam_scanner_ensemble_path_total",
            "Scanner ensemble decision path",
        ),
        &["path"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static DDOS_ENSEMBLE_PATH: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "sunbeam_ddos_ensemble_path_total",
            "DDoS ensemble decision path",
        ),
        &["path"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static GATEWAY_STATE_DRIFT_SECONDS: LazyLock<Gauge> = LazyLock::new(|| {
    let g = Gauge::new(
        "gateway_state_drift_seconds",
        "Maximum age of peer gateway state digests observed by this replica",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Spawn a lightweight HTTP server on `port` serving `/metrics` and `/health`.
/// Returns immediately; the server runs in the background on the tokio runtime.
/// Port 0 = disabled.
fn handle_metrics_request(req: &str) -> (&'static str, &'static str, Vec<u8>) {
    if req.starts_with("GET /metrics") {
        let encoder = TextEncoder::new();
        let families = REGISTRY.gather();
        let mut output = Vec::new();
        encoder.encode(&families, &mut output).unwrap();
        ("200 OK", "text/plain; version=0.0.4", output)
    } else if req.starts_with("GET /health") {
        ("200 OK", "text/plain", b"ok\n".to_vec())
    } else {
        ("404 Not Found", "text/plain", b"not found\n".to_vec())
    }
}

pub fn spawn_metrics_server(port: u16) {
    if port == 0 {
        return;
    }
    tokio::spawn(async move {
        let addr = format!("0.0.0.0:{port}");
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, port, "failed to bind metrics server");
                return;
            }
        };
        tracing::info!(port, "metrics server listening");

        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "metrics accept error");
                    continue;
                }
            };

            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let req = String::from_utf8_lossy(&buf[..n]);

                let (status, content_type, body) = handle_metrics_request(&req);

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_static_metrics_initialize_and_record() {
        REQUESTS_TOTAL
            .with_label_values(&["GET", "example.com", "200", "backend"])
            .inc();
        REQUEST_DURATION.observe(0.01);
        DDOS_DECISIONS.with_label_values(&["allow"]).inc();
        SCANNER_DECISIONS
            .with_label_values(&["block", "reason"])
            .inc();
        RATE_LIMIT_DECISIONS.with_label_values(&["allow"]).inc();
        CACHE_STATUS.with_label_values(&["hit"]).inc();
        ACTIVE_CONNECTIONS.inc();
        CLUSTER_PEERS.set(1.0);
        CLUSTER_BANDWIDTH_IN.set(100.0);
        CLUSTER_BANDWIDTH_OUT.set(100.0);
        CLUSTER_GOSSIP_MESSAGES.with_label_values(&["state"]).inc();
        CLUSTER_AGGREGATE_IN_RATE.set(1.0);
        CLUSTER_AGGREGATE_OUT_RATE.set(2.0);
        CLUSTER_AGGREGATE_TOTAL_RATE.set(3.0);
        BANDWIDTH_LIMIT_DECISIONS
            .with_label_values(&["allow"])
            .inc();
        CLUSTER_MODEL_UPDATES
            .with_label_values(&["ddos", "ok"])
            .inc();
        SCANNER_ENSEMBLE_PATH.with_label_values(&["tree"]).inc();
        DDOS_ENSEMBLE_PATH.with_label_values(&["tree"]).inc();
        GATEWAY_STATE_DRIFT_SECONDS.set(0.5);
        // If every line above compiled and ran, all metrics registered successfully.
    }

    #[test]
    fn handle_metrics_request_returns_prometheus_text() {
        REQUESTS_TOTAL
            .with_label_values(&["GET", "example.com", "200", "backend"])
            .inc_by(3);
        let (status, content_type, body) = handle_metrics_request("GET /metrics HTTP/1.1");
        assert_eq!(status, "200 OK");
        assert_eq!(content_type, "text/plain; version=0.0.4");
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("sunbeam_requests_total"));
        assert!(text.contains("example.com"));
    }

    #[test]
    fn handle_metrics_request_health_returns_ok() {
        let (status, content_type, body) = handle_metrics_request("GET /health HTTP/1.1");
        assert_eq!(status, "200 OK");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, b"ok\n");
    }

    #[test]
    fn handle_metrics_request_unknown_returns_404() {
        let (status, content_type, body) = handle_metrics_request("GET /foo HTTP/1.1");
        assert_eq!(status, "404 Not Found");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, b"not found\n");
    }

    #[test]
    fn spawn_metrics_server_port_zero_is_noop() {
        spawn_metrics_server(0);
    }

    #[tokio::test]
    async fn metrics_server_responds_over_tcp() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        spawn_metrics_server(port);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut resp = String::new();
        let mut buf = vec![0u8; 256];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let n = tokio::time::timeout(remaining, stream.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if n == 0 {
                break;
            }
            resp.push_str(&String::from_utf8_lossy(&buf[..n]));
            if resp.contains("ok\n") {
                break;
            }
        }
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("ok\n"), "{resp}");
    }
}
