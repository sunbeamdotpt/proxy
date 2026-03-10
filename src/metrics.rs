use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::sync::LazyLock;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Global Prometheus registry shared across all proxy workers.
static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::default);

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
        Opts::new(
            "sunbeam_ddos_decisions_total",
            "DDoS detection decisions",
        ),
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
        Opts::new(
            "sunbeam_rate_limit_decisions_total",
            "Rate limit decisions",
        ),
        &["decision"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static CACHE_STATUS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "sunbeam_cache_status_total",
            "Cache hit/miss counts",
        ),
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

/// Spawn a lightweight HTTP server on `port` serving `/metrics` and `/health`.
/// Returns immediately; the server runs in the background on the tokio runtime.
/// Port 0 = disabled.
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

                let (status, content_type, body) = if req.starts_with("GET /metrics") {
                    let encoder = TextEncoder::new();
                    let families = REGISTRY.gather();
                    let mut output = Vec::new();
                    encoder.encode(&families, &mut output).unwrap();
                    ("200 OK", "text/plain; version=0.0.4", output)
                } else if req.starts_with("GET /health") {
                    ("200 OK", "text/plain", b"ok\n".to_vec())
                } else {
                    ("404 Not Found", "text/plain", b"not found\n".to_vec())
                };

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
