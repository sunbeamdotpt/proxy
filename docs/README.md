---
layout: default
title: Sunbeam Proxy Documentation
description: Configuration reference and feature documentation for Sunbeam Proxy
toc: true
---

# Sunbeam Proxy Documentation

Complete reference for configuring and operating Sunbeam Proxy — a TLS-terminating reverse proxy built on [Pingora](https://github.com/cloudflare/pingora) 0.8.

## Quick Start

```sh
# Local development
SUNBEAM_CONFIG=dev.toml RUST_LOG=info cargo run

# Run tests
cargo nextest run

# Build release (linux-musl for containers)
cargo build --release --target x86_64-unknown-linux-musl
```

---

## Configuration Reference

Configuration is TOML, loaded from `$SUNBEAM_CONFIG` or `/etc/pingora/config.toml`.

### Listeners & TLS

```toml
[listen]
http  = "0.0.0.0:80"
https = "0.0.0.0:443"

[tls]
cert_path = "/etc/ssl/tls.crt"
key_path  = "/etc/ssl/tls.key"
```

### Telemetry

```toml
[telemetry]
otlp_endpoint = ""         # OpenTelemetry OTLP endpoint (empty = disabled)
metrics_port  = 9090        # Prometheus scrape port (0 = disabled)
```

### Routes

Each route maps a host prefix to a backend. `host_prefix = "docs"` matches requests to `docs.<your-domain>`.

```toml
[[routes]]
host_prefix = "docs"
backend     = "http://docs-backend.default.svc.cluster.local:8080"
websocket   = false                    # forward WebSocket upgrade headers
disable_secure_redirection = false     # true = allow plain HTTP
```

#### Path Sub-Routes

Longest-prefix match within a host. Mix static serving with API proxying.

```toml
[[routes.paths]]
prefix       = "/api"
backend      = "http://api-backend:8000"
strip_prefix = true                    # /api/users → /users
websocket    = false
```

#### Static File Serving

Serve frontends directly from the proxy. The try_files chain checks candidates in order:

1. `$static_root/$uri` — exact file
2. `$static_root/$uri.html` — with `.html` extension
3. `$static_root/$uri/index.html` — directory index
4. `$static_root/$fallback` — SPA fallback

If nothing matches, the request falls through to the upstream backend.

```toml
[[routes]]
host_prefix = "meet"
backend     = "http://meet-backend:8080"
static_root = "/srv/meet"
fallback    = "index.html"
```

**Content-type detection** is based on file extension:

| Extensions | Content-Type |
|-----------|-------------|
| `html`, `htm` | `text/html; charset=utf-8` |
| `css` | `text/css; charset=utf-8` |
| `js`, `mjs` | `application/javascript; charset=utf-8` |
| `json` | `application/json; charset=utf-8` |
| `svg` | `image/svg+xml` |
| `png`, `jpg`, `gif`, `webp`, `avif` | `image/*` |
| `woff`, `woff2`, `ttf`, `otf` | `font/*` |
| `wasm` | `application/wasm` |

**Cache-control headers** are set per extension type:

| Extensions | Cache-Control |
|-----------|-------------|
| `js`, `css`, `woff2`, `wasm` | `public, max-age=31536000, immutable` |
| `png`, `jpg`, `svg`, `ico` | `public, max-age=86400` |
| Everything else | `no-cache` |

Path sub-routes take priority over static serving — if `/api` matches a path route, it goes to that backend even if a static file exists.

Path traversal (`..`) is rejected and falls through to the upstream.

#### URL Rewrites

Regex patterns compiled at startup, applied before static file lookup. First match wins.

```toml
[[routes.rewrites]]
pattern = "^/docs/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/?$"
target  = "/docs/[id]/index.html"
```

#### Response Body Rewriting

Find/replace in response bodies, like nginx `sub_filter`. Only applies to `text/html`, `application/javascript`, and `text/javascript` responses. Binary responses pass through untouched.

The entire response is buffered in memory before substitution (fine for HTML/JS — typically <1MB). `Content-Length` is removed since the body size may change.

```toml
[[routes.body_rewrites]]
find    = "old-domain.example.com"
replace = "new-domain.sunbeam.pt"
```

#### Custom Response Headers

```toml
[[routes.response_headers]]
name  = "X-Frame-Options"
value = "DENY"
```

#### Auth Subrequests

Gate path routes with an HTTP auth check before forwarding upstream. Similar to nginx `auth_request`.

```toml
[[routes.paths]]
prefix               = "/media"
backend              = "http://seaweedfs-filer:8333"
strip_prefix         = true
auth_request         = "http://drive-backend/api/v1.0/items/media-auth/"
auth_capture_headers = ["Authorization", "X-Amz-Date", "X-Amz-Content-Sha256"]
upstream_path_prefix = "/sunbeam-drive/"
```

The auth subrequest sends a GET to `auth_request` with the original `Cookie`, `Authorization`, and `X-Original-URI` headers.

| Auth response | Proxy behavior |
|--------------|----------------|
| 2xx | Capture specified headers, forward to backend |
| Non-2xx | Return 403 to client |
| Network error | Return 502 to client |

#### HTTP Response Cache

Per-route in-memory cache backed by pingora-cache.

```toml
[routes.cache]
enabled                     = true
default_ttl_secs            = 60      # TTL when upstream has no Cache-Control
stale_while_revalidate_secs = 0       # serve stale while revalidating
max_file_size               = 0       # max cacheable body size (0 = unlimited)
```

**Pipeline position**: Cache runs after the security pipeline and before upstream modifications.

```
Request → DDoS → Scanner → Rate Limit → Cache → Upstream
```

Cache behavior:
- Only caches GET and HEAD requests
- Respects `Cache-Control: no-store` and `Cache-Control: private`
- TTL priority: `s-maxage` > `max-age` > `default_ttl_secs`
- Skips routes with body rewrites (content varies)
- Skips requests with auth subrequest headers (per-user content)
- Cache key: `{host}{path}?{query}`

### SSH Passthrough

Raw TCP proxy for SSH traffic.

```toml
[ssh]
listen  = "0.0.0.0:22"
backend = "gitea-ssh.devtools.svc.cluster.local:2222"
```

### DDoS Detection

KNN-based per-IP behavioral classification over sliding windows.

```toml
[ddos]
enabled         = true
model_path      = "ddos_model.bin"
k               = 5
threshold       = 0.6
window_secs     = 60
window_capacity = 1000
min_events      = 10
```

### Scanner Detection

Logistic regression per-request classification with verified bot allowlist.

```toml
[scanner]
enabled            = true
model_path         = "scanner_model.bin"
threshold          = 0.5
poll_interval_secs = 30        # hot-reload check interval (0 = disabled)
bot_cache_ttl_secs = 86400     # verified bot IP cache TTL

[[scanner.allowlist]]
ua_prefix    = "Googlebot"
reason       = "Google crawler"
dns_suffixes = ["googlebot.com", "google.com"]
cidrs        = ["66.249.64.0/19"]
```

### Rate Limiting

Leaky bucket per-identity throttling. Identity resolution: `ory_kratos_session` cookie > Bearer token > client IP.

```toml
[rate_limit]
enabled                = true
eviction_interval_secs = 300
stale_after_secs       = 600
bypass_cidrs           = ["10.42.0.0/16"]

[rate_limit.authenticated]
burst = 200
rate  = 50.0

[rate_limit.unauthenticated]
burst = 50
rate  = 10.0
```

---

## Observability

### Request IDs

Every request gets a UUID v4 request ID. It's:
- Attached to a `tracing::info_span!` so all log lines within the request inherit it
- Forwarded upstream via `X-Request-Id`
- Returned to clients via `X-Request-Id`
- Included in audit log lines

### Prometheus Metrics

Served at `GET /metrics` on `metrics_port` (default 9090).

| Metric | Type | Labels |
|--------|------|--------|
| `sunbeam_requests_total` | Counter | `method`, `host`, `status`, `backend` |
| `sunbeam_request_duration_seconds` | Histogram | — |
| `sunbeam_ddos_decisions_total` | Counter | `decision` |
| `sunbeam_scanner_decisions_total` | Counter | `decision`, `reason` |
| `sunbeam_rate_limit_decisions_total` | Counter | `decision` |
| `sunbeam_cache_status_total` | Counter | `status` |
| `sunbeam_active_connections` | Gauge | — |

`GET /health` returns 200 for k8s probes.

```yaml
# Prometheus scrape config
- job_name: sunbeam-proxy
  static_configs:
    - targets: ['sunbeam-proxy.ingress.svc.cluster.local:9090']
```

### Audit Logs

Every request produces a structured JSON log line (`target = "audit"`):

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "method": "GET",
  "host": "docs.sunbeam.pt",
  "path": "/api/v1/pages",
  "query": "limit=10",
  "client_ip": "203.0.113.42",
  "status": 200,
  "duration_ms": 23,
  "content_length": 0,
  "user_agent": "Mozilla/5.0 ...",
  "referer": "https://docs.sunbeam.pt/",
  "accept_language": "en-US",
  "accept": "text/html",
  "has_cookies": true,
  "cf_country": "FR",
  "backend": "http://docs-backend:8080",
  "error": null
}
```

### Detection Pipeline Logs

Each security layer emits a `target = "pipeline"` log line before acting:

```
layer=ddos       → all HTTPS traffic (scanner training data)
layer=scanner    → traffic that passed DDoS (rate-limit training data)
layer=rate_limit → traffic that passed scanner
```

This guarantees training pipelines always see the full traffic picture.

---

## CLI Commands

```sh
# Start the proxy server
sunbeam-proxy serve [--upgrade]

# Train DDoS model from audit logs
sunbeam-proxy train --input logs.jsonl --output ddos_model.bin \
    [--attack-ips ips.txt] [--normal-ips ips.txt] \
    [--heuristics heuristics.toml] [--k 5] [--threshold 0.6]

# Replay logs through detection pipeline
sunbeam-proxy replay --input logs.jsonl --model ddos_model.bin \
    [--config config.toml] [--rate-limit]

# Train scanner model
sunbeam-proxy train-scanner --input logs.jsonl --output scanner_model.bin \
    [--wordlists path/to/wordlists] [--threshold 0.5]
```

---

## Architecture

### Source Files

```
src/main.rs          — server bootstrap, watcher spawn, SSH spawn
src/lib.rs           — library crate root
src/config.rs        — TOML config deserialization
src/proxy.rs         — ProxyHttp impl: routing, filtering, caching, logging
src/acme.rs          — Ingress watcher for ACME HTTP-01 challenges
src/watcher.rs       — Secret/ConfigMap watcher for cert + config hot-reload
src/cert.rs          — K8s Secret → cert files on disk
src/telemetry.rs     — JSON logging + OTEL tracing init
src/ssh.rs           — TCP proxy for SSH passthrough
src/metrics.rs       — Prometheus metrics and scrape endpoint
src/static_files.rs  — Static file serving with try_files chain
src/cache.rs         — pingora-cache MemCache backend
src/ddos/            — KNN-based DDoS detection
src/scanner/         — Logistic regression scanner detection
src/rate_limit/      — Leaky bucket rate limiter
src/dual_stack.rs    — Dual-stack (IPv4+IPv6) TCP listener
```

### Runtime Model

Pingora manages its own async runtime. K8s watchers (cert/config, Ingress) each run on separate OS threads with their own tokio runtimes. This isolation is deliberate — Pingora's internal runtime has specific constraints that don't mix with general-purpose async work.

### Security Pipeline

```
Request
  │
  ├── DDoS detection (KNN per-IP)
  │     └── blocked → 429
  │
  ├── Scanner detection (logistic regression per-request)
  │     └── blocked → 403
  │
  ├── Rate limiting (leaky bucket per-identity)
  │     └── blocked → 429
  │
  ├── Cache lookup
  │     └── hit → serve cached response
  │
  └── Upstream request
        ├── Auth subrequest (if configured)
        ├── Response body rewriting (if configured)
        └── Response to client
```
