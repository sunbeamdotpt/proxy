# Sunbeam Proxy

A cloud-native reverse proxy with adaptive ML threat detection. Built on [Pingora](https://github.com/cloudflare/pingora) by [Sunbeam Studios](https://sunbeam.pt).

Sunbeam Proxy learns what normal traffic looks like *for your infrastructure* and adapts its defenses automatically. Instead of relying on generic rulesets written for someone else's problems, it trains on your own audit logs to build behavioral models that protect against the threats you actually face.

## Why it exists

We're a small, women-led queer game studio and we need to handle extraordinary threats on today's internet. Small team, small budget, but the same DDoS attacks, vulnerability scanners, and bot nets that hit everyone else. Off-the-shelf solutions either cost too much or apply someone else's rules to our traffic. So we built a proxy that learns from what it sees and gets better at protecting us over time — and we figured others could use it too.

## What it does

**Adaptive threat detection** — Two ML models run in the request pipeline. A KNN-based DDoS detector classifies per-IP behavior over sliding windows. A logistic regression scanner detector catches vulnerability probes, directory enumeration, and bot traffic per-request. Both models train on your logs, hot-reload without downtime, and improve continuously as your traffic evolves.

**Rate limiting** — Leaky bucket throttling with identity-aware keys (session cookies, bearer tokens, or IP fallback). Separate limits for authenticated and unauthenticated traffic.

**HTTP response caching** — Per-route in-memory cache backed by pingora-cache. Respects `Cache-Control`, supports `stale-while-revalidate`, sits after the security pipeline so blocked requests never touch the cache.

**Static file serving** — Serve frontends directly from the proxy with try_files chains, SPA fallback, content-type detection, and cache headers. Replaces nginx/caddy sidecar containers with a single config block.

**Everything else** — TLS termination with cert hot-reload, host-prefix routing, path sub-routes with prefix stripping, regex URL rewrites, response body rewriting (nginx `sub_filter`), auth subrequests, WebSocket forwarding, SSH TCP passthrough, HTTP-to-HTTPS redirect, ACME HTTP-01 challenge routing, Prometheus metrics, and per-request tracing.

## Quick start

```sh
cargo build
SUNBEAM_CONFIG=dev.toml RUST_LOG=info cargo run
cargo test
```

## The self-learning loop

```
              your traffic
                  │
                  ▼
    ┌─────────────────────────┐
    │      Sunbeam Proxy      │
    │                         │
    │  DDoS ──► Scanner ──►   │──── audit logs (JSON)
    │  Rate Limit ──► Cache   │         │
    └─────────────────────────┘         │
                                        ▼
                                ┌───────────────┐
                                │  Train models  │
                                │  on your logs  │
                                └───────┬───────┘
                                        │
                                   hot-reload
                                        │
                                        ▼
                               updated models
                            (no restart needed)
```

Every request produces a structured audit log with 15+ behavioral features. Feed those logs back into the training pipeline and the models get better at telling your real users apart from threats — no manual rule-writing required.

```sh
# Train DDoS model from your audit logs
cargo run -- train-ddos --input logs.jsonl --output ddos_model.bin --heuristics heuristics.toml

# Train scanner model (--csic mixes in the CSIC 2010 dataset as a base)
cargo run -- train-scanner --input logs.jsonl --output scanner_model.bin --csic

# Replay logs to evaluate model accuracy
cargo run -- replay-ddos --input logs.jsonl --model ddos_model.bin
```

## Detection pipeline

Every HTTPS request passes through three layers before reaching your backend:

| Layer | Model | Granularity | Response |
|-------|-------|-------------|----------|
| DDoS | KNN (14-feature behavioral vectors) | Per-IP over sliding window | 429 + Retry-After |
| Scanner | Logistic regression (path, UA, headers) | Per-request | 403 |
| Rate limit | Leaky bucket | Per-identity (session/token/IP) | 429 + Retry-After |

Verified bots (Googlebot, Bingbot, etc.) bypass scanner detection via reverse-DNS verification and configurable allowlists.

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

---

## Configuration reference

All configuration is TOML, loaded from `$SUNBEAM_CONFIG` or `/etc/pingora/config.toml`.

### Listeners and TLS

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

### Kubernetes

Resource names and namespaces for the cert/config watchers and ACME Ingress routing. Override these if you've renamed the namespace, TLS Secret, or ConfigMap from the defaults.

```toml
[kubernetes]
namespace        = "ingress"        # namespace for Secret, ConfigMap, and Ingress watches
tls_secret       = "pingora-tls"    # TLS Secret name (watched for cert hot-reload)
config_configmap = "pingora-config" # ConfigMap name (watched for config hot-reload)
```

All three fields default to the values shown above, so the section can be omitted entirely if you're using the standard naming.

### Routes

Each route maps a host prefix to a backend. `host_prefix = "docs"` matches requests to `docs.<your-domain>`.

```toml
[[routes]]
host_prefix = "docs"
backend     = "http://docs-backend.default.svc.cluster.local:8080"
websocket   = false                    # forward WebSocket upgrade headers
disable_secure_redirection = false     # true = allow plain HTTP
```

#### Path sub-routes

Path sub-routes use longest-prefix matching within a host, so you can mix static file serving with API proxying on the same domain.

```toml
[[routes.paths]]
prefix       = "/api"
backend      = "http://api-backend:8000"
strip_prefix = true                    # /api/users → /users
websocket    = false
```

#### Static file serving

When a route has `static_root` set, the proxy tries to serve files from disk before forwarding to the upstream backend. Candidates are checked in order:

1. `$static_root/$uri` — exact file
2. `$static_root/$uri.html` — with `.html` extension
3. `$static_root/$uri/index.html` — directory index
4. `$static_root/$fallback` — SPA fallback

If nothing matches, the request goes to the backend as usual.

```toml
[[routes]]
host_prefix = "meet"
backend     = "http://meet-backend:8080"
static_root = "/srv/meet"
fallback    = "index.html"
```

Content types are detected by file extension:

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

Cache-control headers are set automatically:

| Extensions | Cache-Control |
|-----------|-------------|
| `js`, `css`, `woff2`, `wasm` | `public, max-age=31536000, immutable` |
| `png`, `jpg`, `svg`, `ico` | `public, max-age=86400` |
| Everything else | `no-cache` |

Path sub-routes always take priority over static serving. Path traversal (`..`) is rejected.

#### URL rewrites

Regex patterns are compiled at startup and applied before static file lookup. First match wins.

```toml
[[routes.rewrites]]
pattern = "^/docs/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/?$"
target  = "/docs/[id]/index.html"
```

#### Response body rewriting

Find/replace on response bodies, like nginx `sub_filter`. Only applies to `text/html`, `application/javascript`, and `text/javascript` responses — binary responses pass through untouched.

The full response is buffered before substitution (fine for HTML/JS, typically under 1MB). `Content-Length` is removed since the body size may change.

```toml
[[routes.body_rewrites]]
find    = "old-domain.example.com"
replace = "new-domain.sunbeam.pt"
```

#### Custom response headers

```toml
[[routes.response_headers]]
name  = "X-Frame-Options"
value = "DENY"
```

#### Auth subrequests

Path routes can require an HTTP auth check before forwarding upstream, similar to nginx `auth_request`.

```toml
[[routes.paths]]
prefix               = "/media"
backend              = "http://seaweedfs-filer:8333"
strip_prefix         = true
auth_request         = "http://drive-backend/api/v1.0/items/media-auth/"
auth_capture_headers = ["Authorization", "X-Amz-Date", "X-Amz-Content-Sha256"]
upstream_path_prefix = "/sunbeam-drive/"
```

The proxy sends a GET to `auth_request` with the original `Cookie`, `Authorization`, and `X-Original-URI` headers.

| Auth response | Result |
|--------------|--------|
| 2xx | Capture specified headers, forward to backend |
| Non-2xx | 403 to client |
| Network error | 502 to client |

#### HTTP response cache

Per-route in-memory cache backed by pingora-cache.

```toml
[routes.cache]
enabled                     = true
default_ttl_secs            = 60      # TTL when upstream has no Cache-Control
stale_while_revalidate_secs = 0       # serve stale while revalidating
max_file_size               = 0       # max cacheable body size (0 = unlimited)
```

The cache sits after the security pipeline (`Request → DDoS → Scanner → Rate Limit → Cache → Upstream`), so blocked requests never populate it.

- Only caches GET and HEAD requests
- Respects `Cache-Control: no-store` and `Cache-Control: private`
- TTL priority: `s-maxage` > `max-age` > `default_ttl_secs`
- Skips routes with body rewrites (content varies per-response)
- Skips requests with auth subrequest headers (content varies per-user)
- Cache key: `{host}{path}?{query}`

### SSH passthrough

Raw TCP proxy for SSH traffic.

```toml
[ssh]
listen  = "0.0.0.0:22"
backend = "gitea-ssh.devtools.svc.cluster.local:2222"
```

### DDoS detection

KNN-based per-IP behavioral classification over sliding windows. 14-feature vectors cover request rate, path diversity, error rate, cookie/referer presence, and more.

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

### Scanner detection

Logistic regression per-request classification with verified bot allowlist and model hot-reload.

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

### Rate limiting

Leaky bucket per-identity throttling. Identity is resolved as: session cookie > bearer token > client IP.

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

Every request gets a UUID v4 request ID, attached to a `tracing::info_span!` so all log lines within the request inherit it. The ID is forwarded upstream and returned to clients via the `X-Request-Id` header.

### Prometheus metrics

Served at `GET /metrics` on `metrics_port` (default 9090). `GET /health` returns 200 for k8s probes.

| Metric | Type | Labels |
|--------|------|--------|
| `sunbeam_requests_total` | Counter | `method`, `host`, `status`, `backend` |
| `sunbeam_request_duration_seconds` | Histogram | — |
| `sunbeam_ddos_decisions_total` | Counter | `decision` |
| `sunbeam_scanner_decisions_total` | Counter | `decision`, `reason` |
| `sunbeam_rate_limit_decisions_total` | Counter | `decision` |
| `sunbeam_cache_status_total` | Counter | `status` |
| `sunbeam_active_connections` | Gauge | — |

```yaml
# Prometheus scrape config
- job_name: sunbeam-proxy
  static_configs:
    - targets: ['sunbeam-proxy.ingress.svc.cluster.local:9090']
```

### Audit logs

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

### Detection pipeline logs

Each security layer logs its decision before acting, so the training pipeline always sees the full traffic picture:

```
layer=ddos       → all HTTPS traffic
layer=scanner    → traffic that passed DDoS
layer=rate_limit → traffic that passed scanner
```

---

## CLI commands

```sh
# Start the proxy server
sunbeam-proxy serve [--upgrade]

# Train DDoS model from audit logs
sunbeam-proxy train-ddos --input logs.jsonl --output ddos_model.bin \
    [--attack-ips ips.txt] [--normal-ips ips.txt] \
    [--heuristics heuristics.toml] [--k 5] [--threshold 0.6]

# Replay logs through the DDoS detection pipeline
sunbeam-proxy replay-ddos --input logs.jsonl --model ddos_model.bin \
    [--config config.toml] [--rate-limit]

# Train scanner model
sunbeam-proxy train-scanner --input logs.jsonl --output scanner_model.bin \
    [--wordlists path/to/wordlists] [--threshold 0.5]

# Train scanner model with CSIC 2010 base dataset (auto-downloaded, cached locally)
sunbeam-proxy train-scanner --input logs.jsonl --output scanner_model.bin --csic
```

---

## Building

```sh
cargo build                                              # debug
cargo build --release --target x86_64-unknown-linux-musl  # release (container)
cargo test                                                # all tests
cargo clippy -- -D warnings                               # lint
```

## License

Apache License 2.0. See [LICENSE](LICENSE).

Contributions require a signed CLA — see [CONTRIBUTING.md](CONTRIBUTING.md) and [CLA.md](CLA.md) for details.
