# Sunbeam Proxy

A cloud-native reverse proxy with adaptive ML threat detection. Built on [Pingora](https://github.com/cloudflare/pingora) by [Sunbeam Studios](https://sunbeam.pt).

Sunbeam Proxy learns what normal traffic looks like *for your infrastructure* and automatically adapts its defenses. Instead of relying on generic rulesets written for someone else's problems, it trains on your own audit logs to build behavioral models that protect against the threats you actually face.

## Why It Exists

We are a small, women-led queer game studio and we need to be able to handle extraordinary threats in today's internet. We have a small team and a small budget, so we need to be able to do more with less. We also need to be able to scale up quickly when we need to without having to worry about the security of our infrastructure. However, the problems faced in different regions, and with different bot nets, DDoS attacks, and other threats, make it difficult to find a scalable solution.

## What it does

**Adaptive threat detection** — Two ML models run in the request pipeline. A KNN-based DDoS detector classifies per-IP behavior over sliding windows. A logistic regression scanner detector catches vulnerability probes, directory enumeration, and bot traffic per-request. Both models are trained on your logs, hot-reloaded without downtime, and continuously improvable as your traffic evolves.

**Rate limiting** — Leaky bucket throttling with identity-aware keys (session cookies, bearer tokens, or IP fallback). Separate limits for authenticated and unauthenticated traffic. 256-shard concurrent map, zero contention.

**HTTP response caching** — Per-route in-memory cache backed by pingora-cache. Respects `Cache-Control`, supports `stale-while-revalidate`, and sits after the security pipeline so blocked requests never touch the cache.

**Static file serving** — Serve frontends directly from the proxy with try_files chains, SPA fallback, content-type detection, and cache headers. Replace nginx/caddy sidecar containers with a single config block.

**Everything else you need from a reverse proxy** — TLS termination with cert hot-reload, host-prefix routing, path sub-routes with prefix stripping, regex URL rewrites, response body rewriting (like nginx `sub_filter`), auth subrequests, WebSocket forwarding, SSH TCP passthrough, HTTP-to-HTTPS redirect, ACME HTTP-01 challenge routing, and Prometheus metrics with request tracing.

## Quick start

```sh
cargo build
SUNBEAM_CONFIG=dev.toml RUST_LOG=info cargo run
```

See [docs/](docs/README.md) for full configuration reference.

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

Every request produces a structured audit log with 15+ behavioral features. Feed those logs back into the training pipeline and the models get better at distinguishing your real users from threats — automatically, without manual rule-writing.

```sh
# Train DDoS model from your audit logs
cargo run -- train --input logs.jsonl --output ddos_model.bin --heuristics heuristics.toml

# Train scanner model
cargo run -- train-scanner --input logs.jsonl --output scanner_model.bin

# Replay logs to evaluate model accuracy
cargo run -- replay --input logs.jsonl --model ddos_model.bin
```

## Detection pipeline

Every HTTPS request passes through three detection layers before reaching your backend:

| Layer | Model | Granularity | Response |
|-------|-------|-------------|----------|
| DDoS | KNN (14-feature behavioral vectors) | Per-IP over sliding window | 429 + Retry-After |
| Scanner | Logistic regression (path, UA, headers) | Per-request | 403 |
| Rate limit | Leaky bucket | Per-identity (session/token/IP) | 429 + Retry-After |

Verified bots (Googlebot, Bingbot, etc.) bypass scanner detection via reverse-DNS verification and configurable allowlists.

## Configuration

Everything is TOML. Here's a route that serves a frontend statically with an API backend, response body rewriting, caching, and custom headers:

```toml
[[routes]]
host_prefix  = "docs"
backend      = "http://docs-backend:8080"
static_root  = "/srv/docs"
fallback     = "index.html"

[routes.cache]
enabled          = true
default_ttl_secs = 300

[[routes.rewrites]]
pattern = "^/docs/[0-9a-f-]+/?$"
target  = "/docs/[id]/index.html"

[[routes.body_rewrites]]
find    = "old-domain.example.com"
replace = "docs.sunbeam.pt"

[[routes.response_headers]]
name  = "X-Frame-Options"
value = "DENY"

[[routes.paths]]
prefix       = "/api"
backend      = "http://docs-api:8000"
strip_prefix = true
```

## Observability

- **Request IDs**: UUID v4 per request, forwarded via `X-Request-Id` to upstreams and clients
- **Prometheus metrics**: `GET /metrics` on configurable port — request totals, latency histograms, detection decisions, cache hit rates, active connections
- **Health checks**: `GET /health` returns 200 for k8s probes
- **Structured audit logs**: JSON with request ID, client IP, timing, headers, backend, detection decisions

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
