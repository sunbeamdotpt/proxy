<!--
---
title: Sunbeam Proxy
description: A cloud-native reverse proxy with adaptive ML threat detection.
category: overview
nav_order: 1
tags:
  - sunbeam-proxy
  - overview
status: published
visibility: public
---
-->

# Sunbeam Proxy

A cloud-native reverse proxy with adaptive ML threat detection. Built in Rust by [Sunbeam Studios](https://sunbeam.pt).

Sunbeam Proxy learns what normal traffic looks like *for your infrastructure* and adapts its defenses automatically. Instead of relying on generic rulesets written for someone else's problems, it trains on your own audit logs to build behavioral models that protect against the threats you actually face.

## Why it exists

We're a small, women-led queer game studio and we need to handle extraordinary threats on today's internet. We are a small team with an even smallerbudget, but the same DDoS attacks, vulnerability scanners, and bot nets that hit everyone else. Off-the-shelf solutions either cost too much, apply someone else's rules to our traffic, or don't work very well. So we built a proxy that learns from what it sees and gets better at protecting us over time — and we figured others could use it too.

This proxy is running in production at Sunbeam Studios. If you are reading this, you are using it!

## What it does

**Adaptive threat detection** — Two ensemble models (decision tree + MLP) run inline on every request. A per-IP DDoS detector watches behavioral patterns over sliding windows. A per-request scanner detector catches vulnerability probes, directory enumeration, and bot traffic. Both models are compiled directly into the binary as Rust `const` arrays — zero allocation, sub-microsecond inference, no model files to manage.

**Rate limiting** — Leaky bucket throttling with identity-aware keys (session cookies, bearer tokens, or IP fallback). Separate limits for authenticated and unauthenticated traffic.

**HTTP response caching** — Per-route in-memory cache that respects `Cache-Control` and `stale-while-revalidate`, sitting after the security pipeline so blocked requests never touch the cache.

**Static file serving** — Serve frontends directly from the proxy with try_files chains, SPA fallback, content-type detection, and cache headers. Replaces nginx/caddy sidecar containers with a single config block.

**Cluster gossip** — Multi-node deployments share state via an iroh-based gossip protocol. Nodes discover each other through k8s headless services and coordinate bandwidth tracking across the cluster. (more clustering features coming soon!)

**Dual-stack networking** — Native IPv4 + IPv6 support with separate listeners, explicit `IPV6_V6ONLY` socket options, and fair connection scheduling that alternates accept priority so neither stack gets starved.

**Kubernetes Gateway API v1.5** — Full control-plane and data-plane support for `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `UDPRoute`, `TLSRoute`, `ReferenceGrant`, `ListenerSet`, and `BackendTLSPolicy`. Listener hostname matching, TLS termination and passthrough, weighted load balancing, header filters, URL rewrites, request redirects and mirroring, CORS, timeouts, backend TLS, frontend/client-certificate validation, and `allowedRoutes` namespace selection are all supported.

**And the rest** — TLS termination with cert hot-reload, WebSocket forwarding, SSH TCP passthrough, HTTP-to-HTTPS redirect, ACME HTTP-01 challenge routing, Prometheus metrics, and per-request tracing with request IDs.

## Quick start

```sh
cargo build
RUST_LOG=info cargo run
```

## How the models work

Sunbeam uses compiled-in decision tree + MLP ensembles for DDoS and scanner detection. Every request produces a structured audit log that can be fed back into the training pipeline to adapt the models to your traffic. See [docs/threat-detection.md](./docs/threat-detection.md) for the full pipeline, training workflow, and formal verification notes.

## Fair Use

This software is provided as-is, without warranty or support under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). With that, Sunbeam Proxy is free to use for any purpose, including commercial use, for up to 1GiBs of total aggregate cluster bandwidth. Anything beyond that will require a license purchase from Sunbeam Studios. This will support ongoing development and ensure billion-dollar companies don't take advantage of it.

If you're interested in a license, please contact us at [hello@sunbeam.pt](mailto:sunbeam@sunbeam.sh).

---

## Configuration

Sunbeam loads TOML from `$SUNBEAM_CONFIG` or `/etc/sunbeam/config.toml` for global settings (listeners, TLS, telemetry, detectors, clustering), and Kubernetes Gateway API CRDs for all routing.

- [docs/gateway-api.md](./docs/gateway-api.md) — routing with Gateway API.
- [docs/configuration.md](./docs/configuration.md) — full TOML reference.

```toml
[listen]
http  = "0.0.0.0:80"
https = "0.0.0.0:443"

[tls]
cert_path = "/etc/ssl/tls.crt"
key_path  = "/etc/ssl/tls.key"

[telemetry]
otlp_endpoint = ""          # OpenTelemetry OTLP endpoint (empty = disabled)
metrics_port  = 9090         # Prometheus scrape port (0 = disabled)

[kubernetes]
namespace        = "ingress"        # namespace for Secret, ConfigMap, and Ingress watches
tls_secret       = "sunbeam-tls"    # TLS Secret name (watched for cert hot-reload)
config_configmap = "sunbeam-config" # ConfigMap name (watched for config hot-reload)

[ddos]
enabled      = true
threshold    = 0.6
window_secs  = 60
window_capacity = 1000
min_events   = 10
observe_only = false

[scanner]
enabled            = true
threshold          = 0.5
bot_cache_ttl_secs = 86400
observe_only       = false

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

[cluster]
enabled     = true
tenant      = "<your-tenant-ulid>"  # or set SUNBEAM_TENANT_ID; keep the value out of git
gossip_port = 11204

[cluster.discovery]
method           = "k8s"
headless_service = "sunbeam-proxy-gossip.ingress.svc.cluster.local"
```

> **Breaking change in 0.2.0:** the legacy `[[routes]]` TOML format has been removed. All routing is configured through Gateway API resources.

---

## Observability

Sunbeam emits request IDs, Prometheus metrics, and structured audit logs. See [docs/observability.md](./docs/observability.md) for details.

## CLI commands

See [docs/cli.md](./docs/cli.md) for the full command reference.

## Development

See [docs/development.md](./docs/development.md) for build, test, and release instructions.

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See [LICENSE](LICENSE).

Contributions require a signed CLA — see [CONTRIBUTING.md](CONTRIBUTING.md) and [CLA.md](CLA.md) for details.
