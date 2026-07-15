---
title: Configuration Reference
description: TOML settings for listeners, TLS, telemetry, detectors, and clustering.
category: user-guide
order: 2
parent: README.md
tags:
  - config
  - toml
  - reference
status: published
visibility: public
related:
  - gateway-api.md
  - observability.md
---

# Configuration Reference

Sunbeam loads TOML from `$SUNBEAM_CONFIG` or `/etc/sunbeam/config.toml` for global settings. All routing is configured through Kubernetes Gateway API CRDs — see [gateway-api.md](./gateway-api.md).

> **Breaking change in 0.2.0:** the legacy `[[routes]]` TOML format has been removed.

## Listeners and TLS

```toml
[listen]
http  = "0.0.0.0:80"
https = "0.0.0.0:443"

[tls]
cert_path = "/etc/ssl/tls.crt"
key_path  = "/etc/ssl/tls.key"
```

## Telemetry

```toml
[telemetry]
otlp_endpoint = "http://otel-collector:4318"  # OTLP/HTTP endpoint (empty = disabled)
metrics_port  = 9090                          # Prometheus scrape port (0 = disabled)
```

When `otlp_endpoint` is set, request spans are exported to an OTLP collector
over HTTP/protobuf (`/v1/traces` is appended automatically — use the
collector's HTTP port, 4318). Spans are flushed in batches from a dedicated
background thread; if the collector is unreachable or initialization fails,
the proxy logs a warning and continues with JSON logs only.

## Forwarding

```toml
x_forwarded_for = true  # default: false
```

When enabled, the proxy sets the `X-Forwarded-For` header on upstream requests
to the resolved client IP (resolved via `trusted_proxy_cidrs` rules). Any
client-supplied value is replaced, preventing header spoofing. Disabled by
default.

## Kubernetes

Resource names and namespaces for the cert/config watchers and ACME Ingress routing.

```toml
[kubernetes]
namespace        = "ingress"        # namespace for Secret, ConfigMap, and Ingress watches
tls_secret       = "sunbeam-tls"    # TLS Secret name (watched for cert hot-reload)
config_configmap = "sunbeam-config" # ConfigMap name (watched for config hot-reload)
```

All three fields default to the values shown above, so the section can be omitted if you use the standard naming.

## SSH passthrough

```toml
[ssh]
listen  = "0.0.0.0:22"
backend = "gitea-ssh.devtools.svc.cluster.local:2222"
```

## DDoS detection

Per-IP behavioral classification over sliding windows using a compiled-in decision tree + MLP ensemble. 14-feature vectors cover request rate, path diversity, error rate, burst patterns, cookie/referer presence, and more.

```toml
[ddos]
enabled         = true
threshold       = 0.6
window_secs     = 60
window_capacity = 1000
min_events      = 10
observe_only    = false    # log decisions without blocking (shadow mode)
```

## Scanner detection

Per-request classification with a compiled-in decision tree + MLP ensemble. 12-feature vectors cover path structure, header presence, user-agent classification, and traversal patterns. Verified bot allowlist with reverse-DNS verification.

```toml
[scanner]
enabled            = true
threshold          = 0.5
bot_cache_ttl_secs = 86400
observe_only       = false

[[scanner.allowlist]]
ua_prefix    = "Googlebot"
reason       = "Google crawler"
dns_suffixes = ["googlebot.com", "google.com"]
cidrs        = ["66.249.64.0/19"]
```

## Rate limiting

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

## Cluster

Gossip-based multi-node coordination. Nodes discover each other through k8s headless DNS and share bandwidth telemetry.

```toml
[cluster]
enabled     = true
tenant      = "your-tenant-uuid"
gossip_port = 11204

[cluster.discovery]
method           = "k8s"
headless_service = "sunbeam-proxy-gossip.ingress.svc.cluster.local"

[cluster.bandwidth]
broadcast_interval_secs = 1
stale_peer_timeout_secs = 30
meter_window_secs       = 30
```
