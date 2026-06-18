---
title: Observability
description: Request IDs, Prometheus metrics, and structured audit logs.
category: user-guide
order: 4
parent: README.md
tags:
  - metrics
  - logging
  - observability
status: published
visibility: public
related:
  - configuration.md
  - threat-detection.md
---

# Observability

## Request IDs

Every request gets a UUID v4 request ID, attached to a `tracing::info_span!` so all log lines within the request inherit it. The ID is forwarded upstream and returned to clients via the `X-Request-Id` header.

## Prometheus metrics

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
| `sunbeam_scanner_ensemble_path_total` | Counter | `path` |
| `sunbeam_ddos_ensemble_path_total` | Counter | `path` |
| `sunbeam_cluster_peers` | Gauge | — |
| `sunbeam_cluster_bandwidth_in_bytes` | Gauge | — |
| `sunbeam_cluster_bandwidth_out_bytes` | Gauge | — |
| `sunbeam_cluster_gossip_messages_total` | Counter | `channel` |
| `sunbeam_bandwidth_limit_decisions_total` | Counter | `decision` |

## Audit logs

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

These audit logs are the training data. Feed them back into `prepare-dataset` to retrain the models on your actual traffic.
