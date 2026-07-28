---
title: Architecture
description: Internal architecture and module-by-module tour of Sunbeam Proxy.
category: operator-guide
order: 3
parent: README.md
tags:
  - architecture
  - internals
status: published
visibility: public
updated_at: "2026-07-28"
related:
  - development.md
  - TIERS.md
---

# Architecture

Sunbeam is a single binary that handles multiple roles: TLS terminator, Gateway API controller, HTTP router, ML firewall, cache, static file server, and cluster node. This document describes the internal modules in startup order, then follows a request through the system.

---

## Overview

At the highest level, Sunbeam separates into three layers that interact indirectly:

1. **Control plane** — watches Kubernetes Gateway API resources and converts them into an internal route model.
2. **Route manager** — merges route snapshots, compiles them, and hot-swaps the result into the data plane.
3. **Data plane** — accepts connections, runs security checks, looks up a route, and forwards the request.

A fourth layer of **platform glue** — TLS, metrics, logging, graceful upgrades, and cluster gossip — supports everything else.

The core design principle is **one route lookup per request**. Every decision a request needs is pre-computed during compilation, so the hot path follows a plan built earlier.

---

## Startup and the main orchestrator (`src/main.rs`)

`main.rs` controls startup order strictly:

1. Install the rustls crypto provider before anything touches TLS.
2. Load the TOML config file (`$SUNBEAM_CONFIG` or `/etc/sunbeam/config.toml`).
3. Initialize telemetry so every subsequent log line is structured JSON.
4. Build the optional DDoS detector, scanner detector, bot allowlist, and rate limiter.
5. Create a shared Tokio runtime for all application async work (reconciler, watchers, L4 manager, cluster, metrics, SSH).
6. Fetch the initial TLS Secret from Kubernetes and write it to disk.
7. Create the central TLS registry.
8. Build the `RouteManager` and seed it with the static listener configuration from TOML.
9. Start the metrics server, the Gateway API reconciler, the L4 socket manager, and the Kubernetes watchers.
10. Hand control to the proxy runtime, which blocks on `server.run_forever()`.

The proxy runtime manages its own event loop internally; everything else runs on the shared Tokio runtime. Keeping them separate prevents one runtime's assumptions from leaking into the other.

---

## Configuration (`src/config.rs`)

`config.rs` defines the TOML schema. It holds global settings: listeners, TLS paths, telemetry endpoints, Kubernetes namespace/secret names, detector thresholds, rate-limit buckets, and cluster membership.

In 0.2.0, routing moved out of TOML and into Gateway API CRDs. The config file now only describes *how* Sunbeam runs, not *where traffic goes*. That boundary matters: the route manager is the single place where routing decisions live, and Gateway API is the single source that feeds it.

---

## The intermediate representation (`src/ir`)

`src/ir` defines `RouteTable`, the canonical routing model. It is deliberately source-agnostic: whether routes came from Gateway API, a future xDS control plane, or a static fallback, they all end up as the same structs.

The main pieces:

- `RouteTable` — listeners, host routes, ACME routes, L4 routes, and TLS certs.
- `HostRoute` + `Rule` + `RequestMatch` — hostname, path, method, header, and query matching.
- `Action` — what happens on a match: route to backends, redirect, serve static files, or return a fixed response.
- `RouteAction` — weighted backends, timeouts, request/response filters, mirroring, caching, auth, and WebSocket flag.
- `RequestFilter` / `ResponseFilter` — header/path/hostname mutations, CORS, etc.

`src/ir/compile.rs` turns that declarative table into a `CompiledRouteTable`. The compiler front-loads every decision it can:

- Each rule is flattened into one `CompiledPlan` per match.
- Precedence is computed once from path specificity, method specificity, header count, and query param count.
- Exact and prefix paths go into a trie; regex paths live in a fallback list.
- Trie nodes with many plans get an adaptive discriminator that buckets by method, exact header value, or exact query value.
- L4 listeners on the same bind address and protocol are merged.

At runtime, `CompiledRouteTable::lookup()` finds the most specific host, walks the trie, and returns a single `CompiledPlan`. Every later phase reads that plan.

---

## The route manager (`src/route_manager.rs`)

The route manager mediates between the control plane and the data plane. Producers push `RouteTable` snapshots to it; it compiles them and atomically swaps the tables the proxy reads.

Key pieces:

- `RouteManager` holds `ArcSwap` pointers to the compiled route table, L4 config, and rewrite rules, plus a history of recent versions.
- `apply(source, table)` merges sources by priority, compiles the result, and only swaps if compilation succeeds. A failed compile leaves the previous table in place.
- `rollback(steps)` restores an earlier version from history.
- `spawn(max_history)` runs the manager on a background `std::thread` with an mpsc channel. It debounces updates and keeps only the latest snapshot.

The manager also exposes an `l4_changed` condition variable so the L4 socket manager can react when listeners change.

---

## The proxy lifecycle (`src/proxy`)

`src/proxy` implements the HTTP engine traits. `SunbeamProxy` holds the `ArcSwap` handles into the route manager, plus the optional detectors and the ACME route table.

The request context (`src/proxy/ctx.rs`) stores the matched `CompiledPlan`, the request ID, the downstream scheme/port, auth headers, and a body buffer.

A request flows through these phases:

1. **`request_filter`** — determine the real downstream scheme and port from the L4 context, run the security pipeline, perform the single route lookup, and execute any request-stage actions (auth subrequest, CORS preflight, static files, redirects, fixed responses).
2. **`upstream_peer`** — pick a weighted backend, fire any request mirrors, and build an `HttpPeer` with DNS, timeouts, TLS/mTLS, and ALPN.
3. **`upstream_request_filter`** — add `X-Forwarded-Proto` and `X-Request-Id`, forward WebSocket headers, and apply path/hostname/header mutations from the plan.
4. **`upstream_response_filter`** — add `X-Request-Id`, apply response mutations, and decide whether body rewrites are needed.
5. **`response_body_filter`** — buffer up to 10 MB and apply find/replace rules at end-of-stream.
6. **Cache hooks** — cache GET/HEAD responses when safe, respecting `Cache-Control`.
7. **`logging`** — emit the structured JSON audit line.

The proxy relies on the single-lookup invariant: `ctx.plan` is set exactly once in `request_filter` and then read, never recomputed.

---

## Gateway API control plane (`src/gateway`)

The Gateway API machinery is the most complex part of the codebase, but the concept is straightforward: watch Kubernetes resources, validate them, resolve cross-references, and translate the result into the same `ir::RouteTable` that static config would produce.

### `src/gateway/api`

Typed CRD bindings for `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `UDPRoute`, `TLSRoute`, `ListenerSet`, `ReferenceGrant`, and `BackendTLSPolicy`. Most are re-exports or aliases from the upstream `gateway-api` crate; a few (like `Gateway`) are custom because Sunbeam supports project-specific extensions.

### `src/gateway/model`

The pure-Rust canonical view of the cluster state. `ReconciledView` (also called `GatewayView`) is a cheap-to-clone snapshot: every string is `Arc<str>`, so the whole view can be diffed and gossiped without copying. It also holds `ReferenceGrantState`, `BackendTLSPolicyState`, namespace labels, and the listener permission map.

### `src/gateway/reconcile`

The actual controller work happens here. The main loop in `reconcile::leader` runs roughly every 100 ms, or immediately when a watch event triggers it. It starts per-resource controllers, runs a full reconcile tick, translates the result to an `ir::RouteTable`, sends it to the `RouteManager`, broadcasts a digest over gossip, and writes status back to Kubernetes — but only on the leader.

Per-resource controllers include:

- `gatewayclass.rs` — accepts classes whose `controllerName` is `sunbeam` and advertises supported features.
- `gateway/` — builds `GatewayState`, validates listeners, certificates, frontend client-certificate validation, backend TLS, and listener conflicts.
- `httproute.rs` / `grpcroute.rs` — parse and validate HTTP/gRPC routes, match them to listeners, and resolve backends.
- `l4route/` — handles TCP, UDP, and TLS routes.
- `listenerset/` — merges `ListenerSet` resources into parent Gateways.
- `backend.rs`, `refgrant.rs`, `endpoints.rs` — resolve services to pod IPs and enforce cross-namespace permissions.

Only the leader writes status. Every replica still builds and applies the same routing state, so the data plane stays consistent even if the leader changes.

### `src/gateway/translate`

Takes the canonical `ReconciledView` and emits an `ir::RouteTable`. `translate_view_to_ir` is the entry point used in production. It handles hostname intersection, match translation, filter translation, backend weighting, L4 routes, and unprogrammed routes.

### `src/gateway/election`

Leadership is currently implemented with a Kubernetes `coordination.k8s.io/v1` Lease. A background task renews the lease every few seconds. Only the holder writes status; the data plane runs everywhere.

### `src/gateway/gossip`

After each reconcile, the leader (and followers) compute a Blake3 digest of the `ReconciledView` and gossip it to peers. If a replica sees drift, it can force an early reconcile. Resource-change notifications are also gossiped so peers do not have to wait for their own watches to notice a change.

### `src/gateway/status`

Helpers for writing Gateway API status conditions (`Accepted`, `Programmed`, `ResolvedRefs`, `Conflicted`) back to Kubernetes. `patch_status_if_changed` avoids spamming the API server by stripping `lastTransitionTime` before comparing old and new status.

---

## L4 plumbing (`src/l4`, `src/dual_stack`, `src/ssh`, `src/tls_passthrough`)

The proxy runtime handles HTTP/1.1 and HTTP/2 at the application layer, but the public internet arrives as raw TCP and UDP. The L4 layer owns the external sockets.

### `src/l4/manager.rs`

`L4SocketManager` receives `CompiledL4Config` snapshots and diffs them against the current config. New listeners are bound; removed listeners are shut down cleanly. It runs as a task on the shared Tokio runtime.

### `src/l4/router.rs`

For each accepted stream, the router:

- Classifies the protocol (`Http`, `Https`, `Tls`, `Tcp`, `Udp`).
- Peeks the TLS ClientHello for SNI when needed.
- Picks the matching `CompiledL4Route`.
- Executes the action: TCP relay, UDP relay, TLS passthrough, TLS termination, terminate-and-HTTP, or plain HTTP relay.

Backend selection for L4 routes is weighted random. For `TerminateAndHttp` and `HttpRelay`, the router stores per-connection context so the internal HTTP proxy can recover the original listener port and whether TLS was terminated.

### `src/l4/context.rs` and `src/l4/current.rs`

`L4Context` and `HttpRelayContext` carry the small amount of metadata the HTTP proxy needs about a connection. `current.rs` exposes a global handle so tests and conformance code can wait for the dataplane to pick up a listener.

### `src/dual_stack.rs`

A small helper that binds both IPv4 and IPv6 sockets, sets `IPV6_V6ONLY` to avoid port collisions, and alternates accept priority for fairness. Used by SSH and the legacy standalone TLS passthrough path.

### `src/ssh.rs`

A minimal TCP proxy for raw SSH traffic, usually port 22 to a Gitea backend. It accepts a `DualStackTcpListener` and `tokio::io::copy_bidirectional`s each connection to the backend.

### `src/tls_passthrough.rs`

A standalone SNI-based TLS passthrough router that predates the L4 manager. It is still compiled and tested, but in 0.2.0 passthrough is handled by the L4 manager's `TlsPassthrough` action. The module remains as a fallback and a test reference.

---

## TLS and certificates (`src/tls`, `src/cert`, `src/watcher`, `src/acme`, `src/sni`)

### `src/tls/registry.rs`

The TLS registry is the certificate trust center. It holds:

- The default certificate and key.
- Exact-host and wildcard certificates.
- Trust roots for upstream verification.
- Frontend client-certificate roots for mTLS.
- Upstream client certificates for backend mTLS.

`TlsRegistry` wraps an `ArcSwap<CertStore>`, so certificates can be hot-swapped atomically. It implements `rustls::server::ResolvesServerCert` and builds `ServerConfig` objects with ALPN and optional client auth.

### `src/tls/source.rs`

`CertSource` is a trait for loading certificates. `DiskCertSource` loads the configured cert/key files; `GatewayCertSource` pulls listener certificates and backend client certs from the reconciled Gateway API view. `merge_cert_sources` combines them by priority.

### `src/cert.rs`

Two functions: `fetch_and_write` fetches a Kubernetes TLS Secret and writes `tls.crt` and `tls.key` to disk; `write_from_secret` does the same from an already-held `Secret` object. The watcher uses the latter to avoid an extra API round-trip.

### `src/watcher.rs`

Watches the TLS Secret and config ConfigMap. When either changes, it triggers a graceful upgrade: spawn a new process with `serve --upgrade`, then send `SIGQUIT` to the current process. The proxy runtime passes listening socket FDs across a Unix socket, so connections do not drop.

### `src/acme.rs`

Routes cert-manager HTTP-01 challenges to the correct solver pod. `AcmeRoutes` maps `/.well-known/acme-challenge/<token>` to a solver service. It uses `std::sync::RwLock` rather than a tokio lock so reads are safe inside the proxy runtime's async phases.

### `src/sni.rs`

A minimal TLS ClientHello parser that avoids allocations. Given the first ~1.5 KB of a connection, it returns the SNI hostname. This lets Sunbeam route TLS passthrough and terminate TLS for the correct certificate before the full handshake completes.

---

## Security engines (`src/ddos`, `src/scanner`, `src/rate_limit`, `src/ensemble`, `src/dataset`, `src/training`, `src/audit`)

These modules form the firewall layer. They only run on HTTPS traffic; plain HTTP is redirected away before any of this happens.

### `src/audit`

Defines the canonical audit log schema. `AuditLogLine::try_parse()` probes JSON log lines and rejects unknown fields, which catches schema drift between the proxy and the training tools. The proxy emits one audit line per request; the training pipeline reads them back.

### `src/ddos`

Per-IP behavioral detection. `DDoSDetector` keeps a sharded map of ring buffers, one per IP. Once an IP has enough events, it extracts a 14-dimensional feature vector and runs the DDoS ensemble. Blocked traffic gets HTTP 429 (unless `observe_only` is on).

### `src/scanner`

Per-request probe detection. `ScannerDetector` extracts 12 features from a single request and runs the scanner ensemble. It first applies a hard allowlist for known hosts with cookies or browser-like headers, then falls back to the model. Verified bot allowlisting happens in `src/scanner/allowlist`.

### `src/scanner/allowlist`

`BotAllowlist` handles legitimate crawlers. It can accept instantly by IP range or verify via reverse/forward DNS on a background thread. The first request from an unverified IP falls through to the scanner model.

### `src/rate_limit`

A leaky-bucket rate limiter keyed by identity (session cookie, bearer token, or IP fallback). It uses sharded locks and supports separate authenticated/unauthenticated limits, CIDR bypasses, and background eviction of stale buckets.

### `src/ensemble`

The shared inference engine. Each detector uses the same pattern:

1. Normalize features using compiled-in min/max constants.
2. Walk a small packed decision tree (`src/ensemble/tree.rs`).
3. If the tree is confident, return `Block` or `Allow` immediately.
4. If the tree defers, run a 32-hidden-unit MLP (`src/ensemble/mlp.rs`) and threshold the sigmoid output.

Weights live in `src/ensemble/weights/` as Rust `const` arrays, so inference needs no heap allocation and no model files. `src/ensemble/crown` and `src/ensemble/monotonicity_audit` compute certified robustness bounds.

### `src/dataset`

Turns raw logs into training data. `dataset::prepare` mixes production audit logs, CSIC 2010, ModSecurity logs, CIC-IDS2017 flows, and synthetic samples into a `DatasetManifest`. Each source has a sample weight that reflects label confidence.

### `src/training`

Gated behind the `training` feature because it pulls in burn-rs and wgpu. `train_scanner` and `train_ddos` train a CART tree and an MLP, then export the combined weights to `src/ensemble/weights/`. `training::sweep` can vary the cookie feature weight and report validation accuracy for each value.

### How they plug together

In `proxy/request_filter.rs`, for HTTPS traffic:

1. Extract the real client IP.
2. Run DDoS → block returns 429.
3. Run scanner (after allowlist) → block returns 403.
4. Run rate limit → exhausted returns 429 with `Retry-After`.
5. Cluster bandwidth cap runs after that.

Each layer emits a `target = "pipeline"` log line before acting. `observe_only` flags let you run a detector in log-but-don't-block mode.

---

## Caching and static files (`src/cache`, `src/static_files`)

### `src/cache.rs`

Sunbeam uses an in-memory cache backend keyed on host, path, query, auth/cookie presence, and content-negotiation headers. It only caches GET/HEAD responses, only 2xx, and respects `no-store`, `private`, and `max-age`. The cache lives in a global `LazyLock<MemCache>` because the proxy runtime expects a `'static` storage reference.

### `src/static_files.rs`

Implements nginx-style `try_files` with SPA fallback. Given a root and a request path, it tries the exact file, then `path.html`, then `path/index.html`, then an optional fallback like `/index.html`. It canonicalizes paths and refuses anything outside the root, so symlinks and `..` cannot escape. Content-type and cache headers are inferred from file extensions.

---

## Clustering (`src/cluster`)

Optional multi-node gossip. If `cluster.enabled` is true, Sunbeam joins an iroh-gossip mesh with the other pods.

- `ClusterHandle` is the public handle returned by `spawn_cluster`.
- `node::run_cluster` loads or generates an ed25519 node key, binds an iroh endpoint, and subscribes to topics for bandwidth, models, leader election, license, gateway state, and gateway notifications.
- Bandwidth reporting is active today: each node publishes its deltas, merges peer reports, and exposes aggregate rates as Prometheus metrics.
- Gateway-state gossip hooks exist; model/leader/license topics are mostly stubs for future work.

The proxy records request/response bytes into `ClusterHandle.bandwidth`; the cluster task publishes those deltas.

---

## Observability (`src/metrics`, `src/telemetry`)

### `src/telemetry.rs`

Initializes structured JSON logging. The formatter appends the source line number to the `target` field, so a log line from `proxy::request_filter:123` shows up as `target: "proxy::request_filter:123"`. The OTLP exporter path is currently disabled even if configured; JSON logs are always emitted.

### `src/metrics.rs`

A small Prometheus server in the same binary. It registers counters and histograms for requests, latency, DDoS/scanner/rate-limit decisions, cache status, active connections, and cluster bandwidth/gossip. It also answers `GET /health` for Kubernetes probes.

---

## Graceful upgrades (`src/upgrade`)

`upgrade::trigger_upgrade()` resolves the current executable, spawns a new process with `serve --upgrade`, and sends `SIGQUIT` to the current process. The proxy runtime's upgrade handshake passes listening socket FDs to the new process over a Unix socket.

If `SUNBEAM_DISABLE_GRACEFUL_UPGRADE` is set, the function returns immediately. That is useful in test containers where the upgrade handshake can hang.

---

## A few words on `src/autotune`

The original KNN/linear autotune code is gone; the burn-based training pipeline and cookie-weight sweeps replaced it. What remains is a generic Bayesian optimizer (`autotune::optimizer`) and parameter-space helpers (`autotune::params`). They are reusable building blocks but not directly wired to detector tuning today.

---

## Putting it all together: a request's journey

1. A TCP connection arrives at an L4 listener.
2. The L4 router terminates TLS (if needed), classifies the protocol, and forwards plaintext HTTP to the internal proxy runtime listener.
3. The proxy runtime calls `request_filter`. Sunbeam determines the original scheme/port, runs the security pipeline, performs one route lookup, and stores the `CompiledPlan` in the request context.
4. If the route says static files, CORS preflight, redirect, or fixed response, the request is handled immediately.
5. Otherwise, `upstream_peer` picks a backend and builds an `HttpPeer`.
6. `upstream_request_filter` mutates headers and path as requested.
7. The upstream responds; `upstream_response_filter` applies response mutations and sets up body buffering if needed.
8. Cache hooks store the response if caching is enabled.
9. `response_body_filter` applies any find/replace rules.
10. `logging` emits the audit line.

Meanwhile, in the background, the Gateway API reconciler watches the cluster, the route manager hot-swaps compiled tables, and the L4 manager adds or removes listeners as the config changes. The system is designed so the hot path stays simple while the hard work happens before the request arrives.
