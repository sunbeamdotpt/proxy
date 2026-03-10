# AGENTS.md — sunbeam-proxy

## Critical Rules

**Read before you write.** Read every file you intend to modify. Do not guess at code structure, function signatures, or types. This is a ~500-line Rust codebase — read the actual source.

**Minimal changes only.** Do exactly what is asked. Do not:
- Add features, abstractions, or "improvements" beyond the request
- Refactor surrounding code, rename variables, or restructure modules
- Add comments, docstrings, or type annotations to code you didn't change
- Add error handling or validation for scenarios that cannot happen
- Create helper functions or utilities for one-off operations
- Add backwards-compatibility shims, re-exports, or `// removed` comments
- Introduce new dependencies without being explicitly asked

**Do not create new files** unless the task absolutely requires it. Prefer editing existing files.

**Do not over-engineer.** Three similar lines of code is better than a premature abstraction. If a fix is one line, submit one line.

**Ask before acting** on anything destructive or irreversible: deleting files, force-pushing, modifying CI, running commands with side effects.

## Project Overview

sunbeam-proxy is a TLS-terminating reverse proxy built on [Pingora](https://github.com/cloudflare/pingora) 0.8 (Cloudflare's proxy framework) with rustls. It runs in Kubernetes and handles:

- **Host-prefix routing**: routes `foo.example.com` by matching prefix `foo` against the config
- **Path sub-routes**: longest-prefix match within a host, with optional prefix stripping
- **Static file serving**: try_files chain with SPA fallback, replacing nginx/caddy for frontends
- **URL rewrites**: regex-based path rewrites compiled at startup
- **Response body rewriting**: find/replace in HTML/JS responses (like nginx `sub_filter`)
- **Auth subrequests**: gate path routes with HTTP auth checks (like nginx `auth_request`)
- **HTTP response cache**: per-route in-memory cache via pingora-cache with Cache-Control support
- **Prometheus metrics**: request totals, latency histograms, detection decisions, cache hit/miss
- **Request IDs**: UUID v4 per request, forwarded to upstreams and clients via `X-Request-Id`
- **DDoS detection**: KNN-based per-IP behavioral classification
- **Scanner detection**: logistic regression per-request classification with bot allowlist
- **Rate limiting**: leaky bucket per-identity throttling
- **ACME HTTP-01 challenges**: routes `/.well-known/acme-challenge/*` to cert-manager solver pods
- **TLS cert hot-reload**: watches K8s Secrets, writes cert files, triggers zero-downtime upgrade
- **Config hot-reload**: watches K8s ConfigMaps, triggers graceful upgrade on change
- **SSH TCP passthrough**: raw TCP proxy for SSH traffic (port 22 to Gitea)
- **HTTP-to-HTTPS redirect**: with per-route opt-out via `disable_secure_redirection`

See [docs/README.md](docs/README.md) for full feature documentation and configuration reference.

## Source Files

```
src/main.rs          — binary entry point: server bootstrap, watcher spawn, SSH spawn
src/lib.rs           — library crate root: re-exports all modules
src/config.rs        — TOML config deserialization (Config, RouteConfig, PathRoute, CacheConfig, etc.)
src/proxy.rs         — ProxyHttp impl: request_filter, cache hooks, upstream_peer, body rewriting, logging
src/acme.rs          — Ingress watcher: maintains AcmeRoutes (path → solver backend)
src/watcher.rs       — Secret/ConfigMap watcher: cert write + graceful upgrade trigger
src/cert.rs          — fetch_and_write / write_from_secret: K8s Secret → cert files on disk
src/telemetry.rs     — JSON logging + optional OTEL tracing init
src/ssh.rs           — TCP proxy: tokio TcpListener + copy_bidirectional
src/metrics.rs       — Prometheus counters/histograms/gauge, metrics HTTP server, /health endpoint
src/static_files.rs  — Static file serving with try_files chain and SPA fallback
src/cache.rs         — pingora-cache MemCache backend and Cache-Control TTL parser
src/ddos/            — KNN-based DDoS detection (model, detector, training, replay)
src/scanner/         — Logistic regression scanner detection (model, detector, features, training, allowlist, watcher)
src/rate_limit/      — Leaky bucket rate limiter (limiter, key extraction)
src/dual_stack.rs    — Dual-stack (IPv4+IPv6) TCP listener
tests/e2e.rs         — end-to-end test: real SunbeamProxy over plain HTTP with echo backend
tests/proptest.rs    — property-based tests for static files, rewrites, config, metrics, etc.
docs/README.md       — comprehensive feature documentation
```

## Architecture Invariants — Do Not Break These

1. **Separate OS threads for K8s watchers.** The cert/config watcher and Ingress watcher run on their own `std::thread` with their own `tokio::runtime`. Pingora has its own internal runtime. Never share a tokio runtime between Pingora and the watchers.

2. **Fresh K8s Client per runtime.** Each runtime creates its own `kube::Client`. Tower workers are tied to the runtime that created them. Do not pass a Client across runtime boundaries.

3. **`std::sync::RwLock` for AcmeRoutes, not `tokio::sync`.** The RwLock guard is held across code paths in Pingora's async proxy calls. A tokio RwLock guard is `Send` but the waker cross-runtime issues make `std::sync::RwLock` the correct choice here.

4. **`insert_header()` not `headers.insert()` on Pingora `RequestHeader`.** Pingora maintains a CaseMap alongside `base.headers`. Using `headers.insert()` directly causes the header to be silently dropped during `header_to_h1_wire` serialization. Always use `insert_header()` or `remove_header()`.

5. **rustls crypto provider must be installed first.** `rustls::crypto::aws_lc_rs::default_provider().install_default()` must run before any TLS initialization. This is in `main()` line 19.

6. **Cert watcher writes certs from the Apply event payload.** It does NOT re-fetch via the API. The `watcher::Event::Apply(secret)` carries the full Secret object; `cert::write_from_secret` writes directly from it, then triggers the upgrade.

7. **Graceful upgrade = spawn new process with `--upgrade` + SIGQUIT self.** Pingora transfers listening socket FDs via Unix socket. The new process inherits them. Do not change this flow.

## Build & Test Commands

```sh
# Build (debug)
cargo build

# Build (release, with cross-compile for linux-musl if needed)
cargo build --release --target x86_64-unknown-linux-musl

# Run all tests (unit + e2e)
cargo test

# Run unit tests only (no e2e, which needs port 18889)
cargo test --lib

# Check without building
cargo check

# Lint
cargo clippy -- -D warnings

# Format check
cargo fmt -- --check
```

**Always run `cargo check` after making changes.** If it doesn't compile, fix it before proceeding. Do not submit code that doesn't compile.

**Run `cargo test` after any behavioral change.** The e2e test in `tests/e2e.rs` spins up a real proxy and echo backend — it catches real regressions.

**Run `cargo clippy -- -D warnings` before finishing.** Fix all warnings. Do not add `#[allow(...)]` attributes to suppress warnings unless there is a genuine false positive.

## Rust & Pingora Conventions in This Codebase

- Error handling: `anyhow::Result` for fallible startup code, `pingora_core::Result` inside `ProxyHttp` trait methods. Map between them with `pingora_core::Error::because()`.
- Logging: `tracing::info!`, `tracing::warn!`, `tracing::error!` with structured fields. The `logging()` method on the proxy uses `target = "audit"` for the request log line.
- No `unwrap()` in production paths. Use `expect()` only where failure is genuinely impossible and the message explains why. `unwrap_or_else(|e| e.into_inner())` is acceptable for poisoned locks.
- Async: `async_trait` for the `ProxyHttp` impl. Pingora controls the runtime; do not spawn tasks on it.
- Config: All configuration is in TOML, deserialized with serde. Add new fields to the existing structs in `config.rs` with `#[serde(default)]` for backwards compatibility.
- Tests: Unit tests go in `#[cfg(test)] mod tests` inside the relevant source file. Integration tests go in `tests/e2e.rs`.

## Common Mistakes to Avoid

- **Do not add `tokio::main` to `main.rs`.** Pingora manages its own runtime via `server.run_forever()`. The temporary runtimes for cert fetch and SSH are intentionally separate.
- **Do not use `headers.insert()` on upstream requests.** Use `insert_header()`. See invariant #4.
- **Do not hold a `RwLock` guard across `.await` points in proxy.rs.** Clone the data out, drop the guard, then proceed.
- **Do not add new crate dependencies for things the existing deps already cover.** Check `Cargo.toml` first.
- **Do not modify the graceful upgrade flow** (watcher.rs `trigger_upgrade`) unless explicitly asked. It is deliberately simple and correct.
- **Do not add `#[tokio::test]` to e2e tests.** They use `std::thread` + raw `TcpStream` intentionally to avoid runtime conflicts with Pingora.
