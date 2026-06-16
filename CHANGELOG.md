# Changelog

## [0.2.0] - 2026-06-16

### Features
- feat(telemetry): append source line number to log target
- feat(tls): add CA bundle support for backend TLS policies
- feat(gateway): translate Gateway API resources to internal IR
- feat(l4): bind Gateway API listeners and route L4 traffic
- feat(gateway): improve HTTPRoute and GatewayClass reconciliation
- feat(gateway): add GRPCRoute and L4 route reconciliation
- feat(gateway): add BackendTLSPolicy reconciliation
- feat(gateway): add ListenerSet reconciliation and Gateway status writeback
- feat(gateway): add event-driven reconcile trigger and leader loop wiring
- feat(gateway,proxy): BackendTLSPolicy dynamic TLS and Gateway status ancestors
- feat(proxy): dynamic upstream TLS verification for BackendTLSPolicy
- feat(gateway,tls): BackendTLSPolicy CA bundles and frontend validation support
- feat(gateway): implement BackendTLSPolicy and Gateway client-certificate TLS
- feat(gateway): add GRPCRoute API support with reconcile, translation and tests
- feat(gateway): support static addresses, optional values and infrastructure propagation
- feat(l4): route plain HTTP Gateway listeners through the L4 manager
- feat(gateway): thread parentRef port through IR and add 421 detection
- feat(gateway): reconcile HTTPS listeners and expand Gateway API test coverage
- feat(l4): L4 listener manager, TLS passthrough, and Gateway API L4 routes
- feat(build): add Dockerfiles and cloud-init for conformance/integration environments
- feat(cluster): cluster membership, gossip, election, and bandwidth metering
- feat(ml): training pipelines, datasets, ensemble models, and detection tuning
- feat(proxy): introduce IR compiler, route manager, and split proxy into phase modules
- feat(gateway): implement v1.5 Gateway API reconciliation, EndpointSlice resolution, and status
- feat(proxy): implement Gateway API request handling
- feat(config): add Gateway API route and listener configuration fields
- feat(gateway): implement reconcile, translate, certificate management, and cluster wiring
- feat(gateway-api): adopt official gateway-api crate types and extend routing model
- feat(proxy): add K8s manifests and example Gateway API resources
- feat(proxy): wire gossip digest publisher and resource notify into reconcile loop
- feat(proxy): wire Gateway API reconciler into serve path
- feat(proxy): atomic route table hot-reload via ArcSwap
- feat(proxy): implement translate_view (GatewayView → RouteConfig)
- feat(proxy): implement reconcile_tick and HTTPRoute controller
- feat(gateway): add routing model types for HTTPRoute translation
- feat(gateway): add cluster_join, dataplane, listeners, and translate stubs
- feat(proxy): wire gateway module into library root
- feat(metrics): expose registry and add gateway_state_drift_seconds gauge
- feat(config): reject deprecated TOML routes and tls_passthrough sections
- feat(cluster): add gateway gossip topics
- feat(gateway): add gossip digest publisher and resource notifier
- feat(gateway): add reconcile layer for Gateway, GatewayClass, HTTPRoute, ReferenceGrant
- feat(gateway): add status conditions and SSA status writer
- feat(gateway): add lease-based leader election and reconciler watchdog
- feat(gateway): add reconciled model, digest computation, and canonical view
- feat(gateway): add Gateway API v1.5.1 CRD bindings
- feat: add package targets for platform and tuwunel image builds
- feat: add wfe agent skill
- feat(cargo): Gate 4f dep unification — re-include cli, proxy, sunbeam-meet-proto+migrations, activate 3p patches
- feat: SNI-based TLS passthrough for mTLS backends
- feat: complete ensemble integration and remove legacy model code
- feat(lean4): add formal verification specs for ensemble models
- feat(cli): restructure replay as subcommand with ensemble and ddos modes
- feat(autotune): add Bayesian hyperparameter optimization
- feat(dataset): add dataset preparation with auto-download and heuristic labeling
- feat(training): add burn MLP and CART tree trainers with weight export
- feat(ensemble): wire ensemble into scanner and DDoS detectors
- feat(ensemble): add decision tree + MLP inference engine
- feat(cluster): add k8s headless service for gossip peer discovery
- feat(cluster): add Prometheus metrics for cluster gossip and bandwidth
- feat(cluster): wire cluster into proxy lifecycle and request pipeline
- feat(cluster): implement gossip-based cluster subsystem with iroh
- feat(cluster): add iroh-gossip dependencies and cluster config schema
- feat(lean): IEEE-754 lift of Tier 2 monotonicity
- feat(gen): scanner weights with hard-reparameterized adversarial features
- feat(gen): DDoS weights with hard-reparameterized adversarial features
- feat(training): Tier 2 hard reparameterization for adversarial features
- feat(training): sign-constraint penalty for Tier 2 monotonicity
- feat(gen): retrained DDoS + scanner weights for MLP-only verdict path
- feat(ensemble): MLP-only verdict path; tree no longer wired in production
- feat(training): tree excluded features flag (default header-presence)
- feat(lean): full 2-layer MLP soundness on IEEE-754 binary32 hardware
- feat(lean): Interval32 stepIBP soundness for one IBP iteration
- feat(lean): Interval32 scalarMul soundness kernel
- feat(ddos): monotonicity audit + adversarial feature catalog
- feat(ddos_crown): runtime certified radius at inputDim=14
- feat(lean): DDoS specialization at inputDim=14
- feat(crown): outward-rounded f32 IBP
- feat(lean4): compose fp32 forward error with crown bound
- feat(ensemble): add crown certified radius runtime
- feat(lean4): prove verdict stability within certified radius
- feat(lean4): apply crown affine bound to mlpForward
- feat(lean4): prove torchlean tensor ↔ scalar bridge
- feat(lean4): prove deployment soundness from tier-3 and tier-4
- feat(lean4): prove FP32 forward-error bound
- feat(lean4): prove mlpForward Lipschitz sensitivity bound
- feat(lean4): add FP32 model surface via TorchLean
- feat(proxy): scanner monotonicity audit
- feat(lean4): prove ensemble monotonicity under sign constraint
- feat(cli): profile & tunable support
- feat: configurable k8s resources, CSIC training pipeline, unified Dockerfile
- feat(cache): add pingora-cache integration with per-route config
- feat(static_files): add static file serving, SPA fallback, rewrites, body rewriting, and auth subrequests
- feat(proxy): add request IDs, tracing spans, and observability hooks
- feat(metrics): add Prometheus metrics and scrape endpoint
- feat(bench): add Criterion benchmarks and CSIC 2010 dataset converter
- feat(proxy): integrate DDoS, scanner, and rate limiter into request pipeline
- feat(scanner): add model hot-reload and verified bot allowlist
- feat(scanner): add logistic regression training pipeline
- feat(scanner): add per-request scanner detector with linear classifier
- feat(rate_limit): add per-identity leaky bucket rate limiter
- feat(ddos): add KNN-based DDoS detection module
- feat: add native dual-stack IPv4/IPv6 support
- feat(proxy): add SSH TCP passthrough and graceful HTTP-only startup
- feat(proxy): add per-route disable_secure_redirection; preserve query string in redirect
- feat: initial sunbeam-proxy implementation

### Bug Fixes
- fix(l4): preserve DNS backend port and isolate TLS listener hostname matching
- fix(gateway): compute BackendTLSPolicy Gateway ancestors before endpoint expansion
- fix(tls): advertise h2 and http/1.1 ALPN protocols for HTTPS listeners
- fix(proxy): use per-connection context to recover HTTP relay listener port
- fix(l4): preserve HTTP listener protocol during L4 listener merge
- fix(cert): write TLS private key with 0o600 permissions
- fix(proxy): embed workspace and fix iroh 0.96 API for filter-repo split
- fix(proxy): advertise ALPN h2 + http/1.1 so HTTP/2 clients negotiate correctly
- fix(proxy): build from workspace root and drop the find_route panic
- fix(telemetry): create dedicated Tokio runtime for OTLP exporter
- fix(tracing): enter request span in logging() so OTLP exports it
- fix(telemetry): gracefully handle OTLP exporter init failure
- fix(docker): touch lib.rs to invalidate dep-cache for real build
- fix(docker): add dummy lib.rs to dep-cache layer
- fix(training): transpose burn weight before flatten in gen export
- fix(training): unsqueeze_dim(1) for scatter indices in effective_w1
- fix(training): select adversarial input features by dim 1 (burn weight is [out, in])
- fix(scanner): use mainline branch for csic dataset
- fix(scanner): pull CSIC dataset from github sunbeamdotpt remote
- fix(proxy): restore burn 0.20 with original training features
- fix(dataset): realistic class overlap in synthetic samples
- fix(proxy): extract host from :authority for HTTP/2 requests
- fix(telemetry): use simple exporter — no Tokio runtime needed
- fix(proxy): skip detection pipeline for bypass CIDR IPs
- fix(docker): copy benches/ directory for Cargo.toml manifest parsing
- fix(dual_stack): set IPV6_V6ONLY on IPv6 socket to prevent EADDRINUSE
- fix(deps): upgrade pingora 0.7→0.8 and aws-lc-sys to patch CVEs
- fix(proxy): handle Expect: 100-continue for large upstream uploads
- fix(proxy): forward X-Forwarded-Proto via insert_header; add e2e test

### Performance
- perf(gateway): refresh certs and CA bundle only when view changes

### Refactoring
- refactor(main): use a single shared tokio runtime for all async services
- refactor(cluster,l4,gateway): accept shared runtime handle in async subsystems
- refactor(gateway): split translation layer into http/grpc/l4/hostnames/ir modules
- refactor(gateway): split listenerset reconciliation into listenerset/ submodule
- refactor(gateway): split l4route reconciliation into l4route/ submodule
- refactor(gateway): split gateway reconciliation into gateway/ submodule
- refactor(gateway): move HTTP and GRPC route reconciliation into shared route module
- refactor(gateway): split model digest into digest/ submodule
- refactor(gateway): introduce shared reconciler context and status helpers
- refactor(gateway): share ResolvedRefs/Programmed condition builder
- refactor(gateway): phase 5 macro-generate route API aliases
- refactor(gateway): phase 4 extract shared header-filter translation
- refactor(gateway): phase 3 L4 backend-ref consolidation
- refactor(gateway): phase 2 shared backend-ref resolution
- refactor(gateway): phase 1 shared primitives — centralize condition conversion and status patching
- refactor(proxy): remove monolithic proxy.rs after splitting into phase modules
- refactor(gateway): prune unused gRPC/TCP/TLS route and dataplane stubs
- refactor: extract cert and upgrade modules to lib root and wire into main
- refactor(lean4): restore scalar mlpForward; defer TorchLean to CrownBound
- refactor(lean4): reground mlpForward on TorchLean MLP2.forward
- refactor(lean4): lift Sunbeam spec from Float to ℝ

### Testing
- test(cluster): pass runtime handle to spawn_cluster calls
- test(gateway): add gateway_reconcile integration test harness
- test(gateway): cover frontend CA error reason mapping
- test(metrics): add unit tests and improve TCP reliability
- test: add gateway integration tests and update existing tests for new config fields
- test: update tests and benchmarks for ensemble architecture
- test(cluster): add integration tests and proptests for cluster subsystem
- test(proxy): integration test for radius distribution on dataset corpus
- test(training): verify sign-constraint penalty fires + handles lambda=0
- test: add property-based tests for new proxy features

### Build & CI
- build(conformance): run all non-mesh Gateway API tests by default
- build(scripts): unify conformance runner and coverage helper
- build(lean4): pin v4.29.0 toolchain and require TorchLean

### Documentation
- docs(agents): update architecture and module documentation
- docs(proxy): add gateway API controller design document
- docs(platform/proxy): rustdocs for config, detection, rate limiting, and training
- docs(lean4): add Rust cross-references to formal specs
- docs(proxy): TIERS.md glossary for the verification stack
- docs(crown): cite TorchLean Interval32 as f32 IBP soundness basis
- docs(lean4): tighten crown integration docstrings
- docs: rewrite README for ensemble architecture
- docs(paper): add research paper with evaluation and bib references
- docs: add project README, reference docs, license, CLA, and contributing guide

### Chores
- chore(conformance): capture verbose output and generate detailed report
- chore(conformance): update conformance runner script for target profile
- chore(deps): update Cargo.lock for Gateway API v1.5 dependencies
- chore(cluster): expose ClusterHandle shutdown_tx for tests
- chore(conformance): advertise GRPCRoute features in default supported feature list
- chore(tls): remove unnecessary mut from server_config
- chore(tooling): migrate conformance scripts to container runtime on macOS
- chore(license): update SPDX headers to AGPL-3.0-or-later
- chore(build): add cargo musl config and ignore temp/build artifacts
- chore(bench): update scanner bench for new RouteConfig fields
- chore(deps): update Cargo.lock and add delegate crate
- chore: move pingora from 3p/ to forks/ (sunbeamdotpt/pingora)
- chore(platform/proxy): add crates.io metadata (description, license, repository)
- chore(platform/proxy): bump to 0.1.1
- chore: add sunbeam.yaml schema v1
- chore: remove legacy deps (fnntw, rayon) and unused files
- chore: add SPDX copyright headers and update license year
- chore: update scanner/ddos trainers, benchmarks, and tests
- chore(proxy): drop Tier-N labels in Rust; point to docs/TIERS.md
- chore: docs updates
- chore(license): add AGPL-3.0 LICENSE to kratos-admin, sunbeam-meet, typst-editor; relicense proxy to AGPL-3.0

### Styling
- style: apply cargo fmt

### Reverts
- revert(lean4): restore axiom-free ℝ-based spec from mainline

### Other
- deps(proxy): add kube-derive, chrono, schemars, serde_yaml, tower for Gateway API controller
- security(redteam): proxy deny field, auth logging, config hardening
- wip(gen): ddos weights with sign-constraint lambda=100
- wip(gen): ddos weights with sign-constraint lambda=10.0
- wip(gen): ddos weights retrained with sign-constraint lambda=0.1
- bench(ensemble): add crown certified radius criterion bench

