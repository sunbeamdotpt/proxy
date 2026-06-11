#![warn(missing_docs)]
//! sunbeam-proxy — Pingora-based reverse proxy with ML-powered DDoS/scanner detection,
//! rate limiting, gossip clustering, and ACME TLS support.
// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

// Library crate root — exports the proxy/config/acme modules so that
// integration tests in tests/ can construct and drive a SunbeamProxy
// without going through the binary entry point.
#![recursion_limit = "256"]
/// Acme.
pub mod acme;
/// Audit.
pub mod audit;
/// Autotune.
pub mod autotune;
/// Cache.
pub mod cache;
/// Cluster.
pub mod cluster;
/// Config.
pub mod config;
/// Dataset.
pub mod dataset;
/// Ddos.
pub mod ddos;
/// Dual stack.
pub mod dual_stack;
/// Ensemble.
pub mod ensemble;
pub mod gateway;
/// Metrics.
pub mod metrics;
/// Proxy.
pub mod proxy;
/// Rate limit.
pub mod rate_limit;
/// Scanner.
pub mod scanner;
/// Sni.
pub mod sni;
/// Ssh.
pub mod ssh;
/// Static files.
pub mod static_files;
/// Cert.
pub mod cert;
/// Tls passthrough.
pub mod tls_passthrough;
/// Upgrade.
pub mod upgrade;
#[cfg(feature = "training")]
/// Training.
pub mod training;
