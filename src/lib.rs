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
pub mod cache;
pub mod cluster;
pub mod config;
pub mod ddos;
pub mod dual_stack;
pub mod metrics;
pub mod proxy;
pub mod rate_limit;
pub mod scanner;
pub mod ssh;
/// Static files.
pub mod static_files;
/// Tls passthrough.
pub mod tls_passthrough;
#[cfg(feature = "training")]
/// Training.
pub mod training;
