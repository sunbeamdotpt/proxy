// Library crate root — exports the proxy/config/acme modules so that
// integration tests in tests/ can construct and drive a SunbeamProxy
// without going through the binary entry point.
pub mod acme;
pub mod autotune;
pub mod cache;
pub mod cluster;
pub mod config;
pub mod dataset;
pub mod ddos;
pub mod dual_stack;
pub mod ensemble;
pub mod metrics;
pub mod proxy;
pub mod rate_limit;
pub mod scanner;
pub mod ssh;
pub mod static_files;
#[cfg(feature = "training")]
pub mod training;
