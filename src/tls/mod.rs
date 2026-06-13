// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS utilities — certificate registry, trust roots, and SNI resolution.

pub mod registry;
pub mod source;

pub use registry::{certified_key_from_pem, CertStore, TlsRegistry, WildcardPattern};
pub use source::{
    merge_cert_store, CertSource, CompositeCertSource, DiskCertSource, GatewayCertSource,
};
