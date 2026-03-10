// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Unified audit log record definition.
//!
//! This module is the **single source of truth** for the audit log schema.
//! Both the proxy's `logging()` method (serialization) and every training/replay
//! parser (deserialization) must use these types.  `deny_unknown_fields` ensures
//! that any schema change is caught at parse time rather than silently ignored.

use serde::{Deserialize, Serialize};

/// Minimal probe struct to check if a JSON line is an audit log.
#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    fields: Option<ProbeFields>,
}

#[derive(Deserialize)]
struct ProbeFields {
    #[serde(default)]
    target: Option<String>,
}

/// Top-level JSON line written by the tracing JSON layer.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuditLogLine {
    pub timestamp: String,
    pub level: String,
    pub fields: AuditFields,
    /// Span information injected by tracing layers.
    #[serde(default)]
    pub span: Option<serde_json::Value>,
    /// Span list injected by tracing layers.
    #[serde(default)]
    pub spans: Option<serde_json::Value>,
}

/// The request audit fields — canonical schema.
///
/// Every field the proxy emits in `tracing::info!(target = "audit", ...)`
/// must appear here.  `deny_unknown_fields` will cause a hard parse error
/// if the proxy starts emitting a field that isn't listed, forcing you to
/// update this struct (and all downstream consumers) in one place.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuditFields {
    /// The literal "request" message from `tracing::info!("request")`.
    #[serde(default = "default_dash")]
    pub message: String,
    /// The tracing target, always "audit" for request logs.
    #[serde(default = "default_dash")]
    pub target: String,

    // --- request identity ---
    #[serde(default)]
    pub request_id: String,
    pub method: String,
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub query: String,
    pub client_ip: String,

    // --- response ---
    #[serde(deserialize_with = "flexible_u16")]
    pub status: u16,
    #[serde(deserialize_with = "flexible_u64")]
    pub duration_ms: u64,
    #[serde(default, deserialize_with = "flexible_u64_default")]
    pub content_length: u64,
    #[serde(default, deserialize_with = "flexible_u64_default")]
    pub response_bytes: u64,

    // --- headers ---
    #[serde(default = "default_dash")]
    pub user_agent: String,
    #[serde(default = "default_dash")]
    pub referer: String,
    #[serde(default = "default_dash")]
    pub accept_language: String,
    #[serde(default = "default_dash")]
    pub accept: String,
    #[serde(default = "default_dash")]
    pub accept_encoding: String,
    #[serde(default)]
    pub has_cookies: bool,
    #[serde(default = "default_dash")]
    pub connection: String,

    // --- infra ---
    #[serde(default = "default_dash")]
    pub cf_country: String,
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub error: String,
    #[serde(default = "default_dash")]
    pub http_version: String,
    #[serde(default)]
    pub header_count: u16,

    // --- training only (not emitted by proxy, but present in external datasets) ---
    /// Ground-truth label injected by external dataset parsers.
    /// Values: "attack", "normal".
    #[serde(default)]
    pub label: Option<String>,
}

impl AuditLogLine {
    /// Try to parse a JSON line as an audit log entry.
    ///
    /// - Returns `Ok(Some(entry))` for valid audit log lines.
    /// - Returns `Ok(None)` for non-audit lines (TLS errors, etc.).
    /// - Returns `Err` if the line IS an audit log but has unknown fields
    ///   (schema drift that needs fixing).
    pub fn try_parse(line: &str) -> Result<Option<Self>, String> {
        // Quick probe: is this an audit-target line?
        let probe: Probe = match serde_json::from_str(line) {
            Ok(p) => p,
            Err(_) => return Ok(None), // not valid JSON or missing fields
        };
        let is_audit = probe
            .fields
            .as_ref()
            .and_then(|f| f.target.as_deref())
            .map(|t| t == "audit")
            .unwrap_or(false);

        if !is_audit {
            return Ok(None);
        }

        // Full parse with deny_unknown_fields — will error on schema drift.
        match serde_json::from_str::<Self>(line) {
            Ok(entry) => Ok(Some(entry)),
            Err(e) => Err(format!(
                "audit log schema mismatch (update src/audit.rs): {e}"
            )),
        }
    }
}

impl Default for AuditFields {
    fn default() -> Self {
        Self {
            message: "request".to_string(),
            target: "audit".to_string(),
            request_id: String::new(),
            method: String::new(),
            host: String::new(),
            path: String::new(),
            query: String::new(),
            client_ip: String::new(),
            status: 0,
            duration_ms: 0,
            content_length: 0,
            response_bytes: 0,
            user_agent: "-".to_string(),
            referer: "-".to_string(),
            accept_language: "-".to_string(),
            accept: "-".to_string(),
            accept_encoding: "-".to_string(),
            has_cookies: false,
            connection: "-".to_string(),
            cf_country: "-".to_string(),
            backend: String::new(),
            error: String::new(),
            http_version: "-".to_string(),
            header_count: 0,
            label: None,
        }
    }
}

fn default_dash() -> String {
    "-".to_string()
}

pub fn flexible_u64<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum {
        Num(u64),
        Str(String),
    }
    match StringOrNum::deserialize(deserializer)? {
        StringOrNum::Num(n) => Ok(n),
        StringOrNum::Str(s) => s.parse().map_err(serde::de::Error::custom),
    }
}

fn flexible_u64_default<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Val {
        Num(u64),
        Str(String),
    }
    match Val::deserialize(deserializer) {
        Ok(Val::Num(n)) => Ok(n),
        Ok(Val::Str(s)) => Ok(s.parse().unwrap_or(0)),
        Err(_) => Ok(0),
    }
}

pub fn flexible_u16<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u16, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum {
        Num(u16),
        Str(String),
    }
    match StringOrNum::deserialize(deserializer)? {
        StringOrNum::Num(n) => Ok(n),
        StringOrNum::Str(s) => s.parse().map_err(serde::de::Error::custom),
    }
}

/// Strip the port suffix from a socket address string.
pub fn strip_port(addr: &str) -> &str {
    if addr.starts_with('[') {
        addr.find(']').map(|i| &addr[1..i]).unwrap_or(addr)
    } else if let Some(pos) = addr.rfind(':') {
        &addr[..pos]
    } else {
        addr
    }
}
