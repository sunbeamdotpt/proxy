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
    /// Timestamp.
    pub timestamp: String,
    /// Level.
    pub level: String,
    /// Fields.
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
    /// Request id.
    pub request_id: String,
    /// Method.
    pub method: String,
    /// Host.
    pub host: String,
    /// Path.
    pub path: String,
    #[serde(default)]
    /// Query.
    pub query: String,
    /// Client ip.
    pub client_ip: String,

    // --- response ---
    #[serde(deserialize_with = "flexible_u16")]
    /// Status.
    pub status: u16,
    #[serde(deserialize_with = "flexible_u64")]
    /// Duration ms.
    pub duration_ms: u64,
    #[serde(default, deserialize_with = "flexible_u64_default")]
    /// Content length.
    pub content_length: u64,
    #[serde(default, deserialize_with = "flexible_u64_default")]
    /// Response bytes.
    pub response_bytes: u64,

    // --- headers ---
    #[serde(default = "default_dash")]
    /// User agent.
    pub user_agent: String,
    #[serde(default = "default_dash")]
    /// Referer.
    pub referer: String,
    #[serde(default = "default_dash")]
    /// Accept language.
    pub accept_language: String,
    #[serde(default = "default_dash")]
    /// Accept.
    pub accept: String,
    #[serde(default = "default_dash")]
    /// Accept encoding.
    pub accept_encoding: String,
    #[serde(default)]
    /// Has cookies.
    pub has_cookies: bool,
    #[serde(default = "default_dash")]
    /// Connection.
    pub connection: String,

    // --- infra ---
    #[serde(default = "default_dash")]
    /// Cf country.
    pub cf_country: String,
    #[serde(default)]
    /// Backend.
    pub backend: String,
    #[serde(default)]
    /// Error.
    pub error: String,
    #[serde(default = "default_dash")]
    /// Http version.
    pub http_version: String,
    #[serde(default)]
    /// Header count.
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

/// Flexible u64.
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

/// Flexible u16.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_line_try_parse_valid() {
        let line = r#"{"timestamp":"2026-01-01T00:00:00Z","level":"INFO","fields":{"message":"request","target":"audit","method":"GET","host":"app.example.com","path":"/","query":"","client_ip":"1.2.3.4","status":200,"duration_ms":10,"content_length":0,"response_bytes":0,"user_agent":"Mozilla/5.0","referer":"-","accept_language":"en-US","accept":"*/*","accept_encoding":"gzip","has_cookies":true,"connection":"keep-alive","cf_country":"PT","backend":"svc:8080","error":"","http_version":"HTTP/1.1","header_count":10}}"#;
        let result = AuditLogLine::try_parse(line);
        assert!(result.is_ok());
        let entry = result.unwrap();
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().fields.status, 200);
    }

    #[test]
    fn test_audit_log_line_try_parse_non_audit() {
        let line = r#"{"timestamp":"2026-01-01T00:00:00Z","level":"ERROR","fields":{"message":"tls handshake failed","target":"proxy"}}"#;
        let result = AuditLogLine::try_parse(line);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_audit_log_line_try_parse_invalid_json() {
        let result = AuditLogLine::try_parse("not json at all");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_audit_log_line_try_parse_schema_drift() {
        // Missing required 'status' field should trigger schema mismatch.
        let line = r#"{"timestamp":"2026-01-01T00:00:00Z","level":"INFO","fields":{"message":"request","target":"audit","method":"GET","host":"app.example.com","path":"/","client_ip":"1.2.3.4"}}"#;
        let result = AuditLogLine::try_parse(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_fields_default() {
        let fields = AuditFields::default();
        assert_eq!(fields.message, "request");
        assert_eq!(fields.target, "audit");
        assert_eq!(fields.status, 0);
        assert_eq!(fields.user_agent, "-");
        assert!(!fields.has_cookies);
        assert!(fields.label.is_none());
    }

    #[derive(Deserialize)]
    struct U64Wrapper {
        #[serde(deserialize_with = "flexible_u64")]
        value: u64,
    }

    #[derive(Deserialize)]
    struct U64DefaultWrapper {
        #[serde(default, deserialize_with = "flexible_u64_default")]
        value: u64,
    }

    #[derive(Deserialize)]
    struct U16Wrapper {
        #[serde(deserialize_with = "flexible_u16")]
        value: u16,
    }

    #[test]
    fn test_flexible_u64_from_string() {
        let json = r#"{"value":"42"}"#;
        let parsed: U64Wrapper = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.value, 42);
    }

    #[test]
    fn test_flexible_u64_from_number() {
        let json = r#"{"value":42}"#;
        let parsed: U64Wrapper = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.value, 42);
    }

    #[test]
    fn test_flexible_u64_default_invalid_string() {
        let json = r#"{"value":"not-a-number"}"#;
        let parsed: U64DefaultWrapper = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.value, 0);
    }

    #[test]
    fn test_flexible_u64_default_missing() {
        let json = r#"{}"#;
        let parsed: U64DefaultWrapper = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.value, 0);
    }

    #[test]
    fn test_flexible_u16_from_string() {
        let json = r#"{"value":"200"}"#;
        let parsed: U16Wrapper = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.value, 200);
    }

    #[test]
    fn test_flexible_u16_from_number() {
        let json = r#"{"value":404}"#;
        let parsed: U16Wrapper = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.value, 404);
    }

    #[test]
    fn test_strip_port_ipv4() {
        assert_eq!(strip_port("1.2.3.4:443"), "1.2.3.4");
    }

    #[test]
    fn test_strip_port_ipv6() {
        assert_eq!(strip_port("[::1]:443"), "::1");
    }

    #[test]
    fn test_strip_port_no_port() {
        assert_eq!(strip_port("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn test_strip_port_ipv6_no_bracket_falls_back_to_rfind() {
        // Without brackets the function treats the last ':' as a port separator.
        assert_eq!(strip_port("::1"), ":");
    }

    #[test]
    fn test_audit_log_line_serialize_roundtrip() {
        let line = AuditLogLine {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            level: "INFO".to_string(),
            fields: AuditFields {
                method: "GET".to_string(),
                host: "app.example.com".to_string(),
                path: "/".to_string(),
                client_ip: "1.2.3.4".to_string(),
                status: 200,
                duration_ms: 5,
                ..AuditFields::default()
            },
            span: None,
            spans: None,
        };
        let json = serde_json::to_string(&line).unwrap();
        let parsed: AuditLogLine = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.fields.method, "GET");
    }

    #[test]
    fn test_audit_log_line_try_parse_missing_target() {
        // Valid JSON but no audit target → should return None.
        let line = r#"{"timestamp":"2026-01-01T00:00:00Z","level":"INFO","fields":{"message":"request","method":"GET","host":"app.example.com","path":"/","client_ip":"1.2.3.4","status":200,"duration_ms":10}}"#;
        let result = AuditLogLine::try_parse(line);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_flexible_u64_invalid_string_errors() {
        let json = r#"{"value":"not-a-number"}"#;
        let result: Result<U64Wrapper, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_flexible_u16_invalid_string_errors() {
        let json = r#"{"value":"not-a-number"}"#;
        let result: Result<U16Wrapper, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_strip_port_ipv6_missing_bracket() {
        // Without a closing bracket, the function cannot parse the bracket and
        // returns the whole address unchanged.
        assert_eq!(strip_port("[::1"), "[::1");
    }
}
