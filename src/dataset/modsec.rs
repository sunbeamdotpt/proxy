//! Parser for OWASP ModSecurity audit log files (Serial / concurrent format).
//!
//! ModSecurity audit logs consist of multi-section entries delimited by boundary
//! markers like `--xxxxxxxx-A--`, `--xxxxxxxx-B--`, etc.  Each section contains
//! different data about the transaction:
//!
//! - **A**: Timestamp, transaction ID, source/dest IP+port
//! - **B**: Request line + headers
//! - **C**: Request body
//! - **F**: Response status + headers
//! - **H**: Audit log trailer (rule matches, messages, actions)
//!
//! Any entry with a rule match in section H is labeled "attack"; entries with
//! no rule matches are labeled "normal".

use crate::ddos::audit_log::AuditFields;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Parse a ModSecurity audit log file and return `(AuditFields, label)` pairs.
///
/// The label is `"attack"` if section H contains rule match messages, otherwise `"normal"`.
pub fn parse_modsec_audit_log(path: &Path) -> Result<Vec<(AuditFields, String)>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading ModSec audit log: {}", path.display()))?;
    parse_modsec_content(&content)
}

/// Parse ModSecurity audit log content from a string.
fn parse_modsec_content(content: &str) -> Result<Vec<(AuditFields, String)>> {
    let mut results = Vec::new();

    // Collect sections per boundary ID.
    // Boundary markers look like: --xxxxxxxx-A--
    // where xxxxxxxx is a hex/alnum transaction ID and A is the section letter.
    let mut sections: HashMap<String, HashMap<char, Vec<String>>> = HashMap::new();
    let mut current_id: Option<String> = None;
    let mut current_section: Option<char> = None;
    let mut current_lines: Vec<String> = Vec::new();
    // Track order of first appearance of each boundary ID.
    let mut id_order: Vec<String> = Vec::new();

    for line in content.lines() {
        if let Some((id, section)) = parse_boundary(line) {
            // Flush previous section.
            if let (Some(ref cid), Some(sec)) = (&current_id, current_section) {
                let entry = sections.entry(cid.clone()).or_default();
                entry.entry(sec).or_default().extend(current_lines.drain(..));
            }
            if !sections.contains_key(&id) {
                id_order.push(id.clone());
            }
            current_id = Some(id);
            current_section = Some(section);
            current_lines.clear();
        } else if current_id.is_some() {
            current_lines.push(line.to_string());
        }
    }
    // Flush last section.
    if let (Some(ref cid), Some(sec)) = (&current_id, current_section) {
        let entry = sections.entry(cid.clone()).or_default();
        entry.entry(sec).or_default().extend(current_lines.drain(..));
    }

    // Convert each transaction into AuditFields.
    for id in &id_order {
        if let Some(secs) = sections.get(id) {
            if let Some(fields) = transaction_to_audit_fields(secs) {
                results.push(fields);
            }
        }
    }

    Ok(results)
}

/// Try to parse a boundary marker line.
/// Returns `(boundary_id, section_letter)` on success.
fn parse_boundary(line: &str) -> Option<(String, char)> {
    let trimmed = line.trim();
    if !trimmed.starts_with("--") || !trimmed.ends_with("--") {
        return None;
    }
    // Strip leading and trailing --
    let inner = &trimmed[2..trimmed.len() - 2];
    // Should be: boundary_id-SECTION_LETTER
    let dash_pos = inner.rfind('-')?;
    if dash_pos == 0 || dash_pos == inner.len() - 1 {
        return None;
    }
    let id = &inner[..dash_pos];
    let section_str = &inner[dash_pos + 1..];
    if section_str.len() != 1 {
        return None;
    }
    let section = section_str.chars().next()?;
    if !section.is_ascii_alphabetic() {
        return None;
    }
    Some((id.to_string(), section))
}

/// Convert parsed sections into `(AuditFields, label)`.
fn transaction_to_audit_fields(
    sections: &HashMap<char, Vec<String>>,
) -> Option<(AuditFields, String)> {
    // Section A: timestamp + connection info
    let client_ip = sections
        .get(&'A')
        .and_then(|lines| {
            // Section A first line typically:
            // [dd/Mon/yyyy:HH:MM:SS +offset] transaction_id source_ip source_port dest_ip dest_port
            lines.first().and_then(|line| {
                // Find the content after the timestamp bracket.
                let after_bracket = line.find(']').map(|i| &line[i + 1..])?;
                let parts: Vec<&str> = after_bracket.split_whitespace().collect();
                // parts: [transaction_id, source_ip, source_port, dest_ip, dest_port]
                if parts.len() >= 3 {
                    Some(parts[1].to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| "0.0.0.0".to_string());

    // Section B: request line + headers
    let section_b = sections.get(&'B')?;
    if section_b.is_empty() {
        return None;
    }

    // First non-empty line is the request line.
    let request_line = section_b.iter().find(|l| !l.trim().is_empty())?;
    let req_parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if req_parts.len() < 2 {
        return None;
    }
    let method = req_parts[0].to_string();
    let raw_url = req_parts[1];

    let (path, query) = if let Some(q) = raw_url.find('?') {
        (raw_url[..q].to_string(), raw_url[q + 1..].to_string())
    } else {
        (raw_url.to_string(), String::new())
    };

    // Parse headers from remaining lines.
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in section_b.iter().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(colon) = trimmed.find(':') {
            let key = trimmed[..colon].trim().to_ascii_lowercase();
            let value = trimmed[colon + 1..].trim().to_string();
            headers.push((key, value));
        }
    }

    let get_header = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    let host = get_header("host").unwrap_or_else(|| "unknown".to_string());
    let user_agent = get_header("user-agent").unwrap_or_else(|| "-".to_string());
    let has_cookies = get_header("cookie").is_some();
    let referer = get_header("referer").filter(|r| r != "-" && !r.is_empty());
    let accept_language = get_header("accept-language").filter(|a| a != "-" && !a.is_empty());
    let content_length: u64 = get_header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // Section F: response status
    let status = sections
        .get(&'F')
        .and_then(|lines| {
            // First non-empty line: "HTTP/1.1 403 Forbidden"
            lines.iter().find(|l| !l.trim().is_empty()).and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    parts[1].parse::<u16>().ok()
                } else {
                    None
                }
            })
        })
        .unwrap_or(0);

    // Section H: rule matches → determines label.
    let has_rule_match = sections
        .get(&'H')
        .map(|lines| {
            lines.iter().any(|l| {
                let lower = l.to_ascii_lowercase();
                lower.contains("matched") || lower.contains("warning") || lower.contains("id:")
            })
        })
        .unwrap_or(false);

    let label = if has_rule_match { "attack" } else { "normal" }.to_string();

    let fields = AuditFields {
        method,
        host,
        path,
        query,
        client_ip,
        status,
        duration_ms: 0,
        content_length,
        user_agent,
        has_cookies: Some(has_cookies),
        referer,
        accept_language,
        backend: "-".to_string(),
        label: Some(label.clone()),
    };

    Some((fields, label))
}

/// Cache directory for ModSec data (mirrors the CSIC caching pattern).
#[allow(dead_code)]
fn cache_dir() -> std::path::PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            std::path::PathBuf::from(home).join(".cache")
        });
    base.join("sunbeam").join("modsec")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_AUDIT_LOG: &str = r#"--a1b2c3d4-A--
[01/Jan/2026:12:00:00 +0000] XYZ123 192.168.1.100 54321 10.0.0.1 80
--a1b2c3d4-B--
GET /admin/config.php?debug=1 HTTP/1.1
Host: example.com
User-Agent: curl/7.68.0
Accept: */*
--a1b2c3d4-C--
--a1b2c3d4-F--
HTTP/1.1 403 Forbidden
Content-Type: text/html
--a1b2c3d4-H--
Message: Warning. Matched "Operator `Rx' with parameter" [id "941100"]
Action: Intercepted (phase 2)
--a1b2c3d4-Z--
--e5f6a7b8-A--
[01/Jan/2026:12:00:01 +0000] ABC456 10.0.0.50 12345 10.0.0.1 80
--e5f6a7b8-B--
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120
Accept: text/html
Accept-Language: en-US,en;q=0.9
Cookie: session=abc123
Referer: https://example.com/
--e5f6a7b8-F--
HTTP/1.1 200 OK
Content-Type: text/html
--e5f6a7b8-H--
--e5f6a7b8-Z--
"#;

    #[test]
    fn test_parse_boundary() {
        assert_eq!(
            parse_boundary("--a1b2c3d4-A--"),
            Some(("a1b2c3d4".to_string(), 'A'))
        );
        assert_eq!(
            parse_boundary("--a1b2c3d4-H--"),
            Some(("a1b2c3d4".to_string(), 'H'))
        );
        assert_eq!(parse_boundary("not a boundary"), None);
        assert_eq!(parse_boundary("--invalid--"), None);
    }

    #[test]
    fn test_parse_modsec_audit_log_snippet() {
        let results = parse_modsec_content(SAMPLE_AUDIT_LOG).unwrap();
        assert_eq!(results.len(), 2, "should parse two transactions");

        // First entry: attack (has rule match in section H).
        let (attack_fields, attack_label) = &results[0];
        assert_eq!(attack_label, "attack");
        assert_eq!(attack_fields.method, "GET");
        assert_eq!(attack_fields.path, "/admin/config.php");
        assert_eq!(attack_fields.query, "debug=1");
        assert_eq!(attack_fields.client_ip, "192.168.1.100");
        assert_eq!(attack_fields.user_agent, "curl/7.68.0");
        assert_eq!(attack_fields.status, 403);
        assert!(!attack_fields.has_cookies.unwrap_or(true));

        // Second entry: normal (no rule match).
        let (normal_fields, normal_label) = &results[1];
        assert_eq!(normal_label, "normal");
        assert_eq!(normal_fields.method, "GET");
        assert_eq!(normal_fields.path, "/index.html");
        assert_eq!(normal_fields.client_ip, "10.0.0.50");
        assert_eq!(normal_fields.status, 200);
        assert!(normal_fields.has_cookies.unwrap_or(false));
        assert!(normal_fields.referer.is_some());
        assert!(normal_fields.accept_language.is_some());
    }

    #[test]
    fn test_empty_input() {
        let results = parse_modsec_content("").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_single_entry_no_section_h() {
        let content = r#"--abc123-A--
[01/Jan/2026:12:00:00 +0000] TX1 1.2.3.4 1234 5.6.7.8 80
--abc123-B--
GET / HTTP/1.1
Host: test.com
--abc123-F--
HTTP/1.1 200 OK
--abc123-Z--
"#;
        let results = parse_modsec_content(content).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "normal");
    }
}
