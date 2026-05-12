// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Fetch and convert the CSIC 2010 HTTP dataset into labeled training samples.
//!
//! The CSIC 2010 dataset contains raw HTTP/1.1 requests (normal + anomalous)
//! from a web application. When `--csic` is passed to `train-scanner`, this
//! module downloads the dataset from GitHub, parses the raw HTTP requests,
//! and converts them into `AuditFields` entries with ground-truth labels.

use crate::ddos::audit_log::AuditFields;
use anyhow::{Context, Result};
use std::path::PathBuf;

const REPO_BASE: &str =
    "https://raw.githubusercontent.com/sunbeamdotpt/csic-dataset/main";

const FILES: &[(&str, &str)] = &[
    ("normalTrafficTraining.txt", "normal"),
    ("normalTrafficTest.txt", "normal"),
    ("anomalousTrafficTest.txt", "anomalous"),
];

const DEFAULT_HOSTS: &[&str] = &[
    "admin", "src", "docs", "auth", "drive", "grafana", "people", "meet", "s3", "livekit",
];

fn cache_dir() -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".cache")
        });
    base.join("sunbeam").join("csic")
}

fn download_or_cached(filename: &str) -> Result<String> {
    let dir = cache_dir();
    let path = dir.join(filename);

    if path.exists() {
        eprintln!("  cached: {}", path.display());
        return std::fs::read_to_string(&path)
            .with_context(|| format!("reading cached {}", path.display()));
    }

    let url = format!("{REPO_BASE}/{filename}");
    eprintln!("  downloading: {url}");
    let body = reqwest::blocking::get(&url)
        .with_context(|| format!("fetching {url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error for {url}"))?
        .text()
        .with_context(|| format!("reading body of {url}"))?;

    std::fs::create_dir_all(&dir)?;
    std::fs::write(&path, &body)?;
    Ok(body)
}

struct ParsedRequest {
    method: String,
    path: String,
    query: String,
    user_agent: String,
    has_cookies: bool,
    content_length: u64,
    referer: String,
    accept_language: String,
    accept: String,
}

fn parse_csic_content(content: &str) -> Vec<ParsedRequest> {
    let mut requests = Vec::new();
    let mut current_lines: Vec<&str> = Vec::new();

    for line in content.lines() {
        if line.is_empty() && !current_lines.is_empty() {
            if let Some(req) = parse_single_request(&current_lines) {
                requests.push(req);
            }
            current_lines.clear();
        } else {
            current_lines.push(line);
        }
    }
    if !current_lines.is_empty() {
        if let Some(req) = parse_single_request(&current_lines) {
            requests.push(req);
        }
    }
    requests
}

fn parse_single_request(lines: &[&str]) -> Option<ParsedRequest> {
    if lines.is_empty() {
        return None;
    }

    let parts: Vec<&str> = lines[0].splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0].to_string();
    let raw_url = parts[1];

    // Extract path and query — URL may be absolute (http://localhost:8080/path?q=1)
    let (path, query) = if let Some(rest) = raw_url.strip_prefix("http://") {
        // Skip host portion
        let after_host = rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
        split_path_query(after_host)
    } else if let Some(rest) = raw_url.strip_prefix("https://") {
        let after_host = rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
        split_path_query(after_host)
    } else {
        split_path_query(raw_url)
    };

    // Parse headers
    let mut headers: Vec<(&str, &str)> = Vec::new();
    let mut body_start = None;
    for (i, line) in lines[1..].iter().enumerate() {
        if line.is_empty() {
            body_start = Some(i + 2); // +2 because we started from lines[1..]
            break;
        }
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim();
            let value = line[colon + 1..].trim();
            headers.push((key, value));
        }
    }

    let get_header = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };

    let body_len = if let Some(start) = body_start {
        if start < lines.len() {
            lines[start..].iter().map(|l| l.len()).sum::<usize>() as u64
        } else {
            0
        }
    } else {
        0
    };

    let content_length = get_header("Content-Length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(body_len);

    Some(ParsedRequest {
        method,
        path,
        query,
        user_agent: get_header("User-Agent").unwrap_or("-").to_string(),
        has_cookies: get_header("Cookie").is_some(),
        content_length,
        referer: get_header("Referer").unwrap_or("-").to_string(),
        accept_language: get_header("Accept-Language").unwrap_or("-").to_string(),
        accept: get_header("Accept").unwrap_or("-").to_string(),
    })
}

fn split_path_query(url: &str) -> (String, String) {
    if let Some(q) = url.find('?') {
        (url[..q].to_string(), url[q + 1..].to_string())
    } else {
        (url.to_string(), String::new())
    }
}

/// Simple deterministic LCG for reproducible randomness without pulling in `rand`.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() >> 33) as usize % bound
    }
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn choice<'a>(&mut self, items: &'a [&str]) -> &'a str {
        items[self.next_usize(items.len())]
    }
}

fn to_audit_fields(
    req: &ParsedRequest,
    label: &str,
    hosts: &[&str],
    rng: &mut Rng,
) -> AuditFields {
    let (host_prefix, status) = if label == "normal" {
        let host = rng.choice(hosts).to_string();
        let statuses: &[u16] = &[200, 200, 200, 200, 301, 304];
        let status = statuses[rng.next_usize(statuses.len())];
        (host, status)
    } else {
        let host = if rng.next_f64() < 0.7 {
            let unknown: &[&str] = &["unknown", "scanner", "probe", "test"];
            rng.choice(unknown).to_string()
        } else {
            rng.choice(hosts).to_string()
        };
        let statuses: &[u16] = &[404, 404, 404, 400, 403, 500];
        let status = statuses[rng.next_usize(statuses.len())];
        (host, status)
    };

    let host = format!("{host_prefix}.sunbeam.pt");

    // For anomalous samples, simulate real scanner behavior:
    // strip cookies/referer/accept-language that CSIC attacks have from their session.
    let (has_cookies, referer, accept_language, user_agent) = if label != "normal" {
        let referer = "-".to_string();
        let accept_language = if rng.next_f64() < 0.8 {
            "-".to_string()
        } else {
            let al = req.accept_language.clone();
            if al == "-" { "-".to_string() } else { al }
        };
        let r = rng.next_f64();
        let user_agent = if r < 0.15 {
            String::new()
        } else if r < 0.25 {
            "curl/7.68.0".to_string()
        } else if r < 0.35 {
            "python-requests/2.28.0".to_string()
        } else if r < 0.40 {
            "Go-http-client/1.1".to_string()
        } else {
            req.user_agent.clone()
        };
        (false, referer, accept_language, user_agent)
    } else {
        (
            req.has_cookies,
            if req.referer == "-" { "-".to_string() } else { req.referer.clone() },
            if req.accept_language == "-" { "-".to_string() } else { req.accept_language.clone() },
            req.user_agent.clone(),
        )
    };

    // For normal traffic, preserve Accept header from CSIC request.
    // For attacks, degrade it to simulate scanner behavior.
    let accept = if label == "normal" {
        if req.accept == "-" || req.accept.is_empty() {
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string()
        } else {
            req.accept.clone()
        }
    } else if rng.next_f64() < 0.6 {
        "*/*".to_string()
    } else {
        req.accept.clone()
    };

    AuditFields {
        method: req.method.clone(),
        host,
        path: req.path.clone(),
        query: req.query.clone(),
        client_ip: format!(
            "{}.{}.{}.{}",
            rng.next_usize(223) + 1,
            rng.next_usize(256),
            rng.next_usize(256),
            rng.next_usize(254) + 1,
        ),
        status,
        duration_ms: rng.next_usize(50) as u64 + 1,
        content_length: req.content_length,
        user_agent,
        has_cookies,
        referer,
        accept_language,
        accept,
        backend: if label == "normal" {
            format!("{host_prefix}-svc:8080")
        } else {
            "-".to_string()
        },
        label: Some(
            if label == "normal" { "normal" } else { "attack" }.to_string(),
        ),
        ..AuditFields::default()
    }
}

/// Download (or use cached) CSIC 2010 dataset, parse raw HTTP requests,
/// and convert into labeled `AuditFields` entries ready for scanner training.
pub fn fetch_csic_dataset() -> Result<Vec<(AuditFields, String)>> {
    eprintln!("fetching CSIC 2010 dataset...");

    let mut rng = Rng::new(42);
    let mut all_entries: Vec<(AuditFields, String)> = Vec::new();

    for (filename, label) in FILES {
        let content = download_or_cached(filename)?;
        let requests = parse_csic_content(&content);
        eprintln!("  parsed {} {label} requests from {filename}", requests.len());

        for req in &requests {
            let fields = to_audit_fields(req, label, DEFAULT_HOSTS, &mut rng);
            let host_prefix = fields.host.split('.').next().unwrap_or("").to_string();
            all_entries.push((fields, host_prefix));
        }
    }

    // Shuffle to interleave normal/attack
    let n = all_entries.len();
    for i in (1..n).rev() {
        let j = rng.next_usize(i + 1);
        all_entries.swap(i, j);
    }

    eprintln!(
        "CSIC total: {} ({} normal, {} attack)",
        all_entries.len(),
        all_entries.iter().filter(|(f, _)| f.label.as_deref() == Some("normal")).count(),
        all_entries.iter().filter(|(f, _)| f.label.as_deref() == Some("attack")).count(),
    );

    Ok(all_entries)
}

/// Check if cached CSIC files exist.
pub fn csic_is_cached() -> bool {
    let dir = cache_dir();
    FILES.iter().all(|(f, _)| dir.join(f).exists())
}

/// Return the cache directory path for display.
pub fn csic_cache_path() -> PathBuf {
    cache_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_http_request() {
        let lines = vec![
            "GET /index.html HTTP/1.1",
            "Host: localhost:8080",
            "User-Agent: Mozilla/5.0",
            "Cookie: session=abc",
            "Accept: text/html",
        ];
        let req = parse_single_request(&lines).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/index.html");
        assert!(req.has_cookies);
        assert_eq!(req.user_agent, "Mozilla/5.0");
        assert_eq!(req.accept, "text/html");
    }

    #[test]
    fn test_parse_absolute_url() {
        let lines = vec!["POST http://localhost:8080/tienda1/miembros/editar.jsp?id=2 HTTP/1.1"];
        let req = parse_single_request(&lines).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/tienda1/miembros/editar.jsp");
        assert_eq!(req.query, "id=2");
    }

    #[test]
    fn test_parse_csic_content_multiple_requests() {
        let content = "GET /page1 HTTP/1.1\nHost: localhost\n\nPOST /page2 HTTP/1.1\nHost: localhost\n\n";
        let reqs = parse_csic_content(content);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[1].method, "POST");
    }

    #[test]
    fn test_to_audit_fields_normal() {
        let req = ParsedRequest {
            method: "GET".to_string(),
            path: "/index.html".to_string(),
            query: String::new(),
            user_agent: "Mozilla/5.0".to_string(),
            has_cookies: true,
            content_length: 100,
            referer: "https://example.com".to_string(),
            accept_language: "en-US".to_string(),
            accept: "text/html".to_string(),
        };
        let mut rng = Rng::new(42);
        let fields = to_audit_fields(&req, "normal", DEFAULT_HOSTS, &mut rng);
        assert_eq!(fields.label.as_deref(), Some("normal"));
        assert!(fields.has_cookies);
        assert!(fields.host.ends_with(".sunbeam.pt"));
    }

    #[test]
    fn test_to_audit_fields_anomalous_strips_cookies() {
        let req = ParsedRequest {
            method: "GET".to_string(),
            path: "/.env".to_string(),
            query: String::new(),
            user_agent: "Mozilla/5.0".to_string(),
            has_cookies: true,
            content_length: 0,
            referer: "https://example.com".to_string(),
            accept_language: "en-US".to_string(),
            accept: "text/html".to_string(),
        };
        let mut rng = Rng::new(42);
        let fields = to_audit_fields(&req, "anomalous", DEFAULT_HOSTS, &mut rng);
        assert_eq!(fields.label.as_deref(), Some("attack"));
        assert!(!fields.has_cookies);
    }

    #[test]
    fn test_rng_deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
