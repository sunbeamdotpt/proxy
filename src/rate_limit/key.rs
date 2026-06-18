// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// Identity key for rate limiting buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitKey {
    /// Hashed auth credential (session cookie or bearer token).
    Identity(u64),
    /// Unauthenticated fallback: client IP.
    Ip(IpAddr),
}

impl RateLimitKey {
    pub fn is_authenticated(&self) -> bool {
        matches!(self, RateLimitKey::Identity(_))
    }
}

/// Extract a rate-limit key from request headers.
///
/// Priority:
/// 1. `ory_kratos_session` cookie → `Identity(hash)`
/// 2. `Authorization: Bearer <token>` → `Identity(hash)`
/// 3. Client IP → `Ip(addr)`
pub fn extract_key(
    cookie_header: Option<&str>,
    auth_header: Option<&str>,
    client_ip: IpAddr,
) -> RateLimitKey {
    // 1. Check for Kratos session cookie
    if let Some(cookies) = cookie_header
        && let Some(value) = extract_cookie_value(cookies, "ory_kratos_session") {
            return RateLimitKey::Identity(fx_hash(value));
        }

    // 2. Check for Bearer token
    if let Some(auth) = auth_header
        && let Some(token) = auth.strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return RateLimitKey::Identity(fx_hash(token));
            }
        }

    // 3. Fall back to IP
    RateLimitKey::Ip(client_ip)
}

fn extract_cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=')
            && k.trim() == name {
                return Some(v.trim());
            }
    }
    None
}

fn fx_hash(s: &str) -> u64 {
    let mut h = rustc_hash::FxHasher::default();
    s.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_extraction() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let key = extract_key(Some("ory_kratos_session=abc123; other=val"), None, ip);
        assert!(key.is_authenticated());
        assert!(matches!(key, RateLimitKey::Identity(_)));
    }

    #[test]
    fn test_cookie_only_cookie() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let key = extract_key(Some("ory_kratos_session=tok"), None, ip);
        assert!(key.is_authenticated());
    }

    #[test]
    fn test_bearer_extraction() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let key = extract_key(None, Some("Bearer my-token-123"), ip);
        assert!(key.is_authenticated());
    }

    #[test]
    fn test_ip_fallback() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let key = extract_key(None, None, ip);
        assert_eq!(key, RateLimitKey::Ip(ip));
        assert!(!key.is_authenticated());
    }

    #[test]
    fn test_cookie_takes_priority_over_bearer() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let key_cookie = extract_key(Some("ory_kratos_session=sess1"), Some("Bearer tok1"), ip);
        let key_bearer = extract_key(None, Some("Bearer tok1"), ip);
        // Cookie and bearer should produce different hashes
        assert_ne!(key_cookie, key_bearer);
        assert!(key_cookie.is_authenticated());
    }

    #[test]
    fn test_empty_bearer_falls_back() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let key = extract_key(None, Some("Bearer "), ip);
        assert_eq!(key, RateLimitKey::Ip(ip));
    }

    #[test]
    fn test_multiple_cookies() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let key = extract_key(
            Some("foo=bar; ory_kratos_session=mysess; baz=qux"),
            None,
            ip,
        );
        assert!(key.is_authenticated());
    }

    #[test]
    fn test_wrong_cookie_name_falls_back() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let key = extract_key(Some("session=val"), None, ip);
        assert_eq!(key, RateLimitKey::Ip(ip));
    }
}
