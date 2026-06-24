// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::Utc;
use pingora_cache::MemCache;
use std::sync::LazyLock;

/// In-memory cache backend shared across all requests.
/// `Storage` requires `&'static self`, so we store it in a static.
pub static CACHE_BACKEND: LazyLock<MemCache> = LazyLock::new(MemCache::new);

/// Check whether a lowercased Cache-Control header value contains the given
/// directive as a whole token (e.g. `no-store`, `private`).
pub fn cache_control_has_directive(cc: &str, directive: &str) -> bool {
    cc.split(',').any(|part| part.trim() == directive)
}

/// Parse s-maxage or max-age from a (lowercased) Cache-Control header value.
/// s-maxage takes priority (shared cache directive).
pub fn parse_cache_ttl(cc: &str) -> Option<u64> {
    let mut max_age = None;
    let mut s_maxage = None;
    for part in cc.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("s-maxage=") {
            s_maxage = val.trim().parse().ok();
        } else if let Some(val) = part.strip_prefix("max-age=") {
            max_age = val.trim().parse().ok();
        }
    }
    s_maxage.or(max_age)
}

/// Parse an Age header value into seconds.
pub fn parse_age(age: &str) -> Option<u64> {
    age.trim().parse().ok()
}

/// Parse an Expires header (IMF-fixdate, RFC 7231) and return the remaining TTL
/// in seconds. Returns `Some(0)` if the date is in the past.
pub fn parse_expires_ttl(expires: &str) -> Option<u64> {
    let s = expires.trim();
    // IMF-fixdate ends with a literal " GMT". Strip it and parse the remaining
    // date/time as a naive UTC timestamp.
    let without_tz = s.strip_suffix(" GMT")?;
    let naive = chrono::NaiveDateTime::parse_from_str(without_tz, "%a, %d %b %Y %H:%M:%S").ok()?;
    let expires_utc = chrono::DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
    let remaining = expires_utc.signed_duration_since(Utc::now());
    if remaining.num_seconds() <= 0 {
        Some(0)
    } else {
        Some(remaining.num_seconds() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_max_age_only() {
        assert_eq!(parse_cache_ttl("public, max-age=3600"), Some(3600));
    }

    #[test]
    fn parse_s_maxage_takes_priority() {
        assert_eq!(
            parse_cache_ttl("public, max-age=3600, s-maxage=60"),
            Some(60)
        );
    }

    #[test]
    fn parse_no_age_directives() {
        assert_eq!(parse_cache_ttl("no-cache"), None);
    }

    #[test]
    fn parse_zero_max_age() {
        assert_eq!(parse_cache_ttl("max-age=0"), Some(0));
    }

    #[test]
    fn detects_no_store_directive() {
        assert!(cache_control_has_directive("public, no-store", "no-store"));
        assert!(!cache_control_has_directive(
            "public, max-age=10",
            "no-store"
        ));
    }

    #[test]
    fn detects_no_cache_directive() {
        assert!(cache_control_has_directive("public, no-cache", "no-cache"));
    }

    #[test]
    fn parse_age_value() {
        assert_eq!(parse_age("120"), Some(120));
        assert_eq!(parse_age("  120  "), Some(120));
        assert_eq!(parse_age("abc"), None);
    }

    #[test]
    fn parse_expires_future_date() {
        let future = (Utc::now() + chrono::Duration::seconds(300))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let ttl = parse_expires_ttl(&future).unwrap();
        assert!(ttl >= 295 && ttl <= 300);
    }

    #[test]
    fn parse_expires_past_date_returns_zero() {
        let past = (Utc::now() - chrono::Duration::seconds(10))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        assert_eq!(parse_expires_ttl(&past), Some(0));
    }

    #[test]
    fn parse_expires_invalid_date() {
        assert_eq!(parse_expires_ttl("not a date"), None);
    }
}
