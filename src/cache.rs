// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use pingora_cache::MemCache;
use std::sync::LazyLock;

/// In-memory cache backend shared across all requests.
/// `Storage` requires `&'static self`, so we store it in a static.
pub static CACHE_BACKEND: LazyLock<MemCache> = LazyLock::new(MemCache::new);

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
}
