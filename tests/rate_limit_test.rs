use std::net::IpAddr;
use sunbeam_proxy::config::{BucketConfig, RateLimitConfig};
use sunbeam_proxy::rate_limit::key::{self, RateLimitKey};
use sunbeam_proxy::rate_limit::limiter::{RateLimitResult, RateLimiter};

fn default_config() -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        bypass_cidrs: vec!["10.0.0.0/8".into(), "fd00::/8".into()],
        eviction_interval_secs: 300,
        stale_after_secs: 600,
        authenticated: BucketConfig {
            burst: 20,
            rate: 10.0,
        },
        unauthenticated: BucketConfig {
            burst: 5,
            rate: 2.0,
        },
    }
}

#[test]
fn test_unauthenticated_burst_limit() {
    let limiter = RateLimiter::new(&default_config());
    let ip: IpAddr = "203.0.113.50".parse().unwrap();
    let key = RateLimitKey::Ip(ip);

    for _ in 0..5 {
        assert_eq!(limiter.check(ip, key), RateLimitResult::Allow);
    }
    match limiter.check(ip, key) {
        RateLimitResult::Reject { retry_after } => assert!(retry_after >= 1),
        _ => panic!("expected reject after burst exhaustion"),
    }
}

#[test]
fn test_authenticated_gets_higher_burst() {
    let limiter = RateLimiter::new(&default_config());
    let ip: IpAddr = "203.0.113.51".parse().unwrap();
    let key = RateLimitKey::Identity(99999);

    for i in 0..20 {
        assert_eq!(
            limiter.check(ip, key),
            RateLimitResult::Allow,
            "request {i} should be allowed"
        );
    }
    assert!(matches!(
        limiter.check(ip, key),
        RateLimitResult::Reject { .. }
    ));
}

#[test]
fn test_cluster_cidr_bypass() {
    let limiter = RateLimiter::new(&default_config());
    let internal_ip: IpAddr = "10.244.1.5".parse().unwrap();
    let key = RateLimitKey::Ip(internal_ip);

    // Should never be rate-limited
    for _ in 0..200 {
        assert_eq!(limiter.check(internal_ip, key), RateLimitResult::Allow);
    }
}

#[test]
fn test_key_extraction_cookie() {
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let key = key::extract_key(
        Some("_csrf=abc; ory_kratos_session=session123; lang=en"),
        None,
        ip,
    );
    assert!(key.is_authenticated());
}

#[test]
fn test_key_extraction_bearer() {
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let key = key::extract_key(None, Some("Bearer gitea_pat_abc123"), ip);
    assert!(key.is_authenticated());
}

#[test]
fn test_key_extraction_ip_fallback() {
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let key = key::extract_key(None, None, ip);
    assert_eq!(key, RateLimitKey::Ip(ip));
}

#[test]
fn test_concurrent_different_ips() {
    let limiter = std::sync::Arc::new(RateLimiter::new(&default_config()));
    let mut handles = vec![];

    for i in 0..10u8 {
        let limiter = limiter.clone();
        handles.push(std::thread::spawn(move || {
            let ip: IpAddr = format!("203.0.113.{i}").parse().unwrap();
            let key = RateLimitKey::Ip(ip);
            let mut allowed = 0;
            for _ in 0..10 {
                if limiter.check(ip, key) == RateLimitResult::Allow {
                    allowed += 1;
                }
            }
            // Each IP gets burst=5, so exactly 5 should be allowed
            assert_eq!(allowed, 5, "IP 203.0.113.{i} allowed {allowed}, expected 5");
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
