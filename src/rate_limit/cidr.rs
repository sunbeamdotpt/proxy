use std::net::IpAddr;

/// A parsed CIDR block for allowlist matching.
#[derive(Debug, Clone)]
pub struct CidrBlock {
    addr: IpAddr,
    prefix_len: u8,
}

impl CidrBlock {
    /// Parse a CIDR string like "10.0.0.0/8" or "fd00::/8".
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_str, len_str) = s.split_once('/')?;
        let prefix_len: u8 = len_str.parse().ok()?;
        let addr: IpAddr = addr_str.parse().ok()?;
        match &addr {
            IpAddr::V4(_) if prefix_len > 32 => return None,
            IpAddr::V6(_) if prefix_len > 128 => return None,
            _ => {}
        }
        Some(Self { addr, prefix_len })
    }

    /// Check whether `ip` falls within this CIDR block.
    /// Handles IPv4-mapped IPv6 addresses (e.g. `::ffff:10.0.0.1`).
    pub fn contains(&self, ip: IpAddr) -> bool {
        // Normalise IPv4-mapped IPv6 → IPv4
        let ip = normalise(ip);
        let addr = normalise(self.addr);

        match (addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let mask = v4_mask(self.prefix_len);
                u32::from(net) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let mask = v6_mask(self.prefix_len);
                let net_bits = u128::from(net);
                let cand_bits = u128::from(candidate);
                net_bits & mask == cand_bits & mask
            }
            _ => false, // v4 vs v6 mismatch
        }
    }
}

/// Parse a list of CIDR strings, skipping any that are invalid.
pub fn parse_cidrs(strings: &[String]) -> Vec<CidrBlock> {
    strings.iter().filter_map(|s| CidrBlock::parse(s)).collect()
}

/// Check if `ip` is contained in any of the given CIDR blocks.
pub fn is_bypassed(ip: IpAddr, cidrs: &[CidrBlock]) -> bool {
    cidrs.iter().any(|c| c.contains(ip))
}

fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn v6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_contains() {
        let cidr = CidrBlock::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains("10.1.2.3".parse().unwrap()));
        assert!(cidr.contains("10.255.255.255".parse().unwrap()));
        assert!(!cidr.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_contains() {
        let cidr = CidrBlock::parse("fd00::/8").unwrap();
        assert!(cidr.contains("fd12::1".parse().unwrap()));
        assert!(!cidr.contains("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_v6() {
        let cidr = CidrBlock::parse("10.0.0.0/8").unwrap();
        // ::ffff:10.0.0.1 should match 10.0.0.0/8
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(cidr.contains(mapped));
    }

    #[test]
    fn test_private_ranges() {
        let cidrs = parse_cidrs(&[
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
        ]);
        assert!(is_bypassed("10.0.0.1".parse().unwrap(), &cidrs));
        assert!(is_bypassed("172.31.255.1".parse().unwrap(), &cidrs));
        assert!(is_bypassed("192.168.1.1".parse().unwrap(), &cidrs));
        assert!(!is_bypassed("8.8.8.8".parse().unwrap(), &cidrs));
    }

    #[test]
    fn test_invalid_cidrs() {
        assert!(CidrBlock::parse("not-a-cidr").is_none());
        assert!(CidrBlock::parse("10.0.0.0/33").is_none());
        assert!(CidrBlock::parse("10.0.0.0").is_none());
    }

    #[test]
    fn test_slash_zero() {
        let cidr = CidrBlock::parse("0.0.0.0/0").unwrap();
        assert!(cidr.contains("1.2.3.4".parse().unwrap()));
        assert!(cidr.contains("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_slash_32() {
        let cidr = CidrBlock::parse("1.2.3.4/32").unwrap();
        assert!(cidr.contains("1.2.3.4".parse().unwrap()));
        assert!(!cidr.contains("1.2.3.5".parse().unwrap()));
    }
}
