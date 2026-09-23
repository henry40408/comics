use std::{net::IpAddr, str::FromStr};

use anyhow::Context as _;
use ipnet::IpNet;

/// The reverse proxies whose `X-Forwarded-For` comics believes.
///
/// Empty by default, meaning **trust nothing**: anyone can write the header, so
/// only the operator can say which peers may. Guessing from topology (e.g.
/// "trust loopback") is wrong both ways — it trusts any local process and
/// distrusts a proxy in a sibling container.
///
/// Entries are CIDR prefixes or bare addresses. The list decides both whether
/// the peer's header is read and which hops in it are infrastructure; see
/// [`rate_limit_key`](super::rate_limit_key).
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies(Vec<IpNet>);

impl TrustedProxies {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Canonicalised first: a `[::]`-bound listener reports `::ffff:10.0.0.2`,
    /// which would otherwise never match `10.0.0.0/8`.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|net| net.contains(&ip))
    }
}

impl FromStr for TrustedProxies {
    type Err = anyhow::Error;

    /// Empty entries are skipped, so a trailing comma or a container's empty
    /// "unset" value is not an error. A bare address is a single-host prefix.
    fn from_str(raw: &str) -> anyhow::Result<Self> {
        let mut nets = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let net = match entry.parse::<IpNet>() {
                Ok(net) => net,
                Err(_) => IpNet::from(
                    entry
                        .parse::<IpAddr>()
                        .context(format!(
                            "trusted proxy entry `{entry}` is neither an IP address \
                             nor a CIDR prefix (e.g. `10.0.0.2` or `172.16.0.0/12`)"
                        ))?
                        .to_canonical(),
                ),
            };
            nets.push(net);
        }
        Ok(Self(nets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn parse(raw: &str) -> TrustedProxies {
        raw.parse().expect("valid list")
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn default_trusts_nothing() {
        let trusted = TrustedProxies::default();
        assert!(trusted.is_empty());
        assert!(!trusted.contains(v4(127, 0, 0, 1)));
        assert!(!trusted.contains(v4(10, 0, 0, 1)));
    }

    #[test]
    fn parses_a_mix_of_prefixes_and_bare_addresses() {
        let trusted = parse("172.16.0.0/12, 10.0.0.2 ,::1");
        assert!(!trusted.is_empty());
        assert!(trusted.contains(v4(172, 20, 3, 4)));
        assert!(trusted.contains(v4(10, 0, 0, 2)));
        assert!(trusted.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        assert!(!trusted.contains(v4(172, 32, 0, 1)));
        assert!(!trusted.contains(v4(10, 0, 0, 3)));
    }

    #[test]
    fn empty_and_blank_values_are_the_empty_list() {
        for raw in ["", "   ", ",", " , "] {
            assert!(parse(raw).is_empty(), "{raw:?}");
        }
    }

    #[test]
    fn rejects_entries_that_are_neither_address_nor_prefix() {
        for raw in ["nonsense", "10.0.0.0/99", "10.0.0.256", "10.0.0.1-10.0.0.9"] {
            assert!(raw.parse::<TrustedProxies>().is_err(), "{raw} was accepted");
        }
    }

    #[test]
    fn error_names_the_offending_entry() {
        let err = "10.0.0.0/8, wat, ::1"
            .parse::<TrustedProxies>()
            .expect_err("should reject");
        assert!(format!("{err}").contains("wat"), "{err}");
    }

    #[test]
    fn ipv4_mapped_addresses_match_ipv4_prefixes() {
        let trusted = parse("10.0.0.0/8");
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        assert!(trusted.contains(mapped));

        // A mapped literal in the list is stored canonicalised.
        let trusted = parse("::ffff:192.0.2.7");
        assert!(trusted.contains(v4(192, 0, 2, 7)));
    }

    #[test]
    fn ipv6_prefixes_match_ipv6_addresses() {
        let trusted = parse("fd00::/8");
        assert!(trusted.contains("fd12::1".parse().unwrap()));
        assert!(!trusted.contains("fe80::1".parse().unwrap()));
    }
}
