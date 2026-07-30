use std::{net::IpAddr, str::FromStr};

use anyhow::Context as _;
use ipnet::IpNet;

/// The reverse proxies whose forwarding headers comics is willing to believe.
///
/// Empty by default, and empty means **trust nothing**: the rate-limit key is
/// the TCP peer and `X-Forwarded-For` is ignored outright. That default is the
/// whole point of the type. Anyone who can reach the port can write the header,
/// so which peers are allowed to is a statement only the operator can make —
/// the rule this replaced ("believe the header when the peer is loopback")
/// guessed at it from the network topology, and guessed wrong in both
/// directions: it trusts any process sharing the host, and it distrusts a proxy
/// running as a sibling container, which is the common deployment.
///
/// Entries are CIDR prefixes or bare addresses (a bare address is its own
/// single-host prefix). The list does double duty: it decides whether the peer
/// may speak at all, *and* which hops inside `X-Forwarded-For` are infrastructure
/// rather than clients — see [`rate_limit_key`](super::rate_limit_key).
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies(Vec<IpNet>);

impl TrustedProxies {
    /// Whether no proxy is trusted, i.e. forwarding headers are ignored.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `ip` falls inside any configured prefix.
    ///
    /// The address is canonicalised first, so a dual-stack listener reporting a
    /// peer as `::ffff:10.0.0.2` still matches a `10.0.0.0/8` entry. Without
    /// that, an operator who wrote the obvious IPv4 prefix would silently get no
    /// match at all on a `[::]`-bound socket.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|net| net.contains(&ip))
    }
}

impl FromStr for TrustedProxies {
    type Err = anyhow::Error;

    /// Parse a comma-separated list of CIDR prefixes and bare addresses.
    ///
    /// Empty entries are skipped so a trailing comma — or an env var set to the
    /// empty string, which is how a container image ends up passing "unset" —
    /// is not an error. A bare address parses as a single-host prefix, since
    /// `10.0.0.1` is what an operator writes when they mean `10.0.0.1/32`.
    fn from_str(raw: &str) -> anyhow::Result<Self> {
        let mut nets = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let net = match entry.parse::<IpNet>() {
                Ok(net) => net,
                // Not a prefix: accept a bare address as a single host. Reported
                // against the original entry, as the operator wrote it.
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

    /// An empty value is how "unset" arrives from a container image that always
    /// passes the variable, so it must mean the empty list rather than an error.
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

    /// The error names the offending entry, not just the whole list — a typo in
    /// one of six prefixes is otherwise a hunt.
    #[test]
    fn error_names_the_offending_entry() {
        let err = "10.0.0.0/8, wat, ::1"
            .parse::<TrustedProxies>()
            .expect_err("should reject");
        assert!(format!("{err}").contains("wat"), "{err}");
    }

    /// Regression for the IPv4-mapped case: a `[::]`-bound listener reports an
    /// IPv4 peer as `::ffff:a.b.c.d`, which matches no IPv4 prefix until it is
    /// canonicalised. Left unhandled, every operator's `10.0.0.0/8` entry would
    /// quietly match nothing.
    #[test]
    fn ipv4_mapped_addresses_match_ipv4_prefixes() {
        let trusted = parse("10.0.0.0/8");
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        assert!(trusted.contains(mapped));

        // And the same in the entry: a mapped literal is stored canonicalised.
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
