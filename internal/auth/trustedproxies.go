package auth

import (
	"fmt"
	"net/netip"
	"strings"
)

// TrustedProxies are the reverse proxies whose X-Forwarded-For comics believes.
//
// Empty by default, meaning trust nothing: anyone can write the header, so only
// the operator can say which peers may. Guessing from topology (such as "trust
// loopback") is wrong both ways: it trusts any local process and distrusts a
// proxy in a sibling container.
//
// Entries are CIDR prefixes or bare addresses. The list decides both whether
// the peer's header is read and which hops in it are infrastructure; see
// ClientKeys.
type TrustedProxies struct {
	prefixes []netip.Prefix
}

// ParseTrustedProxies reads a comma-separated list. Empty entries are skipped,
// so a trailing comma or a container's empty "unset" value is not an error. A
// bare address is a single-host prefix.
func ParseTrustedProxies(raw string) (TrustedProxies, error) {
	var prefixes []netip.Prefix
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := parseTrustedEntry(entry)
		if err != nil {
			return TrustedProxies{}, err
		}
		prefixes = append(prefixes, prefix)
	}
	return TrustedProxies{prefixes: prefixes}, nil
}

func parseTrustedEntry(entry string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("trusted proxy entry `%s` is neither an IP address "+
			"nor a CIDR prefix (e.g. `10.0.0.2` or `172.16.0.0/12`)", entry)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// IsEmpty reports whether no proxy is trusted.
func (t TrustedProxies) IsEmpty() bool { return len(t.prefixes) == 0 }

// Contains reports whether ip is a trusted proxy. The address is unmapped
// first: a [::]-bound listener reports ::ffff:10.0.0.2, which would otherwise
// never match 10.0.0.0/8.
func (t TrustedProxies) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, prefix := range t.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
