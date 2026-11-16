package auth

import (
	"net/netip"
	"strings"
	"testing"
)

func mustParseProxies(t *testing.T, raw string) TrustedProxies {
	t.Helper()
	trusted, err := ParseTrustedProxies(raw)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%q): %v", raw, err)
	}
	return trusted
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDefaultTrustsNothing(t *testing.T) {
	var trusted TrustedProxies
	if !trusted.IsEmpty() {
		t.Fatal("zero value not empty")
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1"} {
		if trusted.Contains(addr(ip)) {
			t.Errorf("%s trusted by default", ip)
		}
	}
}

func TestParsesAMixOfPrefixesAndBareAddresses(t *testing.T) {
	trusted := mustParseProxies(t, "172.16.0.0/12, 10.0.0.2 ,::1")
	if trusted.IsEmpty() {
		t.Fatal("list is empty")
	}
	for _, ip := range []string{"172.20.3.4", "10.0.0.2", "::1"} {
		if !trusted.Contains(addr(ip)) {
			t.Errorf("%s not trusted", ip)
		}
	}
	for _, ip := range []string{"172.32.0.1", "10.0.0.3"} {
		if trusted.Contains(addr(ip)) {
			t.Errorf("%s trusted", ip)
		}
	}
}

func TestEmptyAndBlankValuesAreTheEmptyList(t *testing.T) {
	for _, raw := range []string{"", "   ", ",", " , "} {
		if !mustParseProxies(t, raw).IsEmpty() {
			t.Errorf("%q is not the empty list", raw)
		}
	}
}

func TestRejectsEntriesThatAreNeitherAddressNorPrefix(t *testing.T) {
	for _, raw := range []string{"nonsense", "10.0.0.0/99", "10.0.0.256", "10.0.0.1-10.0.0.9"} {
		if _, err := ParseTrustedProxies(raw); err == nil {
			t.Errorf("%s was accepted", raw)
		}
	}
}

func TestErrorNamesTheOffendingEntry(t *testing.T) {
	_, err := ParseTrustedProxies("10.0.0.0/8, wat, ::1")
	if err == nil {
		t.Fatal("should reject")
	}
	want := "trusted proxy entry `wat` is neither an IP address nor a CIDR prefix"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q lacks %q", err, want)
	}
}

func TestIPv4MappedAddressesMatchIPv4Prefixes(t *testing.T) {
	if !mustParseProxies(t, "10.0.0.0/8").Contains(addr("::ffff:10.1.2.3")) {
		t.Error("mapped address missed its IPv4 prefix")
	}
	// A mapped literal in the list is stored canonicalised.
	if !mustParseProxies(t, "::ffff:192.0.2.7").Contains(addr("192.0.2.7")) {
		t.Error("mapped literal not canonicalised")
	}
}

func TestIPv6PrefixesMatchIPv6Addresses(t *testing.T) {
	trusted := mustParseProxies(t, "fd00::/8")
	if !trusted.Contains(addr("fd12::1")) {
		t.Error("fd12::1 not trusted")
	}
	if trusted.Contains(addr("fe80::1")) {
		t.Error("fe80::1 trusted")
	}
}
