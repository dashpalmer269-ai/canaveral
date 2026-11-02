package network

import (
	"net/netip"
	"testing"
)

// Acceptance (M3): classification covers IPv4 and IPv6 loopback, link-local,
// private/ULA, public, multicast, reserved and unknown.
func TestClassify(t *testing.T) {
	cases := map[string]AddressClass{
		// IPv4
		"0.0.0.0":         ClassUnspecified,
		"127.0.0.1":       ClassLoopback,
		"127.255.0.9":     ClassLoopback,
		"169.254.10.20":   ClassLinkLocal,
		"10.1.2.3":        ClassPrivate,
		"172.16.0.1":      ClassPrivate,
		"172.31.255.254":  ClassPrivate,
		"192.168.1.1":     ClassPrivate,
		"172.32.0.1":      ClassPublic,
		"8.8.8.8":         ClassPublic,
		"52.96.0.1":       ClassPublic,
		"224.0.0.251":     ClassMulticast,
		"239.255.255.250": ClassMulticast,
		"255.255.255.255": ClassBroadcast,
		"100.64.0.1":      ClassReserved,
		"192.0.2.10":      ClassReserved,
		"198.51.100.7":    ClassReserved,
		"203.0.113.9":     ClassReserved,
		"198.18.0.1":      ClassReserved,
		"240.0.0.1":       ClassReserved,
		"0.1.2.3":         ClassReserved,
		// IPv6
		"::":                   ClassUnspecified,
		"::1":                  ClassLoopback,
		"fe80::1":              ClassLinkLocal,
		"fe80::1%12":           ClassLinkLocal,
		"fc00::1":              ClassPrivate,
		"fd12:3456:789a::1":    ClassPrivate,
		"2001:4860:4860::8888": ClassPublic,
		"2606:4700::1111":      ClassPublic,
		"2001:0:4136:e378::1":  ClassPublic, // Teredo is globally routed
		"ff02::fb":             ClassMulticast,
		"ff05::1:3":            ClassMulticast,
		"2001:db8::1":          ClassReserved,
		"100::1":               ClassReserved,
		"2001:10::1":           ClassReserved,
		"fec0::1":              ClassReserved,
		"::1.2.3.4":            ClassReserved, // deprecated IPv4-compatible
		// Embedded IPv4 is classified by the IPv4 address.
		"::ffff:192.168.0.1": ClassPrivate,
		"::ffff:127.0.0.1":   ClassLoopback,
		"::ffff:8.8.8.8":     ClassPublic,
		"64:ff9b::8.8.8.8":   ClassPublic,
		"64:ff9b::10.0.0.1":  ClassPrivate,
		// The reserved-prefix table is per family, so mapped addresses must be
		// unmapped before it is consulted (netip's own predicates unmap
		// internally, the table does not).
		"::ffff:100.64.0.1": ClassReserved,
		"::ffff:192.0.2.1":  ClassReserved,
	}
	for s, want := range cases {
		if got := Classify(netip.MustParseAddr(s)); got != want {
			t.Errorf("Classify(%s) = %s, want %s", s, got, want)
		}
	}
	if got := Classify(netip.Addr{}); got != ClassUnknown {
		t.Errorf("invalid address = %s, want Unknown", got)
	}
}
