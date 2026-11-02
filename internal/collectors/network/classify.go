package network

import "net/netip"

// AddressClass categorizes an IP address. No class is suspicious by itself.
type AddressClass string

// Address classes.
const (
	ClassUnspecified AddressClass = "Unspecified" // 0.0.0.0 or ::, for example a listener on all interfaces
	ClassLoopback    AddressClass = "Loopback"
	ClassLinkLocal   AddressClass = "LinkLocal"
	ClassPrivate     AddressClass = "Private" // RFC 1918 and IPv6 unique local (fc00::/7)
	ClassPublic      AddressClass = "Public"
	ClassMulticast   AddressClass = "Multicast"
	ClassBroadcast   AddressClass = "Broadcast"
	ClassReserved    AddressClass = "Reserved" // special-purpose, documentation, shared (CGNAT) and similar
	ClassUnknown     AddressClass = "Unknown"  // no valid address, for example a UDP socket's remote end
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

var (
	reserved4 = prefixes(
		"0.0.0.0/8",       // "this network"
		"100.64.0.0/10",   // shared address space (CGNAT)
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved for future use
	)
	reserved6 = prefixes(
		"::/96",         // deprecated IPv4-compatible
		"100::/64",      // discard-only
		"2001:db8::/32", // documentation
		"2001:10::/28",  // ORCHID (deprecated)
		"2001:20::/28",  // ORCHIDv2
		"fec0::/10",     // deprecated site-local
	)
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
)

// Classify returns the class of a.
func Classify(a netip.Addr) AddressClass {
	if !a.IsValid() {
		return ClassUnknown
	}
	a = a.WithZone("")
	if a.Is4In6() {
		return Classify(a.Unmap())
	}
	if nat64.Contains(a) {
		b := a.As16()
		return Classify(netip.AddrFrom4([4]byte(b[12:16])))
	}
	switch {
	case a.IsUnspecified():
		return ClassUnspecified
	case a.IsLoopback():
		return ClassLoopback
	case a.IsMulticast():
		return ClassMulticast
	case a.IsLinkLocalUnicast():
		return ClassLinkLocal
	case a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return ClassBroadcast
	}
	table := reserved6
	if a.Is4() {
		table = reserved4
	}
	for _, p := range table {
		if p.Contains(a) {
			return ClassReserved
		}
	}
	switch {
	case a.IsPrivate():
		return ClassPrivate
	case a.IsGlobalUnicast():
		return ClassPublic
	}
	return ClassUnknown
}
