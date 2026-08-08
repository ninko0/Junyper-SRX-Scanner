package config

import (
	"net/netip"
	"strings"
)

// isPrivate is the port of is_private() (srxaudit.py L88-92):
//
//	def is_private(ip):
//	    try:    return ipaddress.ip_address(ip.split("/")[0]).is_private
//	    except ValueError: return True
//
// `ipaddress.is_private`'s semantics are reproduced explicitly rather
// than replaced by netip.Addr.IsPrivate(), which covers ONLY RFC 1918
// and fc00::/7. The difference isn't cosmetic: 203.0.113.1 (TEST-NET-3,
// present in the fixtures) is private for Python and public for Go.
// Using the Go version would flip the fixtures' `untrust` zone to
// `public`, and therefore change an audit finding's severity. This is
// exactly the kind of silent divergence task 09 aims to avoid.
//
// An unreadable address is considered private (the `except` clause's
// behavior).
var pyPrivateV4 = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.170/31",
	"192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
)

var pyPrivateV4Exceptions = mustPrefixes("192.0.0.9/32", "192.0.0.10/32")

var pyPrivateV6 = mustPrefixes(
	"::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64",
	"2001::/23", "2001:db8::/32", "fc00::/7", "fe80::/10",
)

var pyPrivateV6Exceptions = mustPrefixes(
	"2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48",
	"2001:20::/28", "2001:30::/28",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic("invalid internal prefix: " + s)
		}
		out = append(out, p)
	}
	return out
}

func isPrivate(ip string) bool {
	host := ip
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return true
	}
	// No Unmap(): Python evaluates ::ffff:1.2.3.4 as an IPv6 address
	// (so private via ::ffff:0:0/96), not as its IPv4 equivalent.
	nets, exc := pyPrivateV4, pyPrivateV4Exceptions
	if addr.Is6() {
		nets, exc = pyPrivateV6, pyPrivateV6Exceptions
	}
	in := false
	for _, n := range nets {
		if n.Contains(addr) {
			in = true
			break
		}
	}
	if !in {
		return false
	}
	for _, n := range exc {
		if n.Contains(addr) {
			return false
		}
	}
	return true
}
