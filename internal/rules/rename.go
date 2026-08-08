// Package rules groups the rename tool (address objects "named after their
// IP") and the cleanup tool (rules with 0 hit-count). It's the only one of
// the three tools that generates set/delete commands meant to be loaded
// onto the device, by the user, never automatically. It never talks to the
// network except for rename's optional PTR lookup, isolated and
// non-blocking.
package rules

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/inventory"
)

// ipNameRE: port of _IP_NAME_RE (srxtool.py L811-815).
var ipNameRE = regexp.MustCompile(
	`^(?:[A-Za-z]{1,6}[-_])?` + // optional prefix h-, host_, net_, addr_
		`(\d{1,3}(?:\.\d{1,3}){3})` + // the IP
		`(?:[/_-](\d{1,2}))?$`) // optional /mask (/, _ or -)

// IPNamed: port of ip_named() (srxtool.py L818-833). If the object is
// "named after its IP" (uninformative), returns the detected IP/prefix and
// true, otherwise ("", false). Also recognizes the name == prefix case.
func IPNamed(name string, prefix *string) (string, bool) {
	n := strings.TrimSpace(name)
	if prefix != nil && n == *prefix {
		if _, err := netip.ParsePrefix(withMask(*prefix)); err == nil {
			return *prefix, true
		}
	}
	m := ipNameRE.FindStringSubmatch(n)
	if m == nil {
		return "", false
	}
	ip := m[1]
	for _, oct := range strings.Split(ip, ".") {
		v, err := strconv.Atoi(oct)
		if err != nil || v < 0 || v > 255 {
			return "", false
		}
	}
	if m[2] != "" {
		return ip + "/" + m[2], true
	}
	return ip, true
}

// withMask reproduces ipaddress.ip_network(prefix, strict=False) for
// validity detection: a network with no explicit mask is treated as a
// single host (/32 or /128).
func withMask(prefix string) string {
	if strings.Contains(prefix, "/") {
		return prefix
	}
	if strings.Contains(prefix, ":") {
		return prefix + "/128"
	}
	return prefix + "/32"
}

// appHint is an entry from _APP_HINTS (srxtool.py L865-878): keywords then
// the associated role. ORDER matters — the first hint that matches wins.
type appHint struct {
	keys []string
	role string
}

var appHints = []appHint{
	{[]string{"https", "443", "junos-https"}, "web"},
	{[]string{"http", "80", "junos-http"}, "web"},
	{[]string{"ssh", "22", "junos-ssh"}, "ssh"},
	{[]string{"rdp", "3389", "junos-ms-rdp", "junos-rdp"}, "rdp"},
	{[]string{"mysql", "3306", "junos-mysql"}, "db"},
	{[]string{"mssql", "1433", "junos-ms-sql", "ms-sql"}, "db"},
	{[]string{"ldap", "389", "junos-ldap", "ldaps", "636"}, "ldap"},
	{[]string{"dns", "53", "junos-dns-tcp", "junos-dns-udp"}, "dns"},
	{[]string{"smtp", "25", "junos-smtp"}, "mail"},
	{[]string{"smb", "445", "junos-smb", "cifs"}, "file"},
	{[]string{"ntp", "123", "junos-ntp"}, "ntp"},
	{[]string{"snmp", "161", "junos-snmp"}, "snmp"},
	{[]string{"syslog", "514", "junos-syslog"}, "log"},
}

// AppRole: port of app_role() (srxtool.py L880-885).
func AppRole(apps []string) string {
	lower := make([]string, len(apps))
	for i, a := range apps {
		lower[i] = strings.ToLower(a)
	}
	joined := strings.Join(lower, " ")
	for _, hint := range appHints {
		for _, k := range hint.keys {
			if strings.Contains(joined, k) {
				return hint.role
			}
		}
	}
	return ""
}

// ptrLookupTimeout bounds the optional PTR lookup: an outbound network call
// triggered by the content of the uploaded conf must never block an HTTP
// request. Reproduces ptr_lookup()'s `except Exception: return None`
// (srxtool.py L887-893) but with an explicit time budget, absent on the
// Python side (which inherited the system DNS timeout, potentially long).
var ptrLookupTimeout = 2 * time.Second

// PTRLookup: port of ptr_lookup(). Optional reverse DNS resolution, silent
// failure (returns "").
func PTRLookup(ip string) string {
	r := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), ptrLookupTimeout)
	defer cancel()
	names, err := r.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

var nonNameCharRE = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// SuggestName: port of suggest_name() (srxtool.py L895-912).
func SuggestName(ipPrefix string, zoneHint string, usages []inventory.Usage, useDNS bool) string {
	ip := ipPrefix
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	lastOctet := ip
	if i := strings.LastIndexByte(ip, '.'); i >= 0 {
		lastOctet = ip[i+1:]
	}

	if useDNS {
		if host := PTRLookup(ip); host != "" {
			label := host
			if i := strings.IndexByte(label, '.'); i >= 0 {
				label = label[:i]
			}
			return nonNameCharRE.ReplaceAllString(label, "-")
		}
	}

	var apps []string
	for _, u := range usages {
		if u.Kind == "policy-dst" {
			apps = append(apps, u.Apps...)
		}
	}
	role := AppRole(apps)

	zpart := strings.ToLower(zoneHint)
	if zpart == "" {
		zpart = "srv"
	}
	if role != "" {
		return zpart + "-" + role + "-" + lastOctet
	}
	return zpart + "-host-" + lastOctet
}

// Candidate: an address object named after its IP, with the context needed
// for the rename plan. Port of the `detected` dicts from cmd_rename()
// (srxtool.py L1357-1376).
type Candidate struct {
	Book     string
	BookType string
	OldName  string
	Prefix   string
	Zones    []string
	Refs     int
	Apps     []string // union of applications seen across ALL references (policy-src+dst)
	ZoneHint string
	Usages   []inventory.Usage
}

// subnetZone associates a network with the zone that carries it, port of
// build_subnet_zone_map() (srxtool.py L1477-1487).
type subnetZone struct {
	net netip.Prefix
	zn  string
}

func buildSubnetZoneMap(m *config.Model) []subnetZone {
	var out []subnetZone
	for _, vn := range sortedVLANKeys(m.VLANs) {
		v := m.VLANs[vn]
		if v.Zone == nil {
			continue
		}
		for _, a := range v.L3Addresses {
			if p, err := netip.ParsePrefix(withMask(a)); err == nil {
				out = append(out, subnetZone{net: p.Masked(), zn: *v.Zone})
			}
		}
	}
	return out
}

// zoneForIP: port of zone_for_ip() (srxtool.py L1489-1496).
func zoneForIP(ip string, zones []subnetZone) string {
	host := ip
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	for _, sz := range zones {
		if sz.net.Contains(addr) {
			return sz.zn
		}
	}
	return ""
}

// DetectIPNamedObjects: port of the body of cmd_rename() that builds
// `detected` (srxtool.py L1359-1376), starting from the inventory result
// (task 02) rather than duplicating build_address_index — task 04 imports
// internal/inventory precisely for that.
func DetectIPNamedObjects(inv *inventory.Result, m *config.Model) []Candidate {
	subnetZones := buildSubnetZoneMap(m)

	var out []Candidate
	for _, o := range inv.AddressObjects {
		ip, ok := IPNamed(o.Name, o.Prefix)
		if !ok {
			continue
		}
		usages := inv.Usages[o.Name]
		appSet := map[string]struct{}{}
		for _, u := range usages {
			for _, a := range u.Apps {
				if a != "" && a != "any" {
					appSet[a] = struct{}{}
				}
			}
		}
		apps := make([]string, 0, len(appSet))
		for a := range appSet {
			apps = append(apps, a)
		}
		sort.Strings(apps)

		prefix := ip
		if o.Prefix != nil {
			prefix = *o.Prefix
		}
		zoneHint := zoneForIP(prefix, subnetZones)
		if zoneHint == "" && len(o.Zones) > 0 {
			zoneHint = o.Zones[0]
		}

		out = append(out, Candidate{
			Book: o.Book, BookType: o.BookType, OldName: o.Name,
			Prefix: prefix, Zones: append([]string{}, o.Zones...),
			Refs: len(usages), Apps: apps, ZoneHint: zoneHint, Usages: usages,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Book != out[j].Book {
			return out[i].Book < out[j].Book
		}
		return out[i].OldName < out[j].OldName
	})
	return out
}

func sortedVLANKeys(m map[string]config.VLAN) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
