package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/local/srxtool-go/internal/config"
)

// obsoleteApps: port of OBSOLETE_APPS (srxaudit.py L145-157), filtered of
// its neutral "junos-ntp" entry (a None value on the Python side, removed
// by the following dict comprehension).
var obsoleteApps = map[string]string{
	"junos-telnet":      "Telnet (credentials in cleartext)",
	"junos-ftp":         "FTP in cleartext",
	"junos-tftp":        "TFTP (no authentication)",
	"junos-rlogin":      "rlogin (cleartext)",
	"junos-rsh":         "rsh (cleartext)",
	"junos-http":        "HTTP in cleartext",
	"junos-snmp":        "SNMP v1/v2c (community strings in cleartext)",
	"junos-snmp-agentx": "SNMP (cleartext)",
	"junos-ldap":        "unencrypted LDAP (389)",
}

// externalZoneHint: port of EXTERNAL_ZONE_HINT (srxaudit.py L159).
// CASE-SENSITIVE comparison, as in Python (`fz in EXTERNAL_ZONE_HINT`
// with no .lower()): a zone named "Untrust" doesn't match. Behavior kept
// as-is — documented, not silently fixed.
var externalZoneHint = map[string]bool{
	"untrust": true, "internet": true, "wan": true,
	"outside": true, "external": true, "inet": true,
}

// mgmtServices: port of MGMT_SERVICES (srxaudit.py L160-161). Compared
// against service names lowercased by the caller (see checkZones).
var mgmtServices = map[string]bool{
	"ssh": true, "telnet": true, "http": true, "https": true,
	"netconf": true, "ssh-netconf": true, "web-authentication": true, "all": true,
}

func isExternalZoneName(zn string) bool { return externalZoneHint[zn] }

func containsAny(ss []string, vals ...string) bool {
	for _, s := range ss {
		for _, v := range vals {
			if s == v {
				return true
			}
		}
	}
	return false
}

// checkPolicies: port of check_policies() (srxaudit.py L341-421).
func checkPolicies(zones map[string]config.Zone, policies []config.Policy) ([]Finding, error) {
	var out []Finding
	for _, p := range policies {
		fz, tz, pn := p.FromZone, p.ToZone, p.Name
		fzq, err := q(fz)
		if err != nil {
			return nil, err
		}
		tzq, err := q(tz)
		if err != nil {
			return nil, err
		}
		pnq, err := q(pn)
		if err != nil {
			return nil, err
		}
		where := fmt.Sprintf("security policies from-zone %s to-zone %s policy %s", fzq, tzq, pnq)
		base := "set " + where

		isExt := isExternalZoneName(fz) || isExternalZoneName(tz) ||
			zones[fz].Public || zones[tz].Public
		srcAny := containsAny(p.Source, "any", "any-ipv4")
		dstAny := containsAny(p.Destination, "any", "any-ipv4")
		appAny := containsAny(p.Application, "any")

		switch {
		case p.Action == "permit" && srcAny && dstAny && appAny:
			sev := High
			if isExt {
				sev = Critical
			}
			out = append(out, Finding{
				Severity: sev, Check: "POL-ANY-ANY", Title: "Full any/any/any permit",
				Where: where,
				Reco: "Restrict source, destination and application to the strict " +
					"minimum (least privilege). A permit any/any/any defeats the " +
					"point of filtering.",
				Ref: "NIST SP 800-41; charter §3.1",
				Fix: []string{
					"# review then replace — example tightening:",
					"# delete " + where,
					"# " + base + " match source-address <SRC_OBJECT>",
					"# " + base + " match destination-address <DST_OBJECT>",
					"# " + base + " match application <APP>",
				},
			})
		case p.Action == "permit" && appAny:
			// Port of `base.split(' match')[0]`: cuts base at the first
			// occurrence of " match", if any (there never is one in the
			// `base` built above, but the split is reproduced identically
			// to stay faithful to the Python behavior).
			trimmed := base
			if i := strings.Index(base, " match"); i >= 0 {
				trimmed = base[:i]
			}
			out = append(out, Finding{
				Severity: High, Check: "POL-APP-ANY", Title: "Permit with application any",
				Where: where,
				Reco: "Specify the allowed application(s). 'application any' opens " +
					"every port.",
				Ref: "NIST SP 800-41; charter §3.1",
				Fix: []string{
					"# delete " + trimmed + " match application any",
					"# " + base + " match application <SPECIFIC_APP>",
				},
			})
		case p.Action == "permit" && srcAny && dstAny:
			out = append(out, Finding{
				Severity: Medium, Check: "POL-BROAD-ADDR", Title: "Permit with source AND destination any",
				Where: where,
				Reco:  "Restrict at least one of the two sides to a specific object.",
				Ref:   "Charter §3.1",
			})
		}

		if p.Action == "permit" && (isExternalZoneName(fz) || zones[fz].Public) && dstAny {
			out = append(out, Finding{
				Severity: High, Check: "POL-INBOUND-ANY",
				Title: "Inbound traffic from an external zone to destination any",
				Where: where,
				Reco: "Traffic initiated from the Internet must never target 'any' " +
					"as destination: target the published host and go through a " +
					"reverse proxy/WAF where applicable.",
				Ref: "NIST SP 800-41; charter §3.5",
			})
		}

		for _, a := range p.Application {
			if label, ok := obsoleteApps[a]; ok && p.Action == "permit" {
				aq, err := q(a)
				if err != nil {
					return nil, err
				}
				out = append(out, Finding{
					Severity: High, Check: "POL-OBSOLETE-APP",
					Title: "Obsolete protocol allowed: " + label,
					Where: where,
					Reco: fmt.Sprintf("Replace %s with the encrypted equivalent (SSH, SFTP, HTTPS, "+
						"LDAPS, SNMPv3) or formalize a dated exception.", a),
					Ref: "Charter §3.4",
					Fix: []string{fmt.Sprintf("# %s match application %s  <-- to remove/replace", base, aq)},
				})
			}
		}

		if p.Action == "permit" && len(p.Logs) == 0 {
			out = append(out, Finding{
				Severity: Medium, Check: "POL-NOLOG-PERMIT", Title: "Permit with no logging",
				Where: where,
				Reco:  "Enable 'log session-close' for traceability (audit, IR).",
				Ref:   "NIS2 21.2(g); charter §3.8",
				Fix:   []string{base + " then log session-close"},
			})
		}
		if (p.Action == "deny" || p.Action == "reject") && !containsAny(p.Logs, "session-init") {
			out = append(out, Finding{
				Severity: Medium, Check: "POL-NOLOG-DENY", Title: "Deny/reject with no logging",
				Where: where,
				Reco:  "Enable 'log session-init' on denies to detect rejected access attempts.",
				Ref:   "NIST SP 800-41",
				Fix:   []string{base + " then log session-init"},
			})
		}
	}
	return out, nil
}

// checkZones: port of check_zones() (srxaudit.py L423-504).
func checkZones(zones map[string]config.Zone, screens []string) ([]Finding, error) {
	screenSet := make(map[string]bool, len(screens))
	for _, s := range screens {
		screenSet[s] = true
	}

	var out []Finding
	for _, zn := range sortedZoneKeys(zones) {
		z := zones[zn]
		zq, err := q(zn)
		if err != nil {
			return nil, err
		}
		where := "security zones security-zone " + zq
		isExt := isExternalZoneName(zn) || z.Public

		// Faithful port of:
		//   if not z["screen"] and z["interfaces"]:
		//       if is_ext: ZONE-NO-SCREEN
		//       elif z["screen"] is None: ZONE-NO-SCREEN-INT
		//   elif z["screen"] and z["screen"] not in screens: ZONE-SCREEN-MISSING
		//
		// `not z["screen"]` is true if Screen is absent OR empty; the
		// second test is true ONLY if Screen is absent (not just empty) —
		// a bare `screen;` with no value (truthy on the Python side,
		// Screen=&"" here) falls into neither case, as in Python.
		screenAbsent := z.Screen == nil
		screenFalsy := z.Screen == nil || *z.Screen == ""
		switch {
		case screenFalsy && len(z.Interfaces) > 0:
			if isExt {
				out = append(out, Finding{
					Severity: High, Check: "ZONE-NO-SCREEN",
					Title: "External zone with no screen (ids-option)", Where: where,
					Reco: "Attach a screen to this zone: SYN-flood, ip-spoofing, scan, " +
						"land, teardrop protection… Recommended baseline.",
					Ref: "Juniper hardening (screen options)",
					Fix: []string{
						"# baseline screen (to adjust):",
						"set security screen ids-option untrust-screen icmp flood threshold 1000",
						"set security screen ids-option untrust-screen ip spoofing",
						"set security screen ids-option untrust-screen tcp syn-flood alarm-threshold 1024",
						"set security screen ids-option untrust-screen tcp syn-flood attack-threshold 2000",
						"set security screen ids-option untrust-screen tcp land",
						"set " + where + " screen untrust-screen",
					},
				})
			} else if screenAbsent {
				out = append(out, Finding{
					Severity: Low, Check: "ZONE-NO-SCREEN-INT", Title: "Internal zone with no screen",
					Where: where,
					Reco: "Even a minimal screen (ip-spoofing) on internal zones is a " +
						"useful defense in depth.",
					Ref: "Juniper hardening",
				})
			}
		case !screenFalsy && !screenSet[*z.Screen]:
			out = append(out, Finding{
				Severity: Medium, Check: "ZONE-SCREEN-MISSING",
				Title: fmt.Sprintf("Screen '%s' referenced but not defined", *z.Screen),
				Where: where,
				Reco:  "The attached screen doesn't exist in 'security screen ids-option'.",
				Ref:   "Configuration consistency",
			})
		}

		ss := lowerSet(z.SystemServices)
		if ss["all"] {
			sev := High
			if isExt {
				sev = Critical
			}
			out = append(out, Finding{
				Severity: sev, Check: "ZONE-HIB-ALL",
				Title: "host-inbound-traffic system-services = all", Where: where,
				Reco: "Only allow the management services strictly necessary inbound " +
					"on the zone (never 'all', especially on an external zone). " +
					"Exposing 'all' publishes every service of the engine.",
				Ref: "Juniper hardening; NIST SP 800-41",
				Fix: []string{
					"delete " + where + " host-inbound-traffic system-services all",
					"# then add only what's needed, e.g.:",
					"# set " + where + " host-inbound-traffic system-services ping",
				},
			})
		} else if isExt {
			exposed := intersectSorted(ss, mgmtServices)
			if len(exposed) > 0 {
				out = append(out, Finding{
					Severity: High, Check: "ZONE-HIB-MGMT-EXT",
					Title: "Management service(s) exposed externally: " + strings.Join(exposed, ", "),
					Where: where,
					Reco: "Don't expose SSH/HTTP/HTTPS/NETCONF/Telnet inbound from an " +
						"external zone. Manage via a dedicated administration " +
						"network / VPN.",
					Ref: "Juniper hardening",
					Fix: []string{fmt.Sprintf("# delete %s host-inbound-traffic system-services <%s>",
						where, strings.Join(exposed, "/"))},
				})
			}
		}

		if lowerSet(z.Protocols)["all"] {
			out = append(out, Finding{
				Severity: Medium, Check: "ZONE-HIB-PROTO-ALL",
				Title: "host-inbound-traffic protocols = all", Where: where,
				Reco: "Limit to the routing protocols actually in use.",
				Ref:  "Juniper hardening",
				Fix:  []string{"delete " + where + " host-inbound-traffic protocols all"},
			})
		}
	}
	return out, nil
}

func sortedZoneKeys(m map[string]config.Zone) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lowerSet(ss []string) map[string]bool {
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[strings.ToLower(s)] = true
	}
	return out
}

// intersectSorted: port of `ss & MGMT_SERVICES` then `sorted(exposed)`.
func intersectSorted(a map[string]bool, b map[string]bool) []string {
	var out []string
	for k := range a {
		if b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
