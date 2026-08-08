package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const fixtures = "../../testdata/fixtures"
const golden = "../../testdata/golden"

func read(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("unreadable fixture: %v", err)
	}
	return b
}

func mustParse(t *testing.T, name string) *Model {
	t.Helper()
	m, err := Parse(read(t, fixtures, name), Options{})
	if err != nil {
		t.Fatalf("%s: parsing failed: %v", name, err)
	}
	return m
}

func TestDetectFormat(t *testing.T) {
	cases := map[string]string{
		"sample.xml":             "xml",
		"sample2.txt":            "curly",
		"sample-show-config.txt": "curly",
		"sample-display-set.txt": "set",
	}
	for name, want := range cases {
		if got := DetectFormat(read(t, fixtures, name)); got != want {
			t.Errorf("DetectFormat(%s) = %q, expected %q", name, got, want)
		}
		if got := mustParse(t, name).SourceFormat; got != want {
			t.Errorf("%s: source_format = %q, expected %q", name, got, want)
		}
	}
}

func TestParseFixtureCounts(t *testing.T) {
	cases := []struct {
		file                          string
		zones, vlans, policies, units int
		warnings                      int
	}{
		{"sample.xml", 1, 0, 1, 0, 0},
		// sample2.txt: line 1 fits on a single line
		// (`system { services { ssh { root-login deny; } } }`). The Python
		// parser is line-by-line and can't read it: it skips it and emits
		// 2 warnings. Behavior reproduced identically — fixing this would
		// be a divergence, to be decided explicitly (MD 09).
		{"sample2.txt", 2, 2, 2, 2, 2},
		{"sample-show-config.txt", 2, 2, 2, 2, 0},
		{"sample-display-set.txt", 2, 2, 2, 2, 0},
	}
	for _, c := range cases {
		m := mustParse(t, c.file)
		if len(m.Zones) != c.zones || len(m.VLANs) != c.vlans ||
			len(m.Policies) != c.policies || len(m.Units) != c.units {
			t.Errorf("%s: zones=%d vlans=%d policies=%d units=%d, expected %d/%d/%d/%d",
				c.file, len(m.Zones), len(m.VLANs), len(m.Policies), len(m.Units),
				c.zones, c.vlans, c.policies, c.units)
		}
		if len(m.Warnings) != c.warnings {
			t.Errorf("%s: %d warning(s), expected %d: %v",
				c.file, len(m.Warnings), c.warnings, m.Warnings)
		}
	}
}

// TestOrphanVLAN: a VLAN with no resolvable l3-interface must stay orphan
// (null zone, no L3 address). This is the business signal the inventory
// report expects (task 02).
func TestOrphanVLAN(t *testing.T) {
	for _, f := range []string{"sample2.txt", "sample-display-set.txt"} {
		m := mustParse(t, f)
		v, ok := m.VLANs["VLAN99"]
		if !ok {
			t.Fatalf("%s: VLAN99 missing", f)
		}
		if v.Zone != nil || v.L3Interface != nil || len(v.L3Addresses) != 0 {
			t.Errorf("%s: VLAN99 should be orphan, got %+v", f, v)
		}
		if v.VlanID == nil || *v.VlanID != "99" {
			t.Errorf("%s: incorrect VLAN99 vlan-id", f)
		}
	}
	m := mustParse(t, "sample-show-config.txt")
	if v := m.VLANs["VLAN20"]; v.Zone != nil {
		t.Errorf("VLAN20 should be orphan, zone = %v", *v.Zone)
	}
}

// goldenInv is the projection of inv.json relevant to task 01 (the rest of
// the file — address_objects — is task 02's concern).
type goldenInv struct {
	VLANs map[string]struct {
		VlanID      *string  `json:"vlan_id"`
		L3Interface *string  `json:"l3_interface"`
		Members     []string `json:"members"`
		Zone        *string  `json:"zone"`
		L3Addresses []string `json:"l3_addresses"`
	} `json:"vlans"`
	Zones map[string]struct {
		Interfaces   []string     `json:"interfaces"`
		LegacyBook   *AddressBook `json:"legacy_book"`
		VLANs        []string     `json:"vlans"`
		PoliciesFrom []string     `json:"policies_from"`
		PoliciesTo   []string     `json:"policies_to"`
	} `json:"zones"`
	Policies []struct {
		FromZone    string   `json:"from_zone"`
		ToZone      string   `json:"to_zone"`
		Name        string   `json:"name"`
		Source      []string `json:"source"`
		Destination []string `json:"destination"`
		Application []string `json:"application"`
		Action      string   `json:"action"`
		Flags       []string `json:"flags"`
	} `json:"policies"`
}

// TestGoldenInvSample2 compares the Go output field by field against
// inv.json, produced by the Python version on sample2.txt. This is task
// 01's central regression test.
func TestGoldenInvSample2(t *testing.T) {
	var g goldenInv
	if err := json.Unmarshal(read(t, golden, "inv.json"), &g); err != nil {
		t.Fatalf("unreadable golden: %v", err)
	}
	m := mustParse(t, "sample2.txt")

	if len(g.VLANs) != len(m.VLANs) {
		t.Fatalf("VLAN count: %d vs %d expected", len(m.VLANs), len(g.VLANs))
	}
	for name, want := range g.VLANs {
		got, ok := m.VLANs[name]
		if !ok {
			t.Errorf("VLAN %s missing from the Go model", name)
			continue
		}
		if !eqPtr(got.VlanID, want.VlanID) || !eqPtr(got.L3Interface, want.L3Interface) ||
			!eqPtr(got.Zone, want.Zone) ||
			!reflect.DeepEqual(got.L3Addresses, want.L3Addresses) ||
			!reflect.DeepEqual(got.Members, want.Members) {
			t.Errorf("VLAN %s mismatch:\n go   %+v\n want %+v", name, got, want)
		}
	}

	for name, want := range g.Zones {
		got, ok := m.Zones[name]
		if !ok {
			t.Errorf("zone %s missing from the Go model", name)
			continue
		}
		if !reflect.DeepEqual(got.Interfaces, want.Interfaces) ||
			!reflect.DeepEqual(got.VLANs, want.VLANs) ||
			!reflect.DeepEqual(got.PoliciesFrom, want.PoliciesFrom) ||
			!reflect.DeepEqual(got.PoliciesTo, want.PoliciesTo) {
			t.Errorf("zone %s mismatch:\n go   %+v\n want %+v", name, got, want)
		}
		if (got.LegacyBook == nil) != (want.LegacyBook == nil) {
			t.Errorf("zone %s: legacy_book presence mismatch", name)
			continue
		}
		if got.LegacyBook != nil && !reflect.DeepEqual(*got.LegacyBook, *want.LegacyBook) {
			t.Errorf("zone %s: legacy_book mismatch:\n go   %+v\n want %+v",
				name, *got.LegacyBook, *want.LegacyBook)
		}
	}

	if len(g.Policies) != len(m.Policies) {
		t.Fatalf("policy count: %d vs %d expected", len(m.Policies), len(g.Policies))
	}
	for i, want := range g.Policies {
		got := m.Policies[i]
		if got.FromZone != want.FromZone || got.ToZone != want.ToZone ||
			got.Name != want.Name || got.Action != want.Action ||
			!reflect.DeepEqual(got.Source, want.Source) ||
			!reflect.DeepEqual(got.Destination, want.Destination) ||
			!reflect.DeepEqual(got.Application, want.Application) ||
			!reflect.DeepEqual(got.Flags, want.Flags) {
			t.Errorf("policy #%d mismatch:\n go   %+v\n want %+v", i, got, want)
		}
	}
}

// TestCrossFormatEquivalence: the same configuration written in curly
// braces and in 'display set' must produce exactly the same model. This is
// the guard rail against a divergence between parsers, on the Go side as
// on the Python side.
func TestCrossFormatEquivalence(t *testing.T) {
	curly := mustParse(t, "sample2.txt")
	set := mustParse(t, "sample-display-set.txt")

	if !reflect.DeepEqual(curly.Units, set.Units) {
		t.Errorf("units mismatch:\n curly %+v\n set   %+v", curly.Units, set.Units)
	}
	if !reflect.DeepEqual(curly.VLANs, set.VLANs) {
		t.Errorf("vlans mismatch:\n curly %+v\n set   %+v", curly.VLANs, set.VLANs)
	}
	if !reflect.DeepEqual(curly.Zones, set.Zones) {
		t.Errorf("zones mismatch:\n curly %+v\n set   %+v", curly.Zones, set.Zones)
	}
	if !reflect.DeepEqual(curly.Policies, set.Policies) {
		t.Errorf("policies mismatch:\n curly %+v\n set   %+v", curly.Policies, set.Policies)
	}
}

// TestXMLSample covers find_config_root (the <configuration> is under
// <rpc-reply>) and Junos's XML idioms.
func TestXMLSample(t *testing.T) {
	m := mustParse(t, "sample.xml")
	z, ok := m.Zones["trust"]
	if !ok {
		t.Fatal("zone trust missing")
	}
	if !reflect.DeepEqual(z.Interfaces, []string{"ge-0/0/1.0"}) {
		t.Errorf("zone interfaces: %v", z.Interfaces)
	}
	if !reflect.DeepEqual(z.SystemServices, []string{"all"}) {
		t.Errorf("system-services: %v", z.SystemServices)
	}
	p := m.Policies[0]
	if p.FromZone != "trust" || p.ToZone != "untrust" || p.Name != "p1" || p.Action != "permit" {
		t.Errorf("incorrect XML policy: %+v", p)
	}
	if !reflect.DeepEqual(p.Source, []string{"any"}) {
		t.Errorf("source: %v", p.Source)
	}
}

// TestUniformSubtreeAccess checks that navigating the raw subtrees gives
// the same result regardless of the source format — this is what lets
// task 03 write a single code path where Python tested
// isinstance(system, dict) on every access.
func TestUniformSubtreeAccess(t *testing.T) {
	xmlM := mustParse(t, "sample.xml")
	txtM := mustParse(t, "sample-show-config.txt")

	for _, c := range []struct {
		name string
		m    *Model
		want string
	}{
		{"xml", xmlM, "allow"},
		{"curly", txtM, "allow"},
	} {
		ssh := c.m.System.Sub("services").Sub("ssh")
		if !Exists(ssh) {
			t.Fatalf("%s: ssh subtree not found", c.name)
		}
		if v, _ := ssh.Val("root-login"); v != c.want {
			t.Errorf("%s: root-login = %q, expected %q", c.name, v, c.want)
		}
		if !c.m.System.Sub("services").Has("telnet") {
			t.Errorf("%s: telnet not detected", c.name)
		}
	}
}

func TestFormatErrors(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"random text", "hello, this is not a configuration\n"},
		{"empty", ""},
		{"blank", "   \n\n\t\n"},
		{"json", `{"foo": "bar"}`},
		{"binary", "\x00\x01\x02\x03\xff\xfe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.in), Options{})
			if err == nil {
				t.Fatal("expected a format error")
			}
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("errors.Is(ErrFormat) false for %v", err)
			}
			var fe *FormatError
			if !errors.As(err, &fe) {
				t.Fatalf("errors.As(*FormatError) false for %v", err)
			}
		})
	}
}

func TestAllowEmpty(t *testing.T) {
	m, err := Parse([]byte("hello\n"), Options{AllowEmpty: true})
	if err != nil {
		t.Fatalf("AllowEmpty should neutralize the guard rail: %v", err)
	}
	if len(m.Zones) != 0 {
		t.Error("unexpected non-empty model")
	}
}

func TestMalformedXML(t *testing.T) {
	_, err := Parse([]byte("<configuration><security>"), Options{})
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("truncated XML: expected a format error, got %v", err)
	}
	// External entity: encoding/xml doesn't resolve it and rejects the
	// document.
	xxe := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` +
		`<configuration><system>&x;</system></configuration>`
	if _, err := Parse([]byte(xxe), Options{}); err == nil {
		t.Fatal("an external entity must never be resolved or accepted")
	}
}

func TestMaxBytes(t *testing.T) {
	big := strings.Repeat("a", 2048)
	if _, err := Parse([]byte(big), Options{MaxBytes: 1024}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	if _, err := ParseReader(strings.NewReader(big), Options{MaxBytes: 1024}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ParseReader: expected ErrTooLarge, got %v", err)
	}
}

// TestMalformedCurlyWarns: a conf with unbalanced curly braces must not
// fail silently, it must produce actionable warnings (the frontend's .warn
// banner, task 06).
func TestMalformedCurlyWarns(t *testing.T) {
	conf := "security {\n zones {\n  security-zone trust {\n   interfaces {\n    ge-0/0/0.0;\n"
	m, err := Parse([]byte(conf), Options{})
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if len(m.Warnings) == 0 {
		t.Fatal("unclosed blocks must produce a warning")
	}
	conf2 := "system {\n}\n}\n}\nweird line with no punctuation\n"
	m2, _ := Parse([]byte(conf2), Options{AllowEmpty: true})
	joined := strings.Join(m2.Warnings, " | ")
	if !strings.Contains(joined, "extra closing brace") ||
		!strings.Contains(joined, "not parsed") {
		t.Errorf("expected warnings missing: %q", joined)
	}
}

// TestInactiveStanza: 'inactive:' stanzas are parsed as active (Python
// behavior), but flagged.
func TestInactiveStanza(t *testing.T) {
	conf := "system {\n services {\n  inactive: telnet;\n }\n}\n"
	m, _ := Parse([]byte(conf), Options{AllowEmpty: true})
	if !m.System.Sub("services").Has("telnet") {
		t.Error("an inactive stanza must remain visible to the audit")
	}
	if len(m.Warnings) == 0 || !strings.Contains(strings.Join(m.Warnings, " "), "inactive") {
		t.Errorf("missing 'inactive' warning: %v", m.Warnings)
	}
}

func eqPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
