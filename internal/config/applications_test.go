package config

import "testing"

// TestParseApplications_SetFormat covers the "display set" extraction path
// (extract_text.go): a simple single-service application, a term-based
// multi-service application, and an application-set — the three shapes
// buildApplicationObjects/buildApplicationSetObjects in
// internal/inventory rely on downstream.
func TestParseApplications_SetFormat(t *testing.T) {
	text := `set applications application APP-CUSTOM protocol tcp
set applications application APP-CUSTOM destination-port 8443
set applications application APP-MULTI term T1 protocol tcp
set applications application APP-MULTI term T1 destination-port 80
set applications application APP-MULTI term T2 protocol tcp
set applications application APP-MULTI term T2 destination-port 443
set applications application-set APPSET1 application APP-CUSTOM
set applications application-set APPSET1 application APP-MULTI
set security zones security-zone trust interfaces ge-0/0/0.0
set security policies from-zone trust to-zone untrust policy p1 match source-address any
set security policies from-zone trust to-zone untrust policy p1 match destination-address any
set security policies from-zone trust to-zone untrust policy p1 match application APPSET1
set security policies from-zone trust to-zone untrust policy p1 then permit
`
	m, err := Parse([]byte(text), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	simple, ok := m.Applications["APP-CUSTOM"]
	if !ok {
		t.Fatal("APP-CUSTOM not found in m.Applications")
	}
	if len(simple.Protocol) != 1 || simple.Protocol[0] != "tcp" {
		t.Errorf("APP-CUSTOM.Protocol = %v, want [tcp]", simple.Protocol)
	}
	if len(simple.DestinationPort) != 1 || simple.DestinationPort[0] != "8443" {
		t.Errorf("APP-CUSTOM.DestinationPort = %v, want [8443]", simple.DestinationPort)
	}
	if len(simple.Terms) != 0 {
		t.Errorf("APP-CUSTOM.Terms = %v, want none (simple application)", simple.Terms)
	}

	multi, ok := m.Applications["APP-MULTI"]
	if !ok {
		t.Fatal("APP-MULTI not found in m.Applications")
	}
	if len(multi.Terms) != 2 {
		t.Fatalf("APP-MULTI.Terms has %d entries, want 2", len(multi.Terms))
	}
	if multi.Terms[0].Name != "T1" || multi.Terms[0].DestinationPort[0] != "80" {
		t.Errorf("APP-MULTI.Terms[0] = %+v, want T1/80", multi.Terms[0])
	}
	if multi.Terms[1].Name != "T2" || multi.Terms[1].DestinationPort[0] != "443" {
		t.Errorf("APP-MULTI.Terms[1] = %+v, want T2/443", multi.Terms[1])
	}

	set, ok := m.ApplicationSets["APPSET1"]
	if !ok {
		t.Fatal("APPSET1 not found in m.ApplicationSets")
	}
	wantMembers := map[string]bool{"APP-CUSTOM": true, "APP-MULTI": true}
	if len(set.Applications) != 2 {
		t.Fatalf("APPSET1.Applications = %v, want 2 members", set.Applications)
	}
	for _, a := range set.Applications {
		if !wantMembers[a] {
			t.Errorf("unexpected member %q in APPSET1.Applications", a)
		}
	}

	// The policy referencing the application-set should still parse
	// normally — applications aren't expected to change policy parsing.
	if len(m.Policies) != 1 || m.Policies[0].Application[0] != "APPSET1" {
		t.Errorf("policy application = %v, want [APPSET1]", m.Policies[0].Application)
	}
}

// TestParseApplications_XML covers the same three shapes through the XML
// extraction path (extract_xml.go), wrapped in <rpc-reply> like a real
// `show configuration | display xml` capture (see
// testdata/fixtures/sample.xml).
func TestParseApplications_XML(t *testing.T) {
	xmlDoc := `<rpc-reply>
<configuration>
<applications>
<application><name>APP-CUSTOM</name><protocol>tcp</protocol><destination-port>8443</destination-port></application>
<application><name>APP-MULTI</name>
<term><name>T1</name><protocol>tcp</protocol><destination-port>80</destination-port></term>
<term><name>T2</name><protocol>tcp</protocol><destination-port>443</destination-port></term>
</application>
<application-set><name>APPSET1</name>
<application><name>APP-CUSTOM</name></application>
<application><name>APP-MULTI</name></application>
</application-set>
</applications>
<security>
<zones><security-zone><name>trust</name>
<interfaces><name>ge-0/0/0.0</name></interfaces>
</security-zone></zones>
<policies><policy><from-zone-name>trust</from-zone-name><to-zone-name>untrust</to-zone-name>
<policy><name>p1</name><match><source-address>any</source-address><destination-address>any</destination-address><application>APPSET1</application></match><then><permit/></then></policy>
</policy></policies>
</security>
<interfaces></interfaces>
</configuration>
</rpc-reply>
`
	m, err := Parse([]byte(xmlDoc), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	simple, ok := m.Applications["APP-CUSTOM"]
	if !ok {
		t.Fatal("APP-CUSTOM not found in m.Applications")
	}
	if len(simple.Protocol) != 1 || simple.Protocol[0] != "tcp" {
		t.Errorf("APP-CUSTOM.Protocol = %v, want [tcp]", simple.Protocol)
	}
	if len(simple.DestinationPort) != 1 || simple.DestinationPort[0] != "8443" {
		t.Errorf("APP-CUSTOM.DestinationPort = %v, want [8443]", simple.DestinationPort)
	}

	multi, ok := m.Applications["APP-MULTI"]
	if !ok {
		t.Fatal("APP-MULTI not found in m.Applications")
	}
	if len(multi.Terms) != 2 {
		t.Fatalf("APP-MULTI.Terms has %d entries, want 2", len(multi.Terms))
	}
	if multi.Terms[0].DestinationPort[0] != "80" || multi.Terms[1].DestinationPort[0] != "443" {
		t.Errorf("APP-MULTI.Terms = %+v", multi.Terms)
	}

	set, ok := m.ApplicationSets["APPSET1"]
	if !ok {
		t.Fatal("APPSET1 not found in m.ApplicationSets")
	}
	if len(set.Applications) != 2 {
		t.Errorf("APPSET1.Applications = %v, want 2 members", set.Applications)
	}

	if len(m.Policies) != 1 || m.Policies[0].Application[0] != "APPSET1" {
		t.Errorf("policy application = %v, want [APPSET1]", m.Policies[0].Application)
	}
}

// TestParseApplications_AbsentIsEmptyNotNil checks a configuration with no
// applications{} block at all still gets initialized, non-nil maps (JSON
// marshaling should produce "{}" , not "null", for application_objects/
// application_sets — see internal/inventory.buildApplicationObjects, which
// ranges over these maps and must not panic on nil either way, but a
// non-nil empty map keeps the pivot JSON's shape predictable).
func TestParseApplications_AbsentIsEmptyNotNil(t *testing.T) {
	// looksLikeSetFormat requires at least 3 "set " lines when there are
	// no non-"set" lines to compare against (see set.go's min3 rule) —
	// two lines alone would misdetect as curly format and fail parsing
	// before even reaching the applications-emptiness check this test is
	// actually about, so a third, otherwise-irrelevant line is required.
	text := "set system services ssh root-login deny\n" +
		"set system services ssh protocol-version v2\n" +
		"set security zones security-zone trust interfaces ge-0/0/0.0\n"
	m, err := Parse([]byte(text), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Applications == nil {
		t.Error("m.Applications is nil, want an empty (non-nil) map")
	}
	if m.ApplicationSets == nil {
		t.Error("m.ApplicationSets is nil, want an empty (non-nil) map")
	}
}
