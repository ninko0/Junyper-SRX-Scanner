package config

import (
	"reflect"
	"testing"
)

func TestSplitTokens(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"system-services ping", []string{"system-services", "ping"}},
		// Brackets are REMOVED (not expanded): parity with _split_tokens.
		{"system-services [ ping ssh ]", []string{"system-services", "ping", "ssh"}},
		// Opening bracket with no closing one: everything after it is kept.
		{"members [ VLAN10 VLAN20", []string{"members", "VLAN10", "VLAN20"}},
		// Only the first pair is processed, like in Python.
		{"a [ b ] c [ d ]", []string{"a", "b", "c", "[", "d", "]"}},
		{`message "Access restricted"`, []string{"message", "Access restricted"}},
		{`name 'a b'`, []string{"name", "a b"}},
		// Unclosed quote: falls back to a plain split (no error).
		{`message "not closed`, []string{"message", `"not`, "closed"}},
		{"", nil},
	}
	for _, c := range cases {
		if got := splitTokens(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitTokens(%q) = %#v, expected %#v", c.in, got, c.want)
		}
	}
}

// TestCValuesFourForms checks the unification of Junos's four spellings
// of a list, which was the historical bug on the Python side (only the
// block form was read: a zone declaring 'system-services [ ping ssh ]'
// looked like it exposed no service at all).
func TestCValuesFourForms(t *testing.T) {
	cases := []struct {
		name string
		conf string
	}{
		{"block", "host-inbound-traffic {\nsystem-services {\nping;\nssh;\n}\n}"},
		{"inline", "host-inbound-traffic {\nsystem-services [ ping ssh ];\n}"},
		{"repeated", "host-inbound-traffic {\nsystem-services ping;\nsystem-services ssh;\n}"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, _ := parseCurlyText(c.conf)
			hit := root.CChild("host-inbound-traffic")
			got := hit.CValues("system-services")
			if !reflect.DeepEqual(got, []string{"ping", "ssh"}) {
				t.Fatalf("CValues = %#v, expected [ping ssh]", got)
			}
		})
	}
}

func TestCLeafForms(t *testing.T) {
	root, _ := parseCurlyText("a {\nb value;\nc {\nalone;\n}\nd name {\ne;\n}\nf;\n}")
	a := root.CChild("a")
	if v, ok := a.CLeaf("b"); !ok || v != "value" {
		t.Errorf("simple key: %q %v", v, ok)
	}
	if v, ok := a.CLeaf("c"); !ok || v != "alone" {
		t.Errorf("block-value form: %q %v", v, ok)
	}
	if v, ok := a.CLeaf("d"); !ok || v != "name" {
		t.Errorf("valued-header form: %q %v", v, ok)
	}
	// Present with no value: equivalent of Python's True.
	if v, ok := a.CLeaf("f"); !ok || v != "" {
		t.Errorf("bare presence: %q %v", v, ok)
	}
	if _, ok := a.CLeaf("nonexistent"); ok {
		t.Error("absent key reported present")
	}
}

func TestNilSafety(t *testing.T) {
	var n *Node
	if n.CChild("x") != nil || n.CValues("x") != nil || n.CHas("x") || n.CBareNames() != nil {
		t.Error("the helpers must tolerate a nil node (equivalent of Python's None)")
	}
	if _, ok := n.CLeaf("x"); ok {
		t.Error("CLeaf on nil must report absent")
	}
	if Exists(n) {
		t.Error("Exists must be false for a nil *Node carried by an interface")
	}
}

func TestIsPrivatePythonSemantics(t *testing.T) {
	cases := map[string]bool{
		"10.10.10.1/24":  true,
		"192.168.1.1":    true,
		"203.0.113.1/30": true, // TEST-NET-3: private for Python
		"198.51.100.7":   true, // TEST-NET-2
		"100.64.0.1":     true, // CGNAT
		"8.8.8.8":        false,
		"1.1.1.1/32":     false,
		"192.0.0.9":      false, // PCP exception
		"fe80::1":        true,
		"2001:db8::1":    true, // 2001:db8::/32 is one of Python's private networks
		"not-an-address": true, // ValueError -> True
	}
	for ip, want := range cases {
		if got := isPrivate(ip); got != want {
			t.Errorf("isPrivate(%q) = %v, expected %v", ip, got, want)
		}
	}
}
