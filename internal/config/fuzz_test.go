package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse verifies a single property, but the most important one for a
// component that ingests untrusted data: no input, however malformed,
// should ever cause a panic. The result isn't checked — an absurd conf
// is entitled to produce an absurd model or an error, not a process
// crash (see task 08).
//
// Starting corpus: the real fixtures, so the fuzzer starts from valid
// structures and mutates them rather than exploring pure noise.
func FuzzParse(f *testing.F) {
	entries, err := os.ReadDir(fixtures)
	if err != nil {
		f.Fatalf("unreadable corpus: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(fixtures, e.Name()))
		if err != nil {
			continue
		}
		f.Add(b)
	}
	// A few explicit adversarial seeds.
	f.Add([]byte("{{{{{{{{{{{{{{{{{{{{"))
	f.Add([]byte("}}}}}}}}}}"))
	f.Add([]byte("set "))
	f.Add([]byte("set security policies from-zone to-zone"))
	f.Add([]byte(`a "unclosed { ;`))
	f.Add([]byte("<configuration><vlans><vlan><name>"))
	f.Add([]byte("address-book { address [ ; } }"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// MaxBytes bounds the fuzzer without changing the code paths tested.
		m, err := Parse(data, Options{MaxBytes: 1 << 20, AllowEmpty: true})
		if err != nil {
			return
		}
		if m == nil {
			t.Fatal("nil model with no error")
		}
		// The model's invariants must hold regardless of the input: no
		// nil slice where the JSON must produce [].
		if m.Policies == nil || m.Warnings == nil || m.Screens == nil {
			t.Fatal("uninitialized model slices")
		}
		for name, v := range m.VLANs {
			if v.Members == nil || v.L3Addresses == nil {
				t.Fatalf("VLAN %q: uninitialized slices", name)
			}
		}
		for name, z := range m.Zones {
			if z.Interfaces == nil || z.VLANs == nil ||
				z.PoliciesFrom == nil || z.PoliciesTo == nil {
				t.Fatalf("zone %q: uninitialized slices", name)
			}
		}
		// Navigating the raw subtrees must stay safe even when they're
		// absent (this is the path taken by the audit).
		_ = m.System.Sub("services").Sub("ssh").Vals("root-login")
		_ = m.SNMP.Names()
		_ = m.Security.Sub("zones").Has("security-zone")
	})
}
