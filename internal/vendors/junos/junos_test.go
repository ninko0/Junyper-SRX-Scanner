package junos

import (
	"testing"

	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/vendors"
)

const minimalConf = `security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
    policies {
        from-zone trust to-zone trust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
`

// TestJunosRegistersItself: importing the package (already done by
// internal/api upstream of this test binary via internal/vendors/junos)
// must be enough for "junos" to show up in the registry — no manual
// registration required elsewhere.
func TestJunosRegistersItself(t *testing.T) {
	found := false
	for _, v := range vendors.ConfigVendors() {
		if v == Name {
			found = true
		}
	}
	if !found {
		t.Fatalf("vendor %q missing from vendors.ConfigVendors(): %v", Name, vendors.ConfigVendors())
	}
}

// TestParseConfigDelegatesToConfigPackage: the adapter must not change
// internal/config.Parse's behavior — same model, same errors.
func TestParseConfigDelegatesToConfigPackage(t *testing.T) {
	want, err := config.Parse([]byte(minimalConf), config.Options{})
	if err != nil {
		t.Fatalf("config.Parse (reference): %v", err)
	}

	p := parser{}
	got, err := p.ParseConfig([]byte(minimalConf), config.Options{})
	if err != nil {
		t.Fatalf("parser.ParseConfig: %v", err)
	}
	if len(got.Zones) != len(want.Zones) || len(got.Policies) != len(want.Policies) {
		t.Errorf("model mismatch: got=%+v want=%+v", got, want)
	}
}

func TestParseConfigViaRegistryMatchesDirectParse(t *testing.T) {
	want, err := config.Parse([]byte(minimalConf), config.Options{})
	if err != nil {
		t.Fatalf("config.Parse (reference): %v", err)
	}

	got, v, err := vendors.DetectConfig([]byte(minimalConf), config.Options{})
	if err != nil {
		t.Fatalf("vendors.DetectConfig: %v", err)
	}
	if v != Name {
		t.Errorf("vendor = %q, expected %q", v, Name)
	}
	if len(got.Zones) != len(want.Zones) {
		t.Errorf("zone mismatch: got=%d want=%d", len(got.Zones), len(want.Zones))
	}
}

func TestParseCountersDelegatesToRulesPackage(t *testing.T) {
	xml := `<security-policies-hit-count-information>
<policy-hit-count>
<from-zone>trust</from-zone>
<to-zone>trust</to-zone>
<policy-name>allow-all</policy-name>
<count>0</count>
<policy-action>permit</policy-action>
</policy-hit-count>
</security-policies-hit-count-information>`

	p := parser{}
	hits, err := p.ParseCounters([]byte(xml))
	if err != nil {
		t.Fatalf("ParseCounters: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(hits))
	}

	cp, ok := vendors.CounterParserFor(Name)
	if !ok {
		t.Fatal("junos counter parser not found in the registry")
	}
	hits2, err := cp.ParseCounters([]byte(xml))
	if err != nil {
		t.Fatalf("CounterParserFor(...).ParseCounters: %v", err)
	}
	if len(hits2) != len(hits) {
		t.Errorf("mismatched results between direct call and registry: %d vs %d", len(hits2), len(hits))
	}
}
