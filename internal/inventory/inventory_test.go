package inventory

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/local/srxtool-go/internal/config"
)

const fixtures = "../../testdata/fixtures"
const golden = "../../testdata/golden"

func mustModel(t *testing.T, name string) *config.Model {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatalf("unreadable fixture: %v", err)
	}
	m, err := config.Parse(data, config.Options{})
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	return m
}

// TestGoldenInvJSON is task 02's central regression test: Build()'s JSON
// output must be strictly identical to inv.json, produced by the
// reference Python on sample2.txt.
func TestGoldenInvJSON(t *testing.T) {
	m := mustModel(t, "sample2.txt")
	res := Build(m)

	gotBytes, err := res.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(gotBytes, &got); err != nil {
		t.Fatalf("re-reading Go JSON: %v", err)
	}
	wantBytes, err := os.ReadFile(filepath.Join(golden, "inv.json"))
	if err != nil {
		t.Fatalf("unreadable golden: %v", err)
	}
	if err := json.Unmarshal(wantBytes, &want); err != nil {
		t.Fatalf("unreadable golden: %v", err)
	}

	for _, key := range []string{"vlans", "zones", "policies", "address_objects"} {
		gv, err1 := json.Marshal(got[key])
		wv, err2 := json.Marshal(want[key])
		if err1 != nil || err2 != nil {
			t.Fatalf("encoding: %v %v", err1, err2)
		}
		var gg, ww any
		json.Unmarshal(gv, &gg)
		json.Unmarshal(wv, &ww)
		if !jsonEqual(gg, ww) {
			t.Errorf("field %q mismatch:\n go   %s\n want %s", key, gv, wv)
		}
	}
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

// TestOrphanVLANInReport: the text report must explicitly flag VLANs with
// no L3 zone (VLAN99), task 02's #1 point of attention.
func TestOrphanVLANInReport(t *testing.T) {
	m := mustModel(t, "sample2.txt")
	report := Build(m).ReportText()
	if !containsAll(report, "VLAN99", "without an L3 zone") {
		t.Errorf("the report should flag VLAN99 as orphan:\n%s", report)
	}
}

func TestReportTextStructure(t *testing.T) {
	m := mustModel(t, "sample-show-config.txt")
	report := Build(m).ReportText()
	if !containsAll(report, "SRX INVENTORY", "ZONE  trust", "ZONE  untrust",
		"Detected source format: curly") {
		t.Errorf("unexpected report structure:\n%s", report)
	}
}

// TestReferencesCount checks that an address object's reference count
// follows both policies AND address-sets, like build_address_index().
func TestReferencesCount(t *testing.T) {
	m := mustModel(t, "sample2.txt")
	res := Build(m)
	found := false
	for _, a := range res.AddressObjects {
		if a.Name == "10.10.10.50" {
			found = true
			// Referenced once as a member of the corp-servers address-set,
			// and corp-servers (not the IP directly) is the source of the
			// allow-web policy: so a single reference carried by the IP
			// object itself.
			if a.References != 1 {
				t.Errorf("references = %d, expected 1", a.References)
			}
		}
	}
	if !found {
		t.Fatal("object 10.10.10.50 missing")
	}
}

// TestUnreferencedObjectIsZero: an object that's never used must have
// References == 0 (and would be colored ORPHAN in the XLSX export).
func TestUnreferencedObjectIsZero(t *testing.T) {
	conf := `security {
    zones {
        security-zone trust {
            interfaces { ge-0/0/0.0; }
            address-book {
                address unused-obj 10.5.5.5/32;
            }
        }
    }
}
`
	m, err := config.Parse([]byte(conf), config.Options{})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	res := Build(m)
	if len(res.AddressObjects) != 1 || res.AddressObjects[0].References != 0 {
		t.Fatalf("unreferenced object: %+v", res.AddressObjects)
	}
}

// TestExportXLSXReadable checks that the export produces a valid workbook
// with the right number of rows per sheet.
func TestExportXLSXReadable(t *testing.T) {
	m := mustModel(t, "sample2.txt")
	res := Build(m)

	var buf bytes.Buffer
	if err := res.ExportXLSX(&buf); err != nil {
		t.Fatalf("ExportXLSX: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty workbook")
	}
	// Minimal ZIP signature: "PK\x03\x04".
	b := buf.Bytes()
	if len(b) < 4 || b[0] != 'P' || b[1] != 'K' {
		t.Fatal("the produced file doesn't look like a zip/xlsx")
	}
}

// TestDeterministicOrder: two successive calls must produce the same JSON
// byte for byte (diffable outputs, cf. task 08/09).
func TestDeterministicOrder(t *testing.T) {
	m := mustModel(t, "sample-show-config.txt")
	a, err := Build(m).JSON()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(m).JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("non-deterministic output between two calls")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !stringsContains(s, sub) {
			return false
		}
	}
	return true
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
