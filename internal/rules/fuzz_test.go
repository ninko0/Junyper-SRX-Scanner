package rules

import (
	"bytes"
	"testing"
)

// FuzzParseHitcount: ParseHitcount ingests a device export — untrusted
// input just like the conf itself (cf task 01). Only property checked: no
// panic, regardless of input.
func FuzzParseHitcount(f *testing.F) {
	f.Add([]byte(hitcountXML))
	f.Add([]byte("Policy: x, action:permit\nFrom zone: a, To zone: b\nNumber of policy hit: 0\n"))
	f.Add([]byte("<policy-hit-count><from-zone>a</from-zone></policy-hit-count>"))
	f.Add([]byte(""))
	f.Add([]byte("<<<<<<<<<"))
	f.Add([]byte("Policy: , action:\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseHitcount(bytes.NewReader(data))
	})
}

// FuzzReadRenameMapCSV: the --from-map CSV is filled in by hand by an
// operator then re-uploaded — untrusted input that ends up in generated
// set/delete commands (cf task 04, name validation).
func FuzzReadRenameMapCSV(f *testing.F) {
	f.Add([]byte("book,book_type,old_name,prefix,zones,refs,apps,suggested_new_name,new_name\ntrust,zone,10.10.10.50,10.10.10.50/32,trust,1,,trust-host-50,web-01\n"))
	f.Add([]byte(""))
	f.Add([]byte("not,even,a,valid,csv,header\n\"unterminated"))
	f.Add([]byte("new_name\nbad;name\n"))
	f.Add([]byte("new_name\n" + string(make([]byte, 200)) + "\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ReadRenameMapCSV(bytes.NewReader(data))
	})
}
