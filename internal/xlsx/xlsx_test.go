package xlsx

import (
	"archive/zip"
	"bytes"
	"testing"
)

// TestWriteValidZip checks that the produced workbook is a readable zip
// with the mandatory parts of a minimal OOXML file.
func TestWriteValidZip(t *testing.T) {
	w := New()
	w.AddSheet("Sheet1", []string{"A", "B"},
		[][]Cell{{Text("x"), Num(1)}, {Text("y").Styled(StyleCritical), Num(2)}},
		20, 10)

	var buf bytes.Buffer
	if err := w.Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("invalid zip: %v", err)
	}
	want := []string{
		"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
		"xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/worksheets/sheet1.xml",
	}
	got := map[string]bool{}
	for _, f := range zr.File {
		got[f.Name] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("part missing from zip: %s", w)
		}
	}
}

func TestWriteEmptyWorkbookRejected(t *testing.T) {
	if err := New().Write(&bytes.Buffer{}); err == nil {
		t.Fatal("a workbook with no sheet should be rejected")
	}
}

// TestStyleIndexOrder locks in _FILL_ORDER's order: changing it would
// break the correspondence between a cell's `s=` attribute and its
// actual fill.
func TestStyleIndexOrder(t *testing.T) {
	cases := map[Style]int{
		StyleNone: 0, StyleHeader: 1, StyleCritical: 2, StyleHigh: 3,
		StyleMedium: 4, StyleLow: 5, StyleInfo: 6, StyleOrphan: 7, StyleOK: 8,
	}
	for s, want := range cases {
		if got := styleIndex(s); got != want {
			t.Errorf("styleIndex(%s) = %d, expected %d", s, got, want)
		}
	}
}

func TestColLetter(t *testing.T) {
	cases := map[int]string{0: "A", 1: "B", 25: "Z", 26: "AA", 27: "AB", 51: "AZ", 52: "BA"}
	for idx, want := range cases {
		if got := colLetter(idx); got != want {
			t.Errorf("colLetter(%d) = %q, expected %q", idx, got, want)
		}
	}
}

func TestEscapeXML(t *testing.T) {
	if got := escape(`a & b < c > d`); got != "a &amp; b &lt; c &gt; d" {
		t.Errorf("escape: %q", got)
	}
}

// TestSheetNameTruncated: Excel limits a sheet name to 31 characters.
func TestSheetNameTruncated(t *testing.T) {
	w := New()
	long := "a-sheet-name-way-too-long-for-excel-to-handle"
	w.AddSheet(long, []string{"A"}, [][]Cell{{Text("v")}})
	xml := w.workbookXML()
	if bytesContains(xml, long) {
		t.Error("the full sheet name should not appear (31-character limit)")
	}
	if !bytesContains(xml, long[:31]) {
		t.Error("the name truncated to 31 characters should appear")
	}
}

func bytesContains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
