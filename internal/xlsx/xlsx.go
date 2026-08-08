// Package xlsx is a minimal OOXML workbook generator (zip + raw XML), a
// port of srxaudit.py / srxtool.py's homegrown generator — or rather of
// its TWO copies, identical line for line across both Python files
// (srxaudit.py L633-654 / srxtool.py L1009-1030). This duplication is
// exactly what the rewrite is meant to remove: here, a single writer,
// used by `inventory` (task 02) and `audit` (task 03).
//
// Task 02's decision: homegrown implementation rather than `excelize`.
//
//   - zero third-party dependency, so zero supply-chain surface to audit
//     and a final image that stays tiny (consistent with distroless,
//     task 07)
//   - output byte-comparable to Python's, which makes parity verifiable
//     by test (see TestXLSXParity)
//   - it means owning OOXML generation by hand
//
// The produced format is deliberately minimal (inlineStr, no
// sharedStrings, no formulas): it's a read-only export, not a live
// spreadsheet.
package xlsx

import (
	"archive/zip"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Style designates a fill from the palette. The palette matches Python's
// exactly: severity colors must match the web UI's badges (task 06).
type Style string

const (
	StyleNone     Style = ""
	StyleHeader   Style = "header"
	StyleCritical Style = "CRITICAL"
	StyleHigh     Style = "HIGH"
	StyleMedium   Style = "MEDIUM"
	StyleLow      Style = "LOW"
	StyleInfo     Style = "INFO"
	StyleOrphan   Style = "ORPHAN"
	StyleOK       Style = "OK"
)

// Fills: port of the FILLS dict. ARGB colors.
var Fills = map[Style]string{
	StyleHeader:   "FF2F3B52",
	StyleCritical: "FFC00000",
	StyleHigh:     "FFFF6B6B",
	StyleMedium:   "FFFFD966",
	StyleLow:      "FFC6E0B4",
	StyleInfo:     "FFD9D9D9",
	StyleOrphan:   "FFFFC7CE",
	StyleOK:       "FFE2EFDA",
}

// fillOrder: port of _FILL_ORDER. The order determines the style IDs in
// styles.xml, it must not change.
var fillOrder = []Style{
	StyleHeader, StyleCritical, StyleHigh, StyleMedium,
	StyleLow, StyleInfo, StyleOrphan, StyleOK,
}

// Cell carries a value and an optional style. Value accepts string, int,
// or float64; numbers are written as such (numeric cells), everything
// else is written as an inline string.
type Cell struct {
	Value any
	Style Style
}

// Text builds a text cell.
func Text(v string) Cell { return Cell{Value: v} }

// Num builds a numeric cell.
func Num(v int) Cell { return Cell{Value: v} }

// Styled applies a style to a cell.
func (c Cell) Styled(s Style) Cell { c.Style = s; return c }

// Sheet is a worksheet tab.
type Sheet struct {
	Name      string
	Headers   []string
	Rows      [][]Cell
	ColWidths []float64
}

// Writer accumulates sheets then serializes the workbook.
type Writer struct{ sheets []Sheet }

// New creates an empty writer.
func New() *Writer { return &Writer{} }

// AddSheet adds a sheet. colWidths is optional.
func (w *Writer) AddSheet(name string, headers []string, rows [][]Cell, colWidths ...float64) {
	w.sheets = append(w.sheets, Sheet{
		Name: name, Headers: headers, Rows: rows, ColWidths: colWidths,
	})
}

// Write serializes the workbook. No temporary file is created: the HTTP
// layer (task 05) can stream directly to the response.
func (w *Writer) Write(out io.Writer) error {
	if len(w.sheets) == 0 {
		return fmt.Errorf("workbook with no sheet")
	}
	z := zip.NewWriter(out)
	parts := []struct {
		name string
		body string
	}{
		{"[Content_Types].xml", w.contentTypes()},
		{"_rels/.rels", rootRels},
		{"xl/workbook.xml", w.workbookXML()},
		{"xl/_rels/workbook.xml.rels", w.workbookRels()},
		{"xl/styles.xml", stylesXML()},
	}
	for i, s := range w.sheets {
		parts = append(parts, struct {
			name string
			body string
		}{fmt.Sprintf("xl/worksheets/sheet%d.xml", i+1), sheetXML(s)})
	}
	for _, p := range parts {
		f, err := z.Create(p.name)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(f, p.body); err != nil {
			return err
		}
	}
	return z.Close()
}

const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`

func (w *Writer) contentTypes() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`)
	b.WriteString(`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`)
	b.WriteString(`<Default Extension="xml" ContentType="application/xml"/>`)
	b.WriteString(`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`)
	b.WriteString(`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`)
	for i := range w.sheets {
		fmt.Fprintf(&b, `<Override PartName="/xl/worksheets/sheet%d.xml" `+
			`ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, i+1)
	}
	b.WriteString(`</Types>`)
	return b.String()
}

func (w *Writer) workbookXML() string {
	var sheets strings.Builder
	for i, s := range w.sheets {
		fmt.Fprintf(&sheets, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`,
			escape(truncRunes(s.Name, 31)), i+1, i+1)
	}
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>` + sheets.String() + `</sheets>
</workbook>`
}

func (w *Writer) workbookRels() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for i := range w.sheets {
		fmt.Fprintf(&b, `<Relationship Id="rId%d" `+
			`Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" `+
			`Target="worksheets/sheet%d.xml"/>`, i+1, i+1)
	}
	fmt.Fprintf(&b, `<Relationship Id="rId%d" `+
		`Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" `+
		`Target="styles.xml"/>`, len(w.sheets)+1)
	b.WriteString(`</Relationships>`)
	return b.String()
}

// stylesXML: port of _styles_xml().
func stylesXML() string {
	fills := []string{
		`<fill><patternFill patternType="none"/></fill>`,
		`<fill><patternFill patternType="gray125"/></fill>`,
	}
	for _, name := range fillOrder {
		fills = append(fills, fmt.Sprintf(
			`<fill><patternFill patternType="solid">`+
				`<fgColor rgb="%s"/><bgColor indexed="64"/></patternFill></fill>`, Fills[name]))
	}
	xfs := []string{
		`<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>`,
		`<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>`,
	}
	for i := range fillOrder[1:] {
		xfs = append(xfs, fmt.Sprintf(
			`<xf numFmtId="0" fontId="0" fillId="%d" borderId="0" xfId="0" applyFill="1"/>`, i+3))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2">
<font><sz val="10"/><name val="Calibri"/></font>
<font><sz val="10"/><name val="Calibri"/><b/><color rgb="FFFFFFFF"/></font>
</fonts>
<fills count="%d">%s</fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="%d">%s</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>`, len(fills), strings.Join(fills, ""), len(xfs), strings.Join(xfs, ""))
}

// styleIndex: port of style_index().
func styleIndex(s Style) int {
	switch s {
	case StyleNone:
		return 0
	case StyleHeader:
		return 1
	}
	for i, name := range fillOrder[1:] {
		if name == s {
			return 2 + i
		}
	}
	return 0
}

// sheetXML: port of _sheet_xml().
func sheetXML(s Sheet) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	if len(s.ColWidths) > 0 {
		b.WriteString(`<cols>`)
		for i, wd := range s.ColWidths {
			fmt.Fprintf(&b, `<col min="%d" max="%d" width="%s" customWidth="1"/>`,
				i+1, i+1, strconv.FormatFloat(wd, 'g', -1, 64))
		}
		b.WriteString(`</cols>`)
	}
	b.WriteString(`<sheetData>`)

	r := 1
	fmt.Fprintf(&b, `<row r="%d">`, r)
	for ci, h := range s.Headers {
		b.WriteString(cellXML(ci, r, Cell{Value: h, Style: StyleHeader}))
	}
	b.WriteString(`</row>`)
	for _, row := range s.Rows {
		r++
		fmt.Fprintf(&b, `<row r="%d">`, r)
		for ci, c := range row {
			b.WriteString(cellXML(ci, r, c))
		}
		b.WriteString(`</row>`)
	}
	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

func cellXML(ci, ri int, c Cell) string {
	ref := colLetter(ci) + strconv.Itoa(ri)
	sAttr := ""
	if idx := styleIndex(c.Style); idx != 0 {
		sAttr = fmt.Sprintf(` s="%d"`, idx)
	}
	switch v := c.Value.(type) {
	case nil:
		return fmt.Sprintf(`<c r="%s"%s t="inlineStr"><is><t xml:space="preserve"></t></is></c>`, ref, sAttr)
	case int:
		return fmt.Sprintf(`<c r="%s"%s><v>%d</v></c>`, ref, sAttr, v)
	case float64:
		return fmt.Sprintf(`<c r="%s"%s><v>%s</v></c>`, ref, sAttr,
			strconv.FormatFloat(v, 'g', -1, 64))
	case string:
		return fmt.Sprintf(`<c r="%s"%s t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`,
			ref, sAttr, escape(v))
	default:
		return fmt.Sprintf(`<c r="%s"%s t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`,
			ref, sAttr, escape(fmt.Sprintf("%v", v)))
	}
}

// colLetter: port of _col_letter().
func colLetter(idx int) string {
	idx++
	s := ""
	for idx > 0 {
		r := (idx - 1) % 26
		idx = (idx - 1) / 26
		s = string(rune('A'+r)) + s
	}
	return s
}

// escape reproduces xml.sax.saxutils.escape(): &, < and > only, not
// quotes (values are never placed inside an attribute).
func escape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return strings.ReplaceAll(s, ">", "&gt;")
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
