package rules

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"

	"github.com/local/srxtool-go/internal/inventory"
	"github.com/local/srxtool-go/internal/junosname"
)

// WriteSuggestCSV: port of cmd_rename()'s --suggest phase
// (srxtool.py L1384-1397). Same columns, same order — directly comparable
// to `rename-plan.csv`.
func WriteSuggestCSV(candidates []Candidate, useDNS bool, w io.Writer) error {
	cw := csv.NewWriter(w)
	// Python's csv.writer uses \r\n by default ("excel" dialect); the CSV
	// is meant to be reopened/edited in a spreadsheet, so we match that
	// output format rather than let Go default to \n.
	cw.UseCRLF = true
	if err := cw.Write([]string{"book", "book_type", "old_name", "prefix", "zones",
		"refs", "apps", "suggested_new_name", "new_name"}); err != nil {
		return err
	}
	for _, d := range candidates {
		sug := SuggestName(d.Prefix, d.ZoneHint, d.Usages, useDNS)
		if err := cw.Write([]string{
			d.Book, d.BookType, d.OldName, d.Prefix, joinSemi(d.Zones),
			fmt.Sprintf("%d", d.Refs), joinSemi(d.Apps), sug, "",
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func joinSemi(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ";"
		}
		out += s
	}
	return out
}

// RenameMapEntry: a valid row of the --from-map CSV, keyed by (book, old_name).
type RenameMapKey struct{ Book, OldName string }

// ReadRenameMapCSV: port of the --from-map CSV reading logic
// (srxtool.py L1399-1413). Rows whose new_name is invalid are rejected
// (message kept) rather than aborting the whole file — identical Python
// behavior: errors are collected, processing continues.
func ReadRenameMapCSV(r io.Reader) (mapping map[RenameMapKey]string, rejected []string, err error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	records, err := cr.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return map[RenameMapKey]string{}, nil, nil
	}
	header := records[0]
	idx := map[string]int{}
	for i, h := range header {
		idx[h] = i
	}
	get := func(row []string, col string) string {
		if i, ok := idx[col]; ok && i < len(row) {
			return row[i]
		}
		return ""
	}

	mapping = map[RenameMapKey]string{}
	for lineno, row := range records[1:] {
		newName := trimSpace(get(row, "new_name"))
		if newName == "" {
			continue
		}
		valid, verr := junosname.ValidateNewName(newName, fmt.Sprintf(" (CSV line %d)", lineno+2))
		if verr != nil {
			rejected = append(rejected, verr.Error())
			continue
		}
		mapping[RenameMapKey{Book: get(row, "book"), OldName: get(row, "old_name")}] = valid
	}
	return mapping, rejected, nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}
func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }

// addrCreateLine / addrDeleteLine: ports of addr_create_line() /
// addr_delete_line() (srxtool.py L948-960).
func addrCreateLine(bookType, book, name, prefix string) (string, error) {
	bq, err := junosname.Quote(book)
	if err != nil {
		return "", err
	}
	nq, err := junosname.Quote(name)
	if err != nil {
		return "", err
	}
	pq, err := junosname.Quote(prefix)
	if err != nil {
		return "", err
	}
	if bookType == "global" {
		return fmt.Sprintf("set security address-book %s address %s %s", bq, nq, pq), nil
	}
	return fmt.Sprintf("set security zones security-zone %s address-book address %s %s", bq, nq, pq), nil
}

func addrDeleteLine(bookType, book, name string) (string, error) {
	bq, err := junosname.Quote(book)
	if err != nil {
		return "", err
	}
	nq, err := junosname.Quote(name)
	if err != nil {
		return "", err
	}
	if bookType == "global" {
		return fmt.Sprintf("delete security address-book %s address %s", bq, nq), nil
	}
	return fmt.Sprintf("delete security zones security-zone %s address-book address %s", bq, nq), nil
}

// setRefLines: port of set_ref_lines() (srxtool.py L963-983).
func setRefLines(u inventory.Usage, oldName, newName string) ([]string, error) {
	switch u.Kind {
	case "policy-src", "policy-dst":
		field := "source-address"
		if u.Kind == "policy-dst" {
			field = "destination-address"
		}
		fzq, err := junosname.Quote(u.FromZone)
		if err != nil {
			return nil, err
		}
		tzq, err := junosname.Quote(u.ToZone)
		if err != nil {
			return nil, err
		}
		pq, err := junosname.Quote(u.Policy)
		if err != nil {
			return nil, err
		}
		newq, err := junosname.Quote(newName)
		if err != nil {
			return nil, err
		}
		oldq, err := junosname.Quote(oldName)
		if err != nil {
			return nil, err
		}
		base := fmt.Sprintf("security policies from-zone %s to-zone %s policy %s match %s", fzq, tzq, pq, field)
		return []string{"set " + base + " " + newq, "delete " + base + " " + oldq}, nil
	case "address-set":
		var base string
		bq, err := junosname.Quote(u.Book)
		if err != nil {
			return nil, err
		}
		sq, err := junosname.Quote(u.Set)
		if err != nil {
			return nil, err
		}
		if u.BookType == "global" {
			base = fmt.Sprintf("security address-book %s address-set %s address", bq, sq)
		} else {
			base = fmt.Sprintf("security zones security-zone %s address-book address-set %s address", bq, sq)
		}
		newq, err := junosname.Quote(newName)
		if err != nil {
			return nil, err
		}
		oldq, err := junosname.Quote(oldName)
		if err != nil {
			return nil, err
		}
		return []string{"set " + base + " " + newq, "delete " + base + " " + oldq}, nil
	default:
		return nil, nil
	}
}

// ApplyRenameMap: port of cmd_rename()'s --from-map phase
// (srxtool.py L1425-1452). Always a 3-step workflow per object: create the
// new one -> repoint EVERY reference -> delete the old one. Never an
// in-place rename. An exact (inverse) rollback is always produced.
//
// Mapping candidates not found in `candidates` are ignored with a comment
// in the output (as in Python), not an error: the CSV may have been edited
// after a `--suggest` run against a different conf.
func ApplyRenameMap(candidates []Candidate, mapping map[RenameMapKey]string) (setCmds, rollback []string, err error) {
	byKey := make(map[RenameMapKey]Candidate, len(candidates))
	for _, d := range candidates {
		byKey[RenameMapKey{Book: d.Book, OldName: d.OldName}] = d
	}

	// Deterministic order: Go maps have no stable order, so we sort the
	// keys (an accepted divergence from the Python dict's iteration order,
	// which follows the CSV read order — no functional consequence since
	// each object is processed independently).
	keys := make([]RenameMapKey, 0, len(mapping))
	for k := range mapping {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Book != keys[j].Book {
			return keys[i].Book < keys[j].Book
		}
		return keys[i].OldName < keys[j].OldName
	})

	setCmds = append(setCmds, "# --- rename IP-named objects -> service name ---",
		"# Load under 'configure private' then 'commit check'.")
	rollback = append(rollback, "# --- rename rollback ---")

	for _, key := range keys {
		newName := mapping[key]
		d, ok := byKey[key]
		if !ok {
			setCmds = append(setCmds, fmt.Sprintf("# [ignored] %s/%s not found in the conf", key.Book, key.OldName))
			continue
		}

		setCmds = append(setCmds, "",
			fmt.Sprintf("# %s  ->  %s   (%s, %d reference(s))", d.OldName, newName, d.Prefix, d.Refs))
		create, err := addrCreateLine(d.BookType, d.Book, newName, d.Prefix)
		if err != nil {
			return nil, nil, err
		}
		setCmds = append(setCmds, create)
		for _, u := range d.Usages {
			lines, err := setRefLines(u, d.OldName, newName)
			if err != nil {
				return nil, nil, err
			}
			setCmds = append(setCmds, lines...)
		}
		del, err := addrDeleteLine(d.BookType, d.Book, d.OldName)
		if err != nil {
			return nil, nil, err
		}
		setCmds = append(setCmds, del)

		rollback = append(rollback, fmt.Sprintf("# %s -> %s", newName, d.OldName))
		rbCreate, err := addrCreateLine(d.BookType, d.Book, d.OldName, d.Prefix)
		if err != nil {
			return nil, nil, err
		}
		rollback = append(rollback, rbCreate)
		for _, u := range d.Usages {
			lines, err := setRefLines(u, newName, d.OldName)
			if err != nil {
				return nil, nil, err
			}
			rollback = append(rollback, lines...)
		}
		rbDel, err := addrDeleteLine(d.BookType, d.Book, newName)
		if err != nil {
			return nil, nil, err
		}
		rollback = append(rollback, rbDel)
	}
	return setCmds, rollback, nil
}
