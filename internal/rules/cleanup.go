package rules

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/local/srxtool-go/internal/junosname"
)

// PolicyKey identifies a policy for cross-referencing with the hit-count.
type PolicyKey struct{ FromZone, ToZone, Name string }

// HitInfo: port of the {"count": int, "action": str} dict.
type HitInfo struct {
	Count  int
	Action string // may be empty (absent from the hitcount)
}

// xmlHitEl reproduces enough of the `show security policies hit-count |
// display xml` XML to find the entries and their fields, tolerant to tag
// name variants (from-zone/from-zone-name, to-zone/to-zone-name,
// policy-name, count, policy-action/policy-hit-count-action/action), like
// parse_hitcount() on the Python side, which matches by suffix
// (`t.endswith("from-zone")`).
type xmlHitEl struct {
	XMLName  xml.Name
	Content  []byte     `xml:",innerxml"`
	Children []xmlHitEl `xml:",any"`
}

// ParseHitcount: port of parse_hitcount() (srxtool.py L1473-1541).
func ParseHitcount(r io.Reader) (map[PolicyKey]HitInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	head := data
	if len(head) > 500 {
		head = head[:500]
	}
	if looksLikeXMLHead(head) {
		return parseHitcountXML(data)
	}
	return parseHitcountText(data), nil
}

func looksLikeXMLHead(head []byte) bool {
	s := strings.TrimLeft(string(head), " \t\r\n\f\v")
	return strings.HasPrefix(s, "<")
}

// parseHitcountXML walks the stream token by token rather than decoding the
// whole document into a fixed struct: on an HA-clustered SRX, Junos wraps
// the output in <rpc-reply><multi-routing-engine-results>
// <multi-routing-engine-item><re-name>node0</re-name><policy-hit-count ...>
// ...</policy-hit-count></multi-routing-engine-item>...</...> — two more
// levels of nesting than in standalone mode. Decoding into a struct that
// doesn't declare these levels silently skips the whole element (silent 0
// entries). The token scan ignores depth: it simply looks for
// policy-hit-count-entry (the real format, entries nested inside a
// policy-hit-count container) wherever it appears in the tree, including
// duplicated per node in a cluster (last occurrence wins in the map).
//
// Some variants expose policy-hit-count directly as the entry itself (no
// -entry level, cf the historical golden fixture): handled as a fallback
// when no policy-hit-count-entry is found under the container.
func parseHitcountXML(data []byte) (map[PolicyKey]HitInfo, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	out := map[PolicyKey]HitInfo{}
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "policy-hit-count-entry":
			var entry xmlHitEl
			if err := dec.DecodeElement(&entry, &se); err != nil {
				return nil, err
			}
			addHitEntry(out, entry)
		case "policy-hit-count":
			var container xmlHitEl
			if err := dec.DecodeElement(&container, &se); err != nil {
				return nil, err
			}
			nested := false
			for _, c := range container.Children {
				if c.XMLName.Local == "policy-hit-count-entry" {
					nested = true
					addHitEntry(out, c)
				}
			}
			if !nested {
				// Historical format: policy-hit-count IS the entry.
				addHitEntry(out, container)
			}
		}
	}
	return out, nil
}

// addHitEntry extracts a hit-count entry from its child fields, tolerant to
// the name variants observed on real hardware (from-zone-name in addition
// to from-zone, policy-hit-count-action in addition to
// policy-action/action).
func addHitEntry(out map[PolicyKey]HitInfo, el xmlHitEl) {
	var fz, tz, name, action string
	count := 0
	for _, c := range el.Children {
		val := strings.TrimSpace(string(c.Content))
		local := c.XMLName.Local
		switch {
		case local == "from-zone", local == "from-zone-name", strings.HasSuffix(local, "-from-zone"), strings.HasSuffix(local, "-from-zone-name"):
			fz = val
		case local == "to-zone", local == "to-zone-name", strings.HasSuffix(local, "-to-zone"), strings.HasSuffix(local, "-to-zone-name"):
			tz = val
		case strings.HasSuffix(local, "policy-name"):
			name = val
		case local == "count", strings.HasSuffix(local, "-count"):
			if n, err := strconv.Atoi(val); err == nil {
				count = n
			}
		case strings.Contains(local, "action"):
			action = val
		}
	}
	if name != "" {
		out[PolicyKey{FromZone: fz, ToZone: tz, Name: name}] = HitInfo{Count: count, Action: action}
	}
}

var (
	reHitPolicy = regexp.MustCompile(`(?i)^Policy:\s*([^,]+),\s*action:\s*(\S+)`)
	reHitZones  = regexp.MustCompile(`(?i)^From zone:\s*(\S+),\s*To zone:\s*(\S+)`)
	reHitCount  = regexp.MustCompile(`(?i)Number of policy hit:\s*(\d+)`)
)

// parseHitcountText: port of parse_hitcount()'s CLI text format
// (srxtool.py L1514-1541).
func parseHitcountText(data []byte) map[PolicyKey]HitInfo {
	out := map[PolicyKey]HitInfo{}
	var fz, tz, name, action string
	count := 0
	haveName := false

	flush := func() {
		if haveName {
			out[PolicyKey{FromZone: fz, ToZone: tz, Name: name}] = HitInfo{Count: count, Action: action}
		}
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if m := reHitPolicy.FindStringSubmatch(line); m != nil {
			flush()
			name, action = strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
			haveName = true
			fz, tz = "", ""
			count = 0
			continue
		}
		if m := reHitZones.FindStringSubmatch(line); m != nil {
			fz, tz = m[1], m[2]
			continue
		}
		if m := reHitCount.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				count = n
			}
			continue
		}
	}
	flush()
	return out
}

// CleanupPolicy is the minimal view of a policy that cleanup needs —
// sourced from the inventory JSON (`inv.json`), not from config.Model:
// faithful port of `inv["policies"]` as read by cmd_cleanup() (srxtool.py
// L1544 ff.).
type CleanupPolicy struct {
	FromZone    string   `json:"from_zone"`
	ToZone      string   `json:"to_zone"`
	Name        string   `json:"name"`
	Source      []string `json:"source"`
	Destination []string `json:"destination"`
	Application []string `json:"application"`
	Action      string   `json:"action"`
	Flags       []string `json:"flags"`
}

// CleanupOptions: port of the --only/--exclude/--include-deny/--batch
// options.
type CleanupOptions struct {
	Only        string   // glob pattern, "" is equivalent to "*"
	Exclude     []string // patterns to protect (repeatable)
	IncludeDeny bool
	Batch       string // names the output files / the banner, "" -> "cleanup-hitcount0"
}

// CleanupResult splits the policies into categories, like cmd_cleanup()'s
// console report (srxtool.py L1544-1635): it's the same information
// structure that must appear on the frontend (task 06).
type CleanupResult struct {
	Candidates []CleanupPolicy // removable (hit-count 0)
	KeptDeny   []CleanupPolicy // deny/reject at 0 hits, kept by default
	Excluded   []CleanupPolicy // excluded by --exclude
	Unknown    []CleanupPolicy // no matching hit-count, never removed

	SetCommands []string
	Rollback    []string
}

// Cleanup: port of cmd_cleanup() (srxtool.py L1544-1608), excluding
// disk I/O (left to the caller, HTTP or CLI — cf task 01, pure-signature
// principle).
func Cleanup(policies []CleanupPolicy, hits map[PolicyKey]HitInfo, opts CleanupOptions) (CleanupResult, error) {
	pattern := opts.Only
	if pattern == "" {
		pattern = "*"
	}

	var res CleanupResult
	for _, p := range policies {
		key := PolicyKey{FromZone: p.FromZone, ToZone: p.ToZone, Name: p.Name}
		h, found := hits[key]
		if !found {
			// Fallback: port of `alt = [v for k,v in hits.items() if
			// k[2]==name]` — if exactly one hit matches the policy name
			// (regardless of zones), use it. Ambiguity (0 or several) ->
			// unknown.
			var alt []HitInfo
			for k, v := range hits {
				if k.Name == p.Name {
					alt = append(alt, v)
				}
			}
			if len(alt) == 1 {
				h, found = alt[0], true
			}
		}
		if !found {
			res.Unknown = append(res.Unknown, p)
			continue
		}
		if h.Count != 0 {
			continue
		}
		if !globMatch(pattern, p.Name) {
			continue
		}
		excluded := false
		for _, ex := range opts.Exclude {
			if globMatch(ex, p.Name) {
				excluded = true
				break
			}
		}
		if excluded {
			res.Excluded = append(res.Excluded, p)
			continue
		}
		action := strings.ToLower(firstNonEmpty(h.Action, p.Action, "permit"))
		if (action == "deny" || action == "reject") && !opts.IncludeDeny {
			res.KeptDeny = append(res.KeptDeny, p)
			continue
		}
		res.Candidates = append(res.Candidates, p)
	}

	batch := opts.Batch
	if batch == "" {
		batch = "cleanup-hitcount0"
	}

	dels := []string{
		fmt.Sprintf("# === %s: removing rules with 0 hit-count ===", batch),
		"# GUARD RAILS TO CHECK BEFORE COMMIT:",
		"#  - was the hit-count counter reset recently?",
		"#    (reboot / clear / cluster failover) => 0 may be a false positive.",
		"#  - long enough observation window? aim for >= 90 days of history.",
		"#  - seasonal traffic (DR, quarterly batch) not covered by the window?",
		"#  - load under 'configure private', 'commit check', then 'commit confirmed 10'.",
		"",
	}
	rollback := []string{
		fmt.Sprintf("# === rollback %s (rebuilt from the classification) ===", batch),
		"# Rebuilt fields: source/destination/application/action/flags.",
		"# Check against a full backup for advanced options.",
		"",
	}

	for _, p := range res.Candidates {
		delLine, err := policyDeleteLine(p)
		if err != nil {
			return CleanupResult{}, err
		}
		dels = append(dels, delLine)

		rollback = append(rollback, fmt.Sprintf("# %s->%s %s", p.FromZone, p.ToZone, p.Name))
		setLines, err := policySetLines(p)
		if err != nil {
			return CleanupResult{}, err
		}
		rollback = append(rollback, setLines...)
		rollback = append(rollback, "")
	}

	res.SetCommands = dels
	res.Rollback = rollback
	return res, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// policySetLines / policyDeleteLine: ports of policy_set_lines() /
// policy_delete_line() (srxtool.py L983-1002), used here to rebuild the
// cleanup rollback from the inventory classification.
func policySetLines(p CleanupPolicy) ([]string, error) {
	fzq, err := junosname.Quote(p.FromZone)
	if err != nil {
		return nil, err
	}
	tzq, err := junosname.Quote(p.ToZone)
	if err != nil {
		return nil, err
	}
	nq, err := junosname.Quote(p.Name)
	if err != nil {
		return nil, err
	}
	base := fmt.Sprintf("set security policies from-zone %s to-zone %s policy %s", fzq, tzq, nq)

	var lines []string
	for _, s := range p.Source {
		sq, err := junosname.Quote(s)
		if err != nil {
			return nil, err
		}
		lines = append(lines, base+" match source-address "+sq)
	}
	for _, d := range p.Destination {
		dq, err := junosname.Quote(d)
		if err != nil {
			return nil, err
		}
		lines = append(lines, base+" match destination-address "+dq)
	}
	for _, a := range p.Application {
		aq, err := junosname.Quote(a)
		if err != nil {
			return nil, err
		}
		lines = append(lines, base+" match application "+aq)
	}
	actionQ, err := junosname.Quote(p.Action)
	if err != nil {
		return nil, err
	}
	lines = append(lines, base+" then "+actionQ)
	for _, f := range p.Flags {
		var toks []string
		for _, tok := range strings.Fields(f) {
			tq, err := junosname.Quote(tok)
			if err != nil {
				return nil, err
			}
			toks = append(toks, tq)
		}
		lines = append(lines, base+" then "+strings.Join(toks, " "))
	}
	return lines, nil
}

func policyDeleteLine(p CleanupPolicy) (string, error) {
	fzq, err := junosname.Quote(p.FromZone)
	if err != nil {
		return "", err
	}
	tzq, err := junosname.Quote(p.ToZone)
	if err != nil {
		return "", err
	}
	nq, err := junosname.Quote(p.Name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("delete security policies from-zone %s to-zone %s policy %s", fzq, tzq, nq), nil
}

// globMatch: port of fnmatch.fnmatch(). path.Match is case-sensitive and
// supports *, ?, [...], enough for the documented `--only`/`--exclude`
// patterns (`old-*`, `TEMP-*`, `*`).
func globMatch(pattern, name string) bool {
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}
