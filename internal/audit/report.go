package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/xlsx"
)

// Run: port of the orchestration done in main() (srxaudit.py L899-926) —
// check_policies + check_zones + check_system (if `system` exists), sorted.
//
// Deliberate signature divergence (see finding.go): error returned
// explicitly rather than swallowed, for UnsafeNameError.
func Run(m *config.Model) ([]Finding, error) {
	var all []Finding

	pf, err := checkPolicies(m.Zones, m.Policies)
	if err != nil {
		return nil, err
	}
	all = append(all, pf...)

	zf, err := checkZones(m.Zones, m.Screens)
	if err != nil {
		return nil, err
	}
	all = append(all, zf...)

	// `if m["system"] is not None: check_system(...)`: the SYS-*/SNMP-*
	// checks are ALL skipped if `system {}` is absent from the conf —
	// including SNMP-*, even when `snmp {}` exists elsewhere. This is a
	// Python behavior kept as-is (see docs/README for the discussion), not
	// a silent fix.
	if config.Exists(m.System) {
		sf, err := checkSystem(m.System, m.SNMP)
		if err != nil {
			return nil, err
		}
		all = append(all, sf...)
	}

	sortFindings(all)
	return all, nil
}

// sortFindings: port of `findings.sort(key=lambda f: (SEV_RANK[f.sev], f.check, f.where))`.
func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Where < b.Where
	})
}

// FilterMinSeverity: port of the `--min-severity` filter (srxaudit.py L920-921).
// Only keeps findings whose rank is <= the threshold (i.e. more severe or
// equal).
func FilterMinSeverity(findings []Finding, min Severity) []Finding {
	thr, ok := severityRank[min]
	if !ok {
		thr = severityRank[Info]
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if severityRank[f.Severity] <= thr {
			out = append(out, f)
		}
	}
	return out
}

// CountBySeverity: port of count_by_severity().
func CountBySeverity(findings []Finding) map[Severity]int {
	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// ReportText: port of build_report_text() (srxaudit.py L807-833).
//
// meta carries source_format/warnings, like the optional `m` dict passed
// in Python — an audit must say what it couldn't read, otherwise "0
// findings" is indistinguishable from "understood nothing".
func ReportText(findings []Finding, m *config.Model) string {
	sorted := append([]Finding(nil), findings...)
	sortFindings(sorted)
	counts := CountBySeverity(sorted)

	var lines []string
	sep := strings.Repeat("=", 72)
	lines = append(lines, sep, "SRX HARDENING AUDIT — REMEDIATIONS", sep)

	if m != nil {
		lines = append(lines, fmt.Sprintf("Detected source format: %s", orQuestion(m.SourceFormat)))
		if len(m.Warnings) > 0 {
			lines = append(lines, "",
				fmt.Sprintf("⚠ %d PARSING WARNING(S) — the audit may be incomplete:", len(m.Warnings)))
			for _, w := range m.Warnings {
				lines = append(lines, "    - "+w)
			}
		}
	}

	parts := make([]string, 0, len(severityOrder))
	for _, s := range severityOrder {
		parts = append(parts, fmt.Sprintf("%s:%d", s, counts[s]))
	}
	lines = append(lines, fmt.Sprintf("Total: %d   [%s]", len(sorted), strings.Join(parts, "  ")), "")

	for _, f := range sorted {
		lines = append(lines,
			fmt.Sprintf("[%s] %s — %s", f.Severity, f.Check, f.Title),
			"    where  : "+f.Where,
			"    reco   : "+f.Reco,
			"    ref    : "+f.Ref)
		if len(f.Fix) > 0 {
			lines = append(lines, "    fix :")
			for _, c := range f.Fix {
				lines = append(lines, "        "+c)
			}
		}
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// findingsJSONOut: port of the {"summary": counts, "findings": [...]} dict
// (build_findings_json, srxaudit.py L849-855). Matches the shape of
// `audit.json` exactly.
type findingsJSONOut struct {
	Summary  map[Severity]int `json:"summary"`
	Findings []Finding        `json:"findings"`
}

// FindingsJSON: port of build_findings_json().
func FindingsJSON(findings []Finding) ([]byte, error) {
	sorted := append([]Finding(nil), findings...)
	sortFindings(sorted)
	out := findingsJSONOut{Summary: CountBySeverity(sorted), Findings: sorted}
	if out.Findings == nil {
		out.Findings = []Finding{}
	}
	for i := range out.Findings {
		if out.Findings[i].Fix == nil {
			out.Findings[i].Fix = []string{}
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

// FixText: port of build_fix_text() (srxaudit.py L858-866).
func FixText(findings []Finding) string {
	sorted := append([]Finding(nil), findings...)
	sortFindings(sorted)

	lines := []string{
		"# === proposed fixes (REVIEW before commit) ===",
		"# Commented-out lines (#) need a decision/value.",
		"# Load under 'configure private' then 'commit check'.",
		"",
	}
	for _, f := range sorted {
		if len(f.Fix) == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("# [%s] %s — %s", f.Severity, f.Check, f.Where))
		lines = append(lines, f.Fix...)
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n") + "\n"
}

// ExportXLSX: port of export_findings_xlsx() (srxaudit.py L780-794),
// reusing the shared writer introduced in task 02 (eliminates the
// FILLS/write_xlsx copy duplicated identically in srxaudit.py and
// srxtool.py).
func ExportXLSX(findings []Finding, w io.Writer) error {
	sorted := append([]Finding(nil), findings...)
	sortFindings(sorted)

	rows := make([][]xlsx.Cell, 0, len(sorted))
	for _, f := range sorted {
		rows = append(rows, []xlsx.Cell{
			xlsx.Text(string(f.Severity)).Styled(xlsx.Style(f.Severity)),
			xlsx.Text(f.Check).Styled(xlsx.Style(f.Severity)),
			xlsx.Text(f.Title).Styled(xlsx.Style(f.Severity)),
			xlsx.Text(f.Where).Styled(xlsx.Style(f.Severity)),
			xlsx.Text(f.Reco).Styled(xlsx.Style(f.Severity)),
			xlsx.Text(f.Ref).Styled(xlsx.Style(f.Severity)),
			xlsx.Text(strings.Join(f.Fix, " | ")).Styled(xlsx.Style(f.Severity)),
		})
	}
	wb := xlsx.New()
	wb.AddSheet("Findings",
		[]string{"Severity", "Check", "Title", "Location", "Recommendation", "Reference", "Proposed fix"},
		rows, 11, 20, 40, 45, 55, 20, 60)
	return wb.Write(w)
}

func orQuestion(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
