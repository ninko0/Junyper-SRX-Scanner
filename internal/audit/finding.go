// Package audit reproduces srxaudit.py: a fixed hardening-check catalog,
// findings classified by severity, a text/JSON/XLSX report, and a
// `set`/`delete` fix file in text form — never executed.
package audit

import (
	"github.com/local/srxtool-go/internal/junosname"
)

// Severity: port of SEV_RANK's 5 levels (srxaudit.py L128).
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// severityRank sets the sort order, identical to SEV_RANK.
var severityRank = map[Severity]int{
	Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4,
}

// severityOrder is the summary's display order (build_report_text).
var severityOrder = []Severity{Critical, High, Medium, Low, Info}

// Finding: port of the Finding class (srxaudit.py L130-139).
type Finding struct {
	Severity Severity `json:"severity"`
	Check    string   `json:"check"`
	Title    string   `json:"title"`
	Where    string   `json:"where"`
	Reco     string   `json:"recommendation"`
	Ref      string   `json:"reference"`
	Fix      []string `json:"fix"`
}

// ErrUnsafeName re-exports junosname.ErrUnsafeName: Run() can fail with
// this error (via q()) if a policy or SNMP community name contains an
// injection character. See junosname.Quote.
var ErrUnsafeName = junosname.ErrUnsafeName

// q delegates to junosname.Quote — port of q() (srxtool.py L910-925),
// shared with internal/rules just as Python's srxaudit imports q() from
// srxtool.
func q(name string) (string, error) { return junosname.Quote(name) }
