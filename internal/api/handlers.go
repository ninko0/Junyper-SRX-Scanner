package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/local/srxtool-go/internal/audit"
	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/inventory"
	"github.com/local/srxtool-go/internal/junosname"
	"github.com/local/srxtool-go/internal/rules"
	"github.com/local/srxtool-go/internal/vendors"

	// Side-effect import: registers the Junos parser in the internal/vendors
	// registry (cf backlog item 2, multi-vendor architecture). Adding a
	// vendor means adding one line here (and nothing else in this file —
	// that's the whole point of the registry).
	_ "github.com/local/srxtool-go/internal/vendors/junos"
)

// Session-internal file names. Never derived from user input: the URL only
// ever supplies `sid` (task 05, session section) — the file actually read
// from disk is always one of these constants, chosen by the route itself
// (see Router()).
const (
	fileInvReportTxt    = "inv_report.txt"
	fileInvReportJSON   = "inv_report.json"
	fileInvReportXLSX   = "inv_report.xlsx"
	fileAuditReportTxt  = "audit_report.txt"
	fileAuditReportJSON = "audit_report.json"
	fileAuditReportXLSX = "audit_report.xlsx"
	fileAuditFixSet     = "audit_fix.set"
)

var sessionFileInternalName = map[[2]string]string{
	{"inventory", "report.txt"}:  fileInvReportTxt,
	{"inventory", "report.json"}: fileInvReportJSON,
	{"inventory", "report.xlsx"}: fileInvReportXLSX,
	{"audit", "report.txt"}:      fileAuditReportTxt,
	{"audit", "report.json"}:     fileAuditReportJSON,
	{"audit", "report.xlsx"}:     fileAuditReportXLSX,
	{"audit", "fix.set"}:         fileAuditFixSet,
}

var contentTypeByKind = map[string]string{
	"report.txt":  "text/plain; charset=utf-8",
	"report.json": "application/json; charset=utf-8",
	"report.xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"fix.set":     "text/plain; charset=utf-8",
}

// analyzeResponse is the response body of POST /api/analyze.
type analyzeResponse struct {
	SessionID    string            `json:"session_id"`
	SourceFormat string            `json:"source_format"`
	Warnings     []string          `json:"warnings"`
	Audit        auditSummary      `json:"audit"`
	Inventory    inventorySummary  `json:"inventory"`
	Downloads    map[string]string `json:"downloads"`
}

type auditSummary struct {
	Total   int                    `json:"total"`
	Summary map[audit.Severity]int `json:"summary"`
}

type inventorySummary struct {
	Zones          int `json:"zones"`
	VLANs          int `json:"vlans"`
	Policies       int `json:"policies"`
	AddressObjects int `json:"address_objects"`
}

// handleAnalyze: port of cmd_inventory()+main() from srxaudit.py, merged
// behind a single route that runs all 3 analyses and creates a session
// (POST /api/analyze, cf task 05).
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if !s.analyzeRL.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "too many requests, try again in a few seconds")
		return
	}

	data, _, err := readMultipartFile(r, "conf", s.MaxBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "configuration file missing or unreadable")
		return
	}

	minSev := audit.Info
	if v := r.FormValue("min_severity"); v != "" {
		if sev, ok := parseSeverity(v); ok {
			minSev = sev
		}
	}

	m, _, err := vendors.DetectConfig(data, config.Options{MaxBytes: s.MaxBytes})
	if err != nil {
		s.Logger.Warn("analyze: parsing failed", "error", err)
		writeError(w, http.StatusBadRequest,
			"unreadable configuration: no recognized format (XML, curly braces, or 'display set')")
		return
	}

	invResult := inventory.Build(m)
	findings, err := audit.Run(m)
	if err != nil {
		var un *junosname.UnsafeNameError
		if errors.As(err, &un) {
			writeError(w, http.StatusUnprocessableEntity,
				"a name in the configuration contains an unsafe character, audit aborted")
			return
		}
		s.Logger.Error("analyze: audit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	findings = audit.FilterMinSeverity(findings, minSev)

	sid, err := s.Sessions.Create()
	if err != nil {
		s.Logger.Error("analyze: session creation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := s.writeSessionOutputs(sid, m, invResult, findings); err != nil {
		s.Logger.Error("analyze: writing results failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	resp := analyzeResponse{
		SessionID:    sid,
		SourceFormat: m.SourceFormat,
		Warnings:     m.Warnings,
		Audit:        auditSummary{Total: len(findings), Summary: audit.CountBySeverity(findings)},
		Inventory: inventorySummary{
			Zones: len(m.Zones), VLANs: len(m.VLANs), Policies: len(m.Policies),
			AddressObjects: len(invResult.AddressObjects),
		},
		Downloads: map[string]string{
			"inventory_report_txt":  fmt.Sprintf("/api/sessions/%s/inventory/report.txt", sid),
			"inventory_report_json": fmt.Sprintf("/api/sessions/%s/inventory/report.json", sid),
			"inventory_report_xlsx": fmt.Sprintf("/api/sessions/%s/inventory/report.xlsx", sid),
			"audit_report_txt":      fmt.Sprintf("/api/sessions/%s/audit/report.txt", sid),
			"audit_report_json":     fmt.Sprintf("/api/sessions/%s/audit/report.json", sid),
			"audit_report_xlsx":     fmt.Sprintf("/api/sessions/%s/audit/report.xlsx", sid),
			"audit_fix_set":         fmt.Sprintf("/api/sessions/%s/audit/fix.set", sid),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) writeSessionOutputs(sid string, m *config.Model, inv *inventory.Result, findings []audit.Finding) error {
	writeFile := func(fname string, data []byte) error {
		p, err := s.Sessions.WritePath(sid, fname)
		if err != nil {
			return err
		}
		return writeFileAtomic(p, data)
	}

	if err := writeFile(fileInvReportTxt, []byte(inv.ReportText())); err != nil {
		return err
	}
	invJSON, err := inv.JSON()
	if err != nil {
		return err
	}
	if err := writeFile(fileInvReportJSON, invJSON); err != nil {
		return err
	}
	var invXLSX bytes.Buffer
	if err := inv.ExportXLSX(&invXLSX); err != nil {
		return err
	}
	if err := writeFile(fileInvReportXLSX, invXLSX.Bytes()); err != nil {
		return err
	}

	if err := writeFile(fileAuditReportTxt, []byte(audit.ReportText(findings, m))); err != nil {
		return err
	}
	auditJSON, err := audit.FindingsJSON(findings)
	if err != nil {
		return err
	}
	if err := writeFile(fileAuditReportJSON, auditJSON); err != nil {
		return err
	}
	var auditXLSX bytes.Buffer
	if err := audit.ExportXLSX(findings, &auditXLSX); err != nil {
		return err
	}
	if err := writeFile(fileAuditReportXLSX, auditXLSX.Bytes()); err != nil {
		return err
	}
	return writeFile(fileAuditFixSet, []byte(audit.FixText(findings)))
}

// handleSessionFile serves a whitelisted session file. tool/kind are fixed
// at routing time (Router()), never read from the URL — the only variable
// parameters coming from the client are `sid`, validated by
// session.Manager.ReadPath (strict regex + anti-traversal resolution), and
// the optional `?as=` download name (backlog item 4: renaming an exported
// report before download). `as` only ever feeds the Content-Disposition
// header via sanitizeDownloadName — it is never passed to Sessions.ReadPath
// and never touches the server-side path, which stays `internalName` no
// matter what the client asks to call the download.
func (s *Server) handleSessionFile(tool, kind string) http.HandlerFunc {
	internalName := sessionFileInternalName[[2]string{tool, kind}]
	contentType := contentTypeByKind[kind]
	allowed := map[string]bool{internalName: true}
	ext := filepath.Ext(kind)

	return func(w http.ResponseWriter, r *http.Request) {
		sid := r.PathValue("sid")
		p, err := s.Sessions.ReadPath(sid, internalName, allowed)
		if err != nil {
			// Uniform 404: never distinguish "invalid session" from "file
			// missing" to the client (cf task 08, traversal test).
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		downloadName := sanitizeDownloadName(r.URL.Query().Get("as"), internalName, ext)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", contentDispositionAttachment(downloadName))
		http.ServeFile(w, r, p)
	}
}

// handleRenameSuggest: POST /api/rules/rename/suggest — upload a conf,
// return the plan CSV directly (no session: it's a simple round trip,
// replayed on demand).
func (s *Server) handleRenameSuggest(w http.ResponseWriter, r *http.Request) {
	if !s.rulesRL.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "too many requests, try again in a few seconds")
		return
	}
	data, _, err := readMultipartFile(r, "conf", s.MaxBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "configuration file missing or unreadable")
		return
	}
	useDNS := r.FormValue("dns") == "true" || r.FormValue("dns") == "1"

	m, _, err := vendors.DetectConfig(data, config.Options{MaxBytes: s.MaxBytes})
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable configuration")
		return
	}
	inv := inventory.Build(m)
	candidates := rules.DetectIPNamedObjects(inv, m)

	// Backlog item 4: the client may rename this download via the "as"
	// form field. Same rule as handleSessionFile — sanitizeDownloadName
	// only ever feeds the response header, this request never touches a
	// server-side path (the CSV is generated in memory and streamed
	// directly, cf rules.WriteSuggestCSV below).
	downloadName := sanitizeDownloadName(r.FormValue("as"), "rename-plan.csv", ".csv")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", contentDispositionAttachment(downloadName))
	if err := rules.WriteSuggestCSV(candidates, useDNS, w); err != nil {
		s.Logger.Error("rename/suggest: CSV write failed", "error", err)
	}
}

// renameApplyResponse: port of the rename.set + rename-rollback.set
// content, returned as JSON rather than two separate files — simpler to
// consume from the frontend (task 06), which can offer both as
// client-built (Blob) downloads without an extra server round trip.
type renameApplyResponse struct {
	SetCommands []string `json:"set_commands"`
	Rollback    []string `json:"rollback"`
	Rejected    []string `json:"rejected"` // rejected new_name lines, with reason
	Applied     int      `json:"applied"`
}

// handleRenameApply: POST /api/rules/rename/apply — upload conf + filled-in
// CSV.
func (s *Server) handleRenameApply(w http.ResponseWriter, r *http.Request) {
	if !s.rulesRL.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "too many requests, try again in a few seconds")
		return
	}
	confData, _, err := readMultipartFile(r, "conf", s.MaxBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "configuration file missing or unreadable")
		return
	}
	mapData, _, err := readMultipartFile(r, "map", s.MaxBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "mapping CSV missing or unreadable")
		return
	}

	m, _, err := vendors.DetectConfig(confData, config.Options{MaxBytes: s.MaxBytes})
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable configuration")
		return
	}
	inv := inventory.Build(m)
	candidates := rules.DetectIPNamedObjects(inv, m)

	mapping, rejected, err := rules.ReadRenameMapCSV(bytes.NewReader(mapData))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable mapping CSV")
		return
	}
	if len(mapping) == 0 {
		writeJSON(w, http.StatusOK, renameApplyResponse{Rejected: rejected})
		return
	}

	setCmds, rollback, err := rules.ApplyRenameMap(candidates, mapping)
	if err != nil {
		var un *junosname.UnsafeNameError
		if errors.As(err, &un) {
			writeError(w, http.StatusUnprocessableEntity, "a name contains an unsafe character")
			return
		}
		s.Logger.Error("rename/apply: generation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, renameApplyResponse{
		SetCommands: setCmds, Rollback: rollback, Rejected: rejected, Applied: len(mapping),
	})
}

// cleanupResponse mirrors the same information structure as the console
// report of cmd_cleanup() (candidates / kept deny / excluded / unknown, cf
// task 04/06).
type cleanupResponse struct {
	Candidates  []rules.CleanupPolicy `json:"candidates"`
	KeptDeny    []rules.CleanupPolicy `json:"kept_deny"`
	Excluded    []rules.CleanupPolicy `json:"excluded"`
	Unknown     []rules.CleanupPolicy `json:"unknown"`
	SetCommands []string              `json:"set_commands"`
	Rollback    []string              `json:"rollback"`
	// Warning flags a degraded or fully failed hit-count reconciliation —
	// distinguishes "no unused rule" (Warning empty) from "couldn't read
	// your counters" (Warning set), which would otherwise both render as
	// the same misleading "0 removable". Cf backlog item 1.
	Warning string `json:"warning,omitempty"`
}

// unknownRatioWarning: port of the guard rail "a reconciliation that fails
// entirely must be a reported error, never an empty result" (backlog item
// 1). Thresholds: 100% (total failure, e.g. unreadable/wrong-format
// hit-count) and > 20% (notable partial failure, e.g. a few policies
// missing from the hit-count for lack of traffic since the device's last
// reboot).
func unknownRatioWarning(total, unknown int) string {
	if total == 0 || unknown == 0 {
		return ""
	}
	ratio := float64(unknown) / float64(total)
	switch {
	case unknown == total:
		return fmt.Sprintf(
			"No policy could be reconciled against the hit-count (%d/%d ignored). "+
				"The hit-count file is probably in an unrecognized format or doesn't match this conf — "+
				"check it before concluding '0 removable'.",
			unknown, total,
		)
	case ratio > 0.20:
		return fmt.Sprintf(
			"%d out of %d policies (%.0f%%) have no matching hit-count entry and are ignored, "+
				"not counted as '0 removable'. Check that the hit-count file is complete and up to date.",
			unknown, total, ratio*100,
		)
	default:
		return ""
	}
}

// handleCleanup: POST /api/rules/cleanup — upload an inventory JSON + a
// hit-count export.
func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request) {
	if !s.rulesRL.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "too many requests, try again in a few seconds")
		return
	}
	invData, _, err := readMultipartFile(r, "inventory", s.MaxBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "inventory JSON missing or unreadable")
		return
	}
	hitData, _, err := readMultipartFile(r, "hitcount", s.MaxBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "hit-count export missing or unreadable")
		return
	}

	var invPayload struct {
		Policies []rules.CleanupPolicy `json:"policies"`
	}
	if err := json.Unmarshal(invData, &invPayload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid inventory JSON")
		return
	}

	hits, err := rules.ParseHitcount(bytes.NewReader(hitData))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable hit-count export")
		return
	}

	opts := rules.CleanupOptions{
		Only:        r.FormValue("only"),
		IncludeDeny: r.FormValue("include_deny") == "true" || r.FormValue("include_deny") == "1",
		Batch:       r.FormValue("batch"),
	}
	if excl := r.Form["exclude"]; len(excl) > 0 {
		opts.Exclude = excl
	}

	res, err := rules.Cleanup(invPayload.Policies, hits, opts)
	if err != nil {
		var un *junosname.UnsafeNameError
		if errors.As(err, &un) {
			writeError(w, http.StatusUnprocessableEntity, "a name contains an unsafe character")
			return
		}
		s.Logger.Error("cleanup: generation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	total := len(invPayload.Policies)
	writeJSON(w, http.StatusOK, cleanupResponse{
		Candidates: orEmptyPolicies(res.Candidates), KeptDeny: orEmptyPolicies(res.KeptDeny),
		Excluded: orEmptyPolicies(res.Excluded), Unknown: orEmptyPolicies(res.Unknown),
		SetCommands: res.SetCommands, Rollback: res.Rollback,
		Warning: unknownRatioWarning(total, len(res.Unknown)),
	})
}

func orEmptyPolicies(p []rules.CleanupPolicy) []rules.CleanupPolicy {
	if p == nil {
		return []rules.CleanupPolicy{}
	}
	return p
}

// readMultipartFile reads a multipart file field bounded to maxBytes. The
// content is loaded into memory (the files handled — confs, CSV, hit-count
// exports — stay modest in size; cf task 01 for the limit applied
// independently by the config package).
func readMultipartFile(r *http.Request, field string, maxBytes int64) ([]byte, *multipart.FileHeader, error) {
	if err := r.ParseMultipartForm(maxBytes); err != nil {
		return nil, nil, err
	}
	f, hdr, err := r.FormFile(field)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, fmt.Errorf("file too large")
	}
	return data, hdr, nil
}

func parseSeverity(v string) (audit.Severity, bool) {
	switch strings.ToUpper(v) {
	case "CRITICAL":
		return audit.Critical, true
	case "HIGH":
		return audit.High, true
	case "MEDIUM":
		return audit.Medium, true
	case "LOW":
		return audit.Low, true
	case "INFO":
		return audit.Info, true
	default:
		return "", false
	}
}
