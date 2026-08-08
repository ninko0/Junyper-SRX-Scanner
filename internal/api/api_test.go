package api

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/local/srxtool-go/internal/session"
)

const sample2Conf = `security {
    zones {
        security-zone trust {
            interfaces {
                vlan.10;
            }
            address-book {
                address 10.10.10.50 10.10.10.50/32;
                address-set corp-servers {
                    address 10.10.10.50;
                }
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address corp-servers;
                    destination-address any;
                    application junos-https;
                }
                then {
                    permit;
                    log {
                        session-close;
                    }
                }
            }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 203.0.113.1/30;
            }
        }
    }
    vlan {
        unit 10 {
            family inet {
                address 10.10.10.1/24;
            }
        }
    }
}
vlans {
    VLAN10 {
        vlan-id 10;
        l3-interface vlan.10;
    }
}
`

func newTestServer(t *testing.T) *Server {
	t.Helper()
	sessions, err := session.NewManager(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	s := NewServer(sessions, nil)
	s.analyzeRL = newRateLimiter(1000, 1000) // disable rate limiting in tests
	s.rulesRL = newRateLimiter(1000, 1000)
	return s
}

func multipartRequest(t *testing.T, method, path string, files map[string]string, fields map[string]string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for field, content := range files {
		fw, err := mw.CreateFormFile(field, field+".txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestHealthz(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200", rec.Code)
	}
}

// TestAnalyzeAndDownload: full happy path — upload, check the summary,
// download every session file.
func TestAnalyzeAndDownload(t *testing.T) {
	s := newTestServer(t)
	router := s.Router()

	req := multipartRequest(t, "POST", "/api/analyze", map[string]string{"conf": sample2Conf}, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp analyzeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp.SessionID == "" {
		t.Fatal("empty session_id")
	}
	if resp.Inventory.Zones != 2 {
		t.Errorf("zones = %d, expected 2", resp.Inventory.Zones)
	}
	if resp.SourceFormat != "curly" {
		t.Errorf("source_format = %q, expected curly", resp.SourceFormat)
	}

	for _, url := range resp.Downloads {
		dreq := httptest.NewRequest("GET", url, nil)
		drec := httptest.NewRecorder()
		router.ServeHTTP(drec, dreq)
		if drec.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d", url, drec.Code)
		}
		if drec.Body.Len() == 0 {
			t.Errorf("GET %s: empty body", url)
		}
	}
}

// TestSessionFileDownloadRename covers backlog item 4: a client can rename
// a session file download via "?as=", the response's Content-Disposition
// reflects the sanitized name (real extension forced back on regardless of
// what the client typed), and the body served is still exactly the same
// session file — renaming never changes which file is read.
func TestSessionFileDownloadRename(t *testing.T) {
	s := newTestServer(t)
	router := s.Router()

	req := multipartRequest(t, "POST", "/api/analyze", map[string]string{"conf": sample2Conf}, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var resp analyzeResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	baseURL := resp.Downloads["audit_report_txt"]

	// Baseline: no "as" -> the server's own internal name.
	plain := httptest.NewRequest("GET", baseURL, nil)
	plainRec := httptest.NewRecorder()
	router.ServeHTTP(plainRec, plain)
	if plainRec.Code != http.StatusOK {
		t.Fatalf("baseline download: status = %d", plainRec.Code)
	}
	if cd := plainRec.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="audit_report.txt"`) {
		t.Errorf("baseline Content-Disposition = %q, expected the internal name", cd)
	}
	baseline := plainRec.Body.String()

	cases := []struct {
		name     string
		as       string
		wantInCD string
	}{
		{"simple rename", "my-custom-name", `filename="my-custom-name.txt"`},
		{"client extension ignored, real one forced", "my-custom-name.json", `filename="my-custom-name.txt"`},
		{"path traversal collapses to base name", "../../../etc/passwd", `filename="passwd.txt"`},
		{"empty as falls back to internal name", "", `filename="audit_report.txt"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			renamed := httptest.NewRequest("GET", baseURL+"?as="+url.QueryEscape(c.as), nil)
			renamedRec := httptest.NewRecorder()
			router.ServeHTTP(renamedRec, renamed)
			if renamedRec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", renamedRec.Code, renamedRec.Body.String())
			}
			if cd := renamedRec.Header().Get("Content-Disposition"); !strings.Contains(cd, c.wantInCD) {
				t.Errorf("Content-Disposition = %q, expected to contain %q", cd, c.wantInCD)
			}
			// The renamed download must still be byte-identical to the
			// un-renamed one: "as" only ever affects the header, never
			// which file is read from disk.
			if renamedRec.Body.String() != baseline {
				t.Error("renamed download body differs from the baseline — the server-side file changed")
			}
		})
	}
}

// TestAnalyzeBadFormat: an input that doesn't look like any known format
// must be rejected with a generic message, never a 500.
func TestAnalyzeBadFormat(t *testing.T) {
	s := newTestServer(t)
	req := multipartRequest(t, "POST", "/api/analyze", map[string]string{"conf": "this is not a conf\n"}, nil)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, expected 400", rec.Code)
	}
	var body errorResponse
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Error == "" {
		t.Fatal("expected a generic error message")
	}
	if strings.Contains(body.Error, "/tmp") || strings.Contains(body.Error, "goroutine") {
		t.Fatal("the error message must never contain internal detail")
	}
}

// TestPathTraversal is the explicit test required by task 05/08: an attempt
// with a malicious sid/fname -> always 404, never a file outside the
// session.
func TestPathTraversal(t *testing.T) {
	s := newTestServer(t)
	router := s.Router()

	// Create a real session so there's a legitimate file to try to escape
	// next to.
	req := multipartRequest(t, "POST", "/api/analyze", map[string]string{"conf": sample2Conf}, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var resp analyzeResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	malicious := []string{
		"/api/sessions/../../../etc/passwd/inventory/report.txt",
		"/api/sessions/..%2f..%2f..%2fetc%2fpasswd/inventory/report.txt",
		"/api/sessions/" + strings.Repeat("a", 32) + "/inventory/report.txt", // syntactically valid but nonexistent sid
		"/api/sessions/not-a-valid-sid/inventory/report.txt",
		"/api/sessions/" + resp.SessionID + "/../../../etc/passwd",
	}
	for _, url := range malicious {
		mreq := httptest.NewRequest("GET", url, nil)
		mrec := httptest.NewRecorder()
		router.ServeHTTP(mrec, mreq)

		code, body := mrec.Code, mrec.Body.String()
		// ServeMux automatically cleans up paths containing ".." and
		// redirects (301) to the canonical form before our handlers run —
		// not a leak in itself (just a Location header, no data), but we
		// check the actual destination, the way a client following
		// redirects would.
		if code == http.StatusMovedPermanently || code == http.StatusFound {
			loc := mrec.Header().Get("Location")
			freq := httptest.NewRequest("GET", loc, nil)
			frec := httptest.NewRecorder()
			router.ServeHTTP(frec, freq)
			code, body = frec.Code, frec.Body.String()
		}
		if code != http.StatusNotFound && code != http.StatusBadRequest {
			t.Errorf("GET %s: final status = %d, expected 404/400", url, code)
		}
		if strings.Contains(body, "root:") {
			t.Fatalf("LEAK: GET %s returned suspicious content", url)
		}
	}
}

// TestMaxBodySize: an oversized body must be rejected cleanly.
func TestMaxBodySize(t *testing.T) {
	s := newTestServer(t)
	s.MaxBytes = 100 // very low, for the test
	router := s.Router()

	big := strings.Repeat("a", 10000)
	req := multipartRequest(t, "POST", "/api/analyze", map[string]string{"conf": big}, nil)
	rec := httptest.NewRecorder()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic instead of a clean error: %v", r)
			}
		}()
		router.ServeHTTP(rec, req)
	}()

	if rec.Code == http.StatusOK {
		t.Fatal("an oversized upload should never succeed")
	}
}

// TestRenameSuggestAndApply: full suggest -> apply cycle on the rich
// fixture shared with the rules package.
func TestRenameSuggestAndApply(t *testing.T) {
	s := newTestServer(t)
	router := s.Router()

	req := multipartRequest(t, "POST", "/api/rules/rename/suggest", map[string]string{"conf": richFixtureForAPI}, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("suggest: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csv := rec.Body.String()
	if !strings.Contains(csv, "10.10.10.50") {
		t.Fatalf("unexpected CSV: %s", csv)
	}

	filledCSV := strings.Replace(csv, "trust,zone,10.10.10.50,10.10.10.50/32,trust,1,,trust-host-50,",
		"trust,zone,10.10.10.50,10.10.10.50/32,trust,1,,trust-host-50,web-corp-01", 1)

	req2 := multipartRequest(t, "POST", "/api/rules/rename/apply",
		map[string]string{"conf": richFixtureForAPI, "map": filledCSV}, nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("apply: status = %d, body = %s", rec2.Code, rec2.Body.String())
	}
	var applyResp renameApplyResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &applyResp); err != nil {
		t.Fatalf("invalid response: %v", err)
	}
	if applyResp.Applied != 1 {
		t.Errorf("Applied = %d, expected 1", applyResp.Applied)
	}
	joined := strings.Join(applyResp.SetCommands, "\n")
	if !strings.Contains(joined, "web-corp-01") {
		t.Errorf("expected commands missing: %v", applyResp.SetCommands)
	}
}

// TestRenameSuggestDownloadRename covers backlog item 4 on the CSV
// download: an "as" form field renames the CSV via Content-Disposition,
// with the ".csv" extension always forced back on.
func TestRenameSuggestDownloadRename(t *testing.T) {
	s := newTestServer(t)
	router := s.Router()

	req := multipartRequest(t, "POST", "/api/rules/rename/suggest",
		map[string]string{"conf": richFixtureForAPI}, map[string]string{"as": "my plan.exe"})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="my plan.csv"`) {
		t.Errorf("Content-Disposition = %q, expected the .csv extension forced on", cd)
	}
	if !strings.Contains(rec.Body.String(), "10.10.10.50") {
		t.Fatalf("unexpected CSV: %s", rec.Body.String())
	}
}

// TestCleanupEndpoint: upload inventory JSON + hitcount -> categorization.
func TestCleanupEndpoint(t *testing.T) {
	s := newTestServer(t)
	router := s.Router()

	invJSON := `{"policies":[{"from_zone":"trust","to_zone":"untrust","name":"allow-web","source":["corp-servers"],"destination":["any"],"application":["junos-https"],"action":"permit","flags":["log session-close"]}]}`
	hitXML := `<security-policies-hit-count-information>
<policy-hit-count>
<from-zone>trust</from-zone>
<to-zone>untrust</to-zone>
<policy-name>allow-web</policy-name>
<count>0</count>
<policy-action>permit</policy-action>
</policy-hit-count>
</security-policies-hit-count-information>`

	req := multipartRequest(t, "POST", "/api/rules/cleanup",
		map[string]string{"inventory": invJSON, "hitcount": hitXML}, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp cleanupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response: %v", err)
	}
	if len(resp.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(resp.Candidates))
	}
	if resp.Warning != "" {
		t.Errorf("no warning expected when the reconciliation succeeds: %q", resp.Warning)
	}
}

// TestCleanupEndpointAllUnknownWarns reproduces the UX defect from backlog
// item 1: a hit-count in a format the parser doesn't recognize (here a text
// file unrelated to the hit-count CLI format) must produce an explicit
// warning, not a silent "0 removable" indistinguishable from a genuinely
// clean sweep.
func TestCleanupEndpointAllUnknownWarns(t *testing.T) {
	s := newTestServer(t)
	router := s.Router()

	invJSON := `{"policies":[
		{"from_zone":"trust","to_zone":"untrust","name":"allow-web","action":"permit"},
		{"from_zone":"untrust","to_zone":"trust","name":"any-any","action":"permit"}
	]}`
	// Unrecognized format: matches neither the XML format nor the parser's
	// text regexes -> no entries, both policies stay "unknown".
	hitGarbage := "this is not a valid hit-count export\n"

	req := multipartRequest(t, "POST", "/api/rules/cleanup",
		map[string]string{"inventory": invJSON, "hitcount": hitGarbage}, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp cleanupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response: %v", err)
	}
	if len(resp.Unknown) != 2 {
		t.Fatalf("expected 2 'unknown' policies, got %d", len(resp.Unknown))
	}
	if resp.Warning == "" {
		t.Fatal("an explicit warning is expected when 100% of policies are ignored")
	}
}

func TestUnknownRatioWarning(t *testing.T) {
	cases := []struct {
		name          string
		total, unkown int
		wantEmpty     bool
	}{
		{"none ignored", 10, 0, true},
		{"no policies", 0, 0, true},
		{"total failure", 7, 7, false},
		{"above the 20% threshold", 10, 3, false},
		{"below the 20% threshold", 10, 2, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := unknownRatioWarning(c.total, c.unkown)
			if c.wantEmpty && got != "" {
				t.Errorf("expected empty warning, got %q", got)
			}
			if !c.wantEmpty && got == "" {
				t.Errorf("expected non-empty warning for total=%d unknown=%d", c.total, c.unkown)
			}
		})
	}
}

func TestRateLimiting(t *testing.T) {
	s := newTestServer(t)
	s.analyzeRL = newRateLimiter(0.001, 1) // 1 token, effectively never refilled
	router := s.Router()

	ok, limited := 0, 0
	for i := 0; i < 5; i++ {
		req := multipartRequest(t, "POST", "/api/analyze", map[string]string{"conf": sample2Conf}, nil)
		req.RemoteAddr = "203.0.113.9:1234"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited++
		} else if rec.Code == http.StatusOK {
			ok++
		}
	}
	if limited == 0 {
		t.Fatal("at least one request should have been rate-limited")
	}
	if ok == 0 {
		t.Fatal("at least one request should have gone through (initial burst)")
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/analyze", nil)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on /api/analyze: status = %d, expected 405", rec.Code)
	}
}

// TestWriteFileAtomicNoPartialRead checks that writeFileAtomic never leaves
// a leftover temp file behind after success.
func TestWriteFileAtomicNoPartialRead(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	if err := writeFileAtomic(target, []byte("content")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "content" {
		t.Fatalf("incorrect content: %q, %v", data, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover temp file: %v", entries)
	}
}

const richFixtureForAPI = `system {
    services {
        ssh {
            root-login deny;
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                vlan.10;
            }
            address-book {
                address 10.10.10.50 10.10.10.50/32;
                address-set corp-servers {
                    address 10.10.10.50;
                }
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address corp-servers;
                    destination-address any;
                    application junos-https;
                }
                then {
                    permit;
                    log {
                        session-close;
                    }
                }
            }
        }
        from-zone untrust to-zone trust {
            policy any-any {
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
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 203.0.113.1/30;
            }
        }
    }
    vlan {
        unit 10 {
            family inet {
                address 10.10.10.1/24;
            }
        }
    }
}
vlans {
    VLAN10 {
        vlan-id 10;
        l3-interface vlan.10;
    }
}
`
