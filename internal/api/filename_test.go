package api

import "testing"

func TestSanitizeDownloadName(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		def  string
		ext  string
		want string
	}{
		{"empty falls back to default", "", "audit_report.txt", ".txt", "audit_report.txt"},
		{"blank falls back to default", "   ", "audit_report.txt", ".txt", "audit_report.txt"},
		{"simple name gets extension forced on", "my-audit", "audit_report.txt", ".txt", "my-audit.txt"},
		{"spaces preserved", "Q3 firewall audit", "audit_report.txt", ".txt", "Q3 firewall audit.txt"},
		{"client extension is discarded, real one forced", "my-audit.json", "audit_report.txt", ".txt", "my-audit.txt"},
		{"client extension discarded even if it matches", "my-audit.txt", "audit_report.txt", ".txt", "my-audit.txt"},
		{"unix path collapses to base name", "../../../etc/passwd", "audit_report.txt", ".txt", "passwd.txt"},
		{"absolute unix path collapses to base name", "/etc/passwd", "audit_report.txt", ".txt", "passwd.txt"},
		{"unsafe characters replaced", `bad;name{}*?"<>|`, "audit_report.txt", ".txt", "bad_name________.txt"},
		{"only unsafe characters falls back to default", ";;;", "audit_report.txt", ".txt", "audit_report.txt"},
		{"leading/trailing dots and spaces trimmed", "  .hidden.  ", "audit_report.txt", ".txt", "hidden.txt"},
		{"lone dot falls back to default", ".", "audit_report.txt", ".txt", "audit_report.txt"},
		{"very long name is truncated", stringsRepeat("a", 200), "audit_report.txt", ".txt", stringsRepeat("a", maxDownloadNameLen) + ".txt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeDownloadName(c.raw, c.def, c.ext); got != c.want {
				t.Errorf("sanitizeDownloadName(%q, %q, %q) = %q, expected %q", c.raw, c.def, c.ext, got, c.want)
			}
		})
	}
}

// TestSanitizeDownloadNameNeverContainsPathSeparatorsOrQuotes locks in the
// property the rest of the package relies on: whatever the input, the
// sanitized result never contains a character that could let it escape a
// quoted Content-Disposition filename value or be reinterpreted as a
// filesystem path. It is never fed back into a filesystem path anywhere
// in this package to begin with — this test only guards the header value
// itself.
func TestSanitizeDownloadNameNeverContainsPathSeparatorsOrQuotes(t *testing.T) {
	inputs := []string{
		"../../etc/passwd", "a/b/c", "/", "//", "a/../../b",
		"..%2f..%2fetc%2fpasswd", "a\x00b", "\n\r\t",
		`..\..\..\windows\system32\config`, `a"b\c`,
	}
	for _, in := range inputs {
		got := sanitizeDownloadName(in, "default.txt", ".txt")
		for _, r := range got {
			if r == '/' || r == '\\' || r == '"' {
				t.Errorf("sanitizeDownloadName(%q) = %q contains an unsafe character %q", in, got, r)
			}
		}
	}
}

func TestContentDispositionAttachment(t *testing.T) {
	got := contentDispositionAttachment("my-report.txt")
	want := `attachment; filename="my-report.txt"`
	if got != want {
		t.Errorf("contentDispositionAttachment = %q, expected %q", got, want)
	}
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
