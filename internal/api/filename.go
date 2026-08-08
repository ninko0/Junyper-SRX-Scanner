package api

import (
	"path/filepath"
	"regexp"
	"strings"
)

// downloadNameRE matches every character NOT allowed in a client-chosen
// download base name. Deliberately narrow (letters, digits, space,
// underscore, dot, hyphen): this string is NEVER used to build a
// server-side filesystem path or to look up a session file — see
// handleSessionFile / handleRenameSuggest, where the actual content
// served always comes from a fixed, whitelisted internal name
// (session.Manager.ReadPath's `allowed` map). sanitizeDownloadName only
// ever feeds the Content-Disposition header of a response whose body is
// already determined.
var downloadNameRE = regexp.MustCompile(`[^A-Za-z0-9 _.-]`)

// maxDownloadNameLen caps the sanitized base name length — comfortably
// under any filesystem or HTTP header length limit, and short enough to
// stay readable.
const maxDownloadNameLen = 80

// sanitizeDownloadName turns a client-supplied "rename before download"
// hint into a safe file name for the Content-Disposition header:
//
//   - only the final path element is kept (filepath.Base), so a
//     traversal attempt like "../../etc/passwd" collapses to "passwd"
//     and can never reach outside the header value;
//   - any extension the client typed is discarded — the real one
//     (`ext`, derived from the fixed, server-chosen `kind`, never from
//     client input) is always forced back on, so a renamed download can
//     never claim a different file type than what's actually served;
//   - anything outside a conservative charset is replaced with "_";
//   - an empty or fully-stripped result falls back to `def` (an
//     already-safe, server-chosen default file name, extension
//     included).
func sanitizeDownloadName(raw, def, ext string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	raw = filepath.Base(raw)
	if raw == "." || raw == string(filepath.Separator) {
		return def
	}
	raw = strings.TrimSuffix(raw, filepath.Ext(raw))
	raw = downloadNameRE.ReplaceAllString(raw, "_")
	raw = strings.Trim(raw, ". ")
	if len(raw) > maxDownloadNameLen {
		raw = raw[:maxDownloadNameLen]
		raw = strings.TrimRight(raw, ". ")
	}
	if !hasAlphanumeric(raw) {
		// A name that sanitized down to nothing meaningful (e.g. only
		// separators/punctuation) is worse than useless — fall back to
		// the safe default rather than hand the client an all-underscore
		// file name.
		return def
	}
	return raw + ext
}

func hasAlphanumeric(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return true
		}
	}
	return false
}

// contentDispositionAttachment builds a Content-Disposition header value
// for a file name already restricted by sanitizeDownloadName's charset
// (no quote, backslash, or control character can reach this point, so a
// bare quoted value is safe here).
func contentDispositionAttachment(filename string) string {
	return `attachment; filename="` + filename + `"`
}
