package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestCreateAndWriteRead(t *testing.T) {
	m := newTestManager(t)
	sid, err := m.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !sidRE.MatchString(sid) || len(sid) != 32 {
		t.Fatalf("malformed sid: %q", sid)
	}

	wp, err := m.WritePath(sid, "report.txt")
	if err != nil {
		t.Fatalf("WritePath: %v", err)
	}
	if err := os.WriteFile(wp, []byte("content"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	allowed := map[string]bool{"report.txt": true}
	rp, err := m.ReadPath(sid, "report.txt", allowed)
	if err != nil {
		t.Fatalf("ReadPath: %v", err)
	}
	data, err := os.ReadFile(rp)
	if err != nil || string(data) != "content" {
		t.Fatalf("incorrect content: %q, %v", data, err)
	}
}

func TestInvalidSessionID(t *testing.T) {
	m := newTestManager(t)
	allowed := map[string]bool{"report.txt": true}
	cases := []string{
		"..", "../etc/passwd", "%2e%2e", "not-hex-at-all-not-hex-at-all-", "",
		"' OR 1=1", "0123456789abcdef0123456789abcde", // 31 chars, too short
	}
	for _, sid := range cases {
		if _, err := m.ReadPath(sid, "report.txt", allowed); err == nil {
			t.Errorf("sid %q should have been rejected", sid)
		}
	}
}

func TestUnwhitelistedFilename(t *testing.T) {
	m := newTestManager(t)
	sid, _ := m.Create()
	wp, _ := m.WritePath(sid, "secret.txt")
	os.WriteFile(wp, []byte("x"), 0o600)

	allowed := map[string]bool{"report.txt": true} // "secret.txt" absent
	if _, err := m.ReadPath(sid, "secret.txt", allowed); err == nil {
		t.Fatal("a filename outside the whitelist should be rejected")
	}
	// Traversal attempt via the filename itself.
	for _, fname := range []string{"../secret.txt", "..%2Fsecret.txt", "/etc/passwd", "..\\secret.txt"} {
		if _, err := m.ReadPath(sid, fname, allowed); err == nil {
			t.Errorf("fname %q should have been rejected", fname)
		}
	}
}

// TestSymlinkEscapeBlocked: if the session directory is replaced by a
// symbolic link pointing outside BaseDir, reading must fail instead of
// following the link — this is app.py's historical flaw class.
func TestSymlinkEscapeBlocked(t *testing.T) {
	m := newTestManager(t)
	sid, err := m.Create()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(m.BaseDir, sid)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir()
	secretPath := filepath.Join(outside, "report.txt")
	if err := os.WriteFile(secretPath, []byte("secret outside the session"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dir); err != nil {
		t.Skipf("symlinks not supported in this environment: %v", err)
	}

	allowed := map[string]bool{"report.txt": true}
	if _, err := m.ReadPath(sid, "report.txt", allowed); err == nil {
		t.Fatal("a session directory hijacked into a symlink must never be followed")
	}
}

func TestNonexistentSession(t *testing.T) {
	m := newTestManager(t)
	allowed := map[string]bool{"report.txt": true}
	fakeSID := "00000000000000000000000000000000"[:32]
	if _, err := m.ReadPath(fakeSID, "report.txt", allowed); err == nil {
		t.Fatal("a nonexistent session should fail")
	}
}

func TestTTLCleanup(t *testing.T) {
	m, err := NewManager(t.TempDir(), 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	m.sweepEvery = 0 // sweep on every Create() to keep the test fast
	sid, err := m.Create()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(m.BaseDir, sid)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}

	// A second Create() triggers the lazy sweep.
	if _, err := m.Create(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the expired session should have been cleaned up, err=%v", err)
	}
}
