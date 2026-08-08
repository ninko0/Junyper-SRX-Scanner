// Package session carries app.py's result-file session logic (around
// L102-146), hardened for a deployment with no authentication (see task
// 05, cross-cutting principles from MD 00):
//
//   - full UUID v4 session identifier (no truncation to 12 hex chars like
//     in Python): with no auth layered on top, the session identifier is
//     a capability secret, it must keep its full entropy.
//   - strict validation on read: sid against a fixed-length hex regex,
//     fname against an explicit whitelist — never an arbitrary name taken
//     from the URL.
//   - containment: the resolved path (symlinks included) must stay under
//     BaseDir. This is exactly app.py's historical flaw
//     (`os.path.basename("..") == ".."`, bypassable) — here we never
//     trust filepath.Base alone.
//   - no session ownership check (no auth for now): explicitly documented,
//     to be reintroduced before any exposure beyond localhost if auth is
//     added later.
package session

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ErrInvalidID / ErrInvalidFile / ErrNotFound: sentinel errors, never
// accompanied by path details on the client side (see cross-cutting
// principles).
var (
	ErrInvalidID   = errors.New("invalid session identifier")
	ErrInvalidFile = errors.New("file name not allowed")
	ErrNotFound    = errors.New("session or file not found")
)

// sidRE: UUID v4 with no dashes (32 hex chars), a format deliberately
// simple to validate with a strict regex.
var sidRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Manager manages the lifecycle of session directories under BaseDir.
type Manager struct {
	BaseDir string
	TTL     time.Duration

	mu         sync.Mutex
	lastSweep  time.Time
	sweepEvery time.Duration
}

// NewManager creates BaseDir (if needed) and returns a ready-to-use
// Manager. ttl<=0 disables automatic cleanup.
func NewManager(baseDir string, ttl time.Duration) (*Manager, error) {
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, err
	}
	return &Manager{BaseDir: abs, TTL: ttl, sweepEvery: time.Minute}, nil
}

// newID generates a UUID v4 identifier with no dashes, 32 hex chars —
// full entropy, never derived from user input (see MD 00, cross-cutting
// principles).
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x", b[:]), nil
}

// Create creates a new session directory and returns its identifier.
func (m *Manager) Create() (id string, err error) {
	m.maybeSweep()
	id, err = newID()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(m.BaseDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return id, nil
}

// resolveDir validates sid and returns the resolved session directory,
// ensuring it stays under BaseDir even after symlink resolution.
func (m *Manager) resolveDir(sid string) (string, error) {
	if !sidRE.MatchString(sid) {
		return "", ErrInvalidID
	}
	dir := filepath.Join(m.BaseDir, sid)
	// filepath.Join + Clean already neutralizes ".." in sid, but sid is
	// constrained by sidRE anyway (no character outside [0-9a-f]): symlink
	// resolution remains the protection against a session directory that
	// was replaced by a link after the fact.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", ErrNotFound
	}
	baseReal, err := filepath.EvalSymlinks(m.BaseDir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(baseReal, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ErrInvalidID
	}
	return real, nil
}

// WritePath returns the path to write `fname` to in session `sid` — used
// only internally (fname is never supplied by a client) when generating
// results.
func (m *Manager) WritePath(sid, fname string) (string, error) {
	dir, err := m.resolveDir(sid)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fname), nil
}

// ReadPath validates (sid, fname) against an explicit whitelist and
// returns the resolved path if everything checks out. `allowed` is the
// caller context's whitelist (never a list built from the URL).
func (m *Manager) ReadPath(sid, fname string, allowed map[string]bool) (string, error) {
	if !allowed[fname] {
		return "", ErrInvalidFile
	}
	dir, err := m.resolveDir(sid)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, fname)
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", ErrNotFound
	}
	baseReal, _ := filepath.EvalSymlinks(dir)
	rel, err := filepath.Rel(baseReal, real)
	if err != nil || rel == ".." {
		return "", ErrInvalidFile
	}
	if _, err := os.Stat(real); err != nil {
		return "", ErrNotFound
	}
	return real, nil
}

// maybeSweep triggers a best-effort cleanup of expired sessions, at most
// once per minute (lazy cleanup on each creation rather than a separate
// periodic goroutine — a documented choice, see task 05).
func (m *Manager) maybeSweep() {
	if m.TTL <= 0 {
		return
	}
	m.mu.Lock()
	due := time.Since(m.lastSweep) > m.sweepEvery
	if due {
		m.lastSweep = time.Now()
	}
	m.mu.Unlock()
	if !due {
		return
	}
	entries, err := os.ReadDir(m.BaseDir)
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > m.TTL {
			_ = os.RemoveAll(filepath.Join(m.BaseDir, e.Name()))
		}
	}
}
