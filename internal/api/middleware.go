// Package api exposes the 3 tools over HTTP, with no authentication —
// protected by network isolation only (localhost / internal to Docker), but
// hardened against OWASP ASVS/Top10 wherever that doesn't depend on auth
// (cf task 05).
package api

import (
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// DefaultMaxBodyBytes mirrors the limit from the old app.py (32 MB).
const DefaultMaxBodyBytes int64 = 32 << 20

// securityHeaders applies a strict CSP (no unsafe-inline — consistent with a
// static frontend with no inline JS, task 06) and the standard OWASP
// headers. No HSTS: the service is plain HTTP on localhost, HSTS on
// non-TLS HTTP doesn't make sense (cf task 05).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

// maxBody applies http.MaxBytesReader to the body of every request — not
// just the upload endpoints, as defense in depth.
func maxBody(max int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next.ServeHTTP(w, r)
	})
}

// recoverer turns any panic into a generic 500 + log entry, never a process
// crash on a malformed request.
func recoverer(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered", "recover", rec, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestLogger logs every request with a server-side correlation ID —
// never returned in detail to the client (cf cross-cutting principles:
// generic messages client-side, detailed logs server-side).
func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := randomID()
		ctx := withRequestID(r.Context(), rid)
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r.WithContext(ctx))
		logger.Info("request", "rid", rid, "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// rateLimiter: simple per-source-IP token bucket, applied to the expensive
// endpoints (/api/analyze, /api/rules/*) — even locally, a buggy script or
// poorly controlled concurrent usage can saturate the CPU (parsing + XLSX
// generation isn't free).
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
}

type bucket struct {
	tokens   float64
	lastFill time.Time
}

func newRateLimiter(ratePerSecond, burst float64) *rateLimiter {
	return &rateLimiter{buckets: map[string]*bucket{}, rate: ratePerSecond, burst: burst}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[key]
	now := time.Now()
	if !ok {
		b = &bucket{tokens: rl.burst, lastFill: now}
		rl.buckets[key] = b
	}
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastFill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r)
		if !rl.allow(key) {
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusTooManyRequests, "too many requests, try again in a few seconds")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomID() string {
	// No need for cryptographic unpredictability here (a log-correlation
	// identifier, not a secret): a timestamped counter is enough, and it
	// avoids a crypto/rand dependency for something this mundane.
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}
