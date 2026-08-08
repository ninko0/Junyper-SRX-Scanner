package api

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/local/srxtool-go/internal/session"
)

// Server groups the state shared by the handlers. Deliberately kept as a
// simple struct (no multiple interfaces, no DI framework): this is a
// single-user internal tool.
type Server struct {
	Sessions *session.Manager
	Logger   *slog.Logger
	MaxBytes int64
	// Static serves the frontend (task 06). nil => no static route
	// registered (the API layer's tests don't need it).
	Static    fs.FS
	analyzeRL *rateLimiter
	rulesRL   *rateLimiter
}

// NewServer builds the server with its default limits.
func NewServer(sessions *session.Manager, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		Sessions: sessions,
		Logger:   logger,
		MaxBytes: DefaultMaxBodyBytes,
		// 1 request/2s steady state, burst of 5: parsing + XLSX generation
		// isn't free (cf task 05).
		analyzeRL: newRateLimiter(0.5, 5),
		rulesRL:   newRateLimiter(0.5, 5),
	}
}

// Router builds the complete http.Handler, middlewares included.
//
// Explicit per-method routing (Go 1.22 stdlib ServeMux, "METHOD /path"
// patterns): no implicit dangerous HTTP method, 405 on everything else
// (ServeMux's default behavior with method-prefixed patterns). "Pure
// stdlib" choice over chi (cf task 05's open decision): the routes are
// simple (no complex nested groups), an external router wouldn't add
// anything here.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/analyze", s.handleAnalyze)
	mux.HandleFunc("GET /api/sessions/{sid}/inventory/report.txt", s.handleSessionFile("inventory", "report.txt"))
	mux.HandleFunc("GET /api/sessions/{sid}/inventory/report.json", s.handleSessionFile("inventory", "report.json"))
	mux.HandleFunc("GET /api/sessions/{sid}/inventory/report.xlsx", s.handleSessionFile("inventory", "report.xlsx"))
	mux.HandleFunc("GET /api/sessions/{sid}/audit/report.txt", s.handleSessionFile("audit", "report.txt"))
	mux.HandleFunc("GET /api/sessions/{sid}/audit/report.json", s.handleSessionFile("audit", "report.json"))
	mux.HandleFunc("GET /api/sessions/{sid}/audit/report.xlsx", s.handleSessionFile("audit", "report.xlsx"))
	mux.HandleFunc("GET /api/sessions/{sid}/audit/fix.set", s.handleSessionFile("audit", "fix.set"))

	mux.HandleFunc("POST /api/rules/rename/suggest", s.handleRenameSuggest)
	mux.HandleFunc("POST /api/rules/rename/apply", s.handleRenameApply)
	mux.HandleFunc("POST /api/rules/cleanup", s.handleCleanup)

	mux.HandleFunc("GET /healthz", s.handleHealthz)

	if s.Static != nil {
		// Static frontend (task 06): index.html at the root, everything
		// else served by exact file name — never a directory listing,
		// never a path built from user input (http.FileServer over an
		// embedded fs.FS, not the disk).
		fileServer := http.FileServer(http.FS(s.Static))
		mux.Handle("GET /style.css", fileServer)
		mux.Handle("GET /app.js", fileServer)
		mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			f, err := s.Static.Open("index.html")
			if err != nil {
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
			defer f.Close()
			_, _ = io.Copy(w, f)
		})
	}

	var h http.Handler = mux
	h = maxBody(s.MaxBytes, h)
	h = securityHeaders(h)
	h = requestLogger(s.Logger, h)
	h = recoverer(s.Logger, h)
	return h
}

// NewHTTPServer builds an *http.Server with explicit timeouts — never Go's
// defaults, which are infinite (cf task 05).
func (s *Server) NewHTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Router(),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second, // leaves time for XLSX generation
		IdleTimeout:       60 * time.Second,
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
