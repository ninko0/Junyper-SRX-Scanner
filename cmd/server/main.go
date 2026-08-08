// Command server is srxtool-go's single entry point (see 00-overview: one
// binary, one container, business packages decoupled internally).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/local/srxtool-go/internal/api"
	"github.com/local/srxtool-go/internal/session"
	"github.com/local/srxtool-go/web"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "query /healthz locally and exit with the matching code (for Docker HEALTHCHECK)")
	versionFlag := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("srxtool-go dev")
		return
	}

	host := envOr("SRXWEB_HOST", "0.0.0.0")
	port := envOr("SRXWEB_PORT", "8080")
	addr := host + ":" + port

	if *healthcheck {
		os.Exit(runHealthcheck(addr))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	baseDir := envOr("SRXWEB_SESSION_DIR", "/tmp/srxweb_sessions")
	ttl := envDuration("SRXWEB_SESSION_TTL", 6*time.Hour)
	maxBytes := envInt64("SRXWEB_MAX_BYTES", api.DefaultMaxBodyBytes)

	sessions, err := session.NewManager(baseDir, ttl)
	if err != nil {
		logger.Error("unable to initialize sessions", "error", err)
		os.Exit(1)
	}

	srv := api.NewServer(sessions, logger)
	srv.MaxBytes = maxBytes
	srv.Static = web.Assets
	httpServer := srv.NewHTTPServer(addr)

	go func() {
		logger.Info("starting", "addr", addr, "session_dir", baseDir)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("unexpected shutdown", "error", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}

// runHealthcheck makes an internal request to /healthz — necessary in a
// distroless image with no curl/wget available for the Docker HEALTHCHECK
// (see task 07).
func runHealthcheck(addr string) int {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
