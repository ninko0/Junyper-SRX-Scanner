# Containerization (task 07)

## Verification and honest limitation

**Docker isn't available in the environment where this project was
written** — impossible to actually build or run the image there. What
was verified instead, directly:

- `CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w"` (exactly
  the `Dockerfile`'s command) produces a **static binary** (`file`
  confirms `statically linked`), a necessary condition to run inside
  `distroless/static` without `libc`.
- The binary built this way starts and responds correctly (`-version`,
  `/healthz`, `/api/analyze` — see `internal/api/README.md`).
- The project has **no external dependency** (`go list -m all` only
  shows the module itself): no `go.sum` to copy, `go mod download` is a
  no-op. The `Dockerfile` copies `go.sum*` (a glob tolerant of its
  absence) rather than a hardcoded `go.sum`, so it doesn't fail on this
  case.

**To be verified by you**, with Docker available, before any deployment:
`docker compose build && docker compose up`, then `curl
localhost:8080/healthz` and `ss -tlnp | grep 8080` (should show
`127.0.0.1:8080`, never `0.0.0.0:8080`).

## Dockerfile key points

- **`distroless/static-debian12:nonroot`**: no shell, no package
  manager — reduces the attack surface compared to a full
  `alpine`/`debian` image. Already ships a non-root user by default
  (`USER nonroot:nonroot` set explicitly anyway, for clarity).
- **`CGO_ENABLED=0`**: static binary, compatible with `scratch`/
  `distroless` with no `libc`.
- **`-trimpath -ldflags="-s -w"`**: strips absolute build paths and
  debug info — avoids leaking the build filesystem's structure.

## docker-compose.yml key points

- **`"127.0.0.1:8080:8080"`** — the most important point: without the
  `127.0.0.1:` prefix, Docker defaults to mapping onto the host's
  `0.0.0.0`, exposing the service to the whole network reachable from
  the machine.
- **`read_only: true` + dedicated `tmpfs`** for `SRXWEB_SESSION_DIR` —
  the container can't write anywhere else.
- **`cap_drop: ALL` + `no-new-privileges`** — a pure Go HTTP server
  needs no Linux capability at all.
- **Healthcheck** via `/srxtool-server -healthcheck` (implemented in
  `cmd/server/main.go`, `runHealthcheck()`): necessary under
  `distroless`, which has neither `curl` nor `wget`. Makes an internal
  HTTP request to `/healthz` and exits with the matching code.

## `.dockerignore`

Excludes `reference/` (the Python spec, never executed nor needed at
runtime), `testdata/golden`, `docs/`, `scripts/` (development tools),
and the `*.md` files.
