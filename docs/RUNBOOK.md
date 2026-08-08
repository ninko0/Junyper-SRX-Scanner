# Runbook — srxtool-go: pure CLI, Docker, and both side by side

Two completely independent ways to run this project:

| | What it is | What you need |
|---|---|---|
| **CLI (`srxtool`)** | A single binary, no server, no network, no graphical interface — exactly like the original Python scripts | Go 1.22+ to compile it |
| **Server + web site** | An HTTP server with a browser UI, or scriptable via `curl` | Go, or Docker |

**If you just want to analyze a conf from the command line, you don't
need Docker at all — go straight to section 1.**

Every command below was actually verified while writing this document
(build, run, outputs pasted as-is) — **except the Docker section
(section 3)**, where Docker wasn't available in the development
environment. The Docker syntax is correct and consistent with
`Dockerfile`/`docker-compose.yml`, but test it once before relying on it
in production.

---

## 1. Pure CLI (`srxtool`) — the lightest path

A single Go binary, no dependency, no network port opened. Five
subcommands, each equivalent to a call into the original Python.

### 1.1 Build

```sh
go build -o srxtool ./cmd/srxtool
./srxtool --help
```

### 1.2 Audit — the most used

```sh
# Text report on stdout, nothing else
./srxtool audit config.xml

# + output files (JSON, XLSX, set/delete fixes)
./srxtool audit config.xml --json audit.json --xlsx audit.xlsx --fix fix.set

# Filter by minimum severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
./srxtool audit config.xml --min-severity HIGH
```

Real output (verified on a project fixture):

```
========================================================================
SRX HARDENING AUDIT — REMEDIATIONS
========================================================================
Detected source format: curly
Total: 10   [CRITICAL:1  HIGH:9  MEDIUM:0  LOW:0  INFO:0]

[CRITICAL] POL-ANY-ANY — Full any/any/any permit
    where  : security policies from-zone trust to-zone untrust policy allow-any
    reco   : Restrict source, destination, and application to the strict minimum needed...
```

### 1.3 Inventory

```sh
./srxtool inventory config.xml
./srxtool inventory config.xml --json inv.json --xlsx inv.xlsx
```

### 1.4 Rename — IP-named objects (2 steps, like Python)

```sh
# Step 1: generate the plan
./srxtool rename-suggest config.xml --csv rename-plan.csv
# -> fill in the "new_name" column in rename-plan.csv (spreadsheet or editor)

# Step 2: generate the commands once the CSV is filled in
./srxtool rename-apply config.xml --map rename-plan.csv \
    --set rename.set --rollback rename-rollback.set
```

### 1.5 Cleanup — 0-hit-count rules

```sh
# Needs the inventory JSON (step 1.3) + an SRX hit-count export
./srxtool cleanup --inventory inv.json --hitcount hitcount.xml \
    --set cleanup.set --rollback cleanup-rollback.set

# Filter / protect certain rules
./srxtool cleanup --inventory inv.json --hitcount hitcount.xml \
    --only "old-*" --exclude "TEMP-keep" --include-deny
```

### 1.6 A note on argument order

Both orders work (verified by test,
`TestInventoryFileOrderDoesNotMatter`):

```sh
./srxtool audit config.xml --json out.json      # file before the flags
./srxtool audit --json out.json config.xml      # flags before the file
```

### 1.7 Scripting a bulk analysis

```sh
for f in confs/*.xml confs/*.txt; do
  echo "=== $f ==="
  ./srxtool audit "$f" --json "results/$(basename "$f").json" > /dev/null
done
```

### 1.8 `configdump` — debug tool (rarer usage)

Dumps the raw parsed model (not an audit/inventory report), useful for
debugging a parse that's misbehaving:

```sh
go build -o configdump ./cmd/configdump
./configdump config.xml | jq '.zones'
```

---

## 2. Server + web site, without Docker

The same business code, exposed over HTTP with a browser UI — useful if
several people need to use it without installing Go, or if you prefer
clicking over typing commands.

```sh
go build -o srxtool-server ./cmd/server
./srxtool-server -version
# -> srxtool-go dev

SRXWEB_HOST=127.0.0.1 SRXWEB_PORT=8080 SRXWEB_SESSION_DIR=/tmp/srxweb_sessions \
  ./srxtool-server
```

Open `http://127.0.0.1:8080` in a browser, or drive it from the command
line without a browser:

```sh
curl -s -F "conf=@config.xml" http://127.0.0.1:8080/api/analyze | tee /tmp/analyze.json
SID=$(python3 -c "import json;print(json.load(open('/tmp/analyze.json'))['session_id'])")
curl -s "http://127.0.0.1:8080/api/sessions/$SID/audit/report.txt"
```

Environment variables (see also `internal/api/README.md`):

| Variable | Default | Role |
|---|---|---|
| `SRXWEB_HOST` | `0.0.0.0` | listen interface |
| `SRXWEB_PORT` | `8080` | port |
| `SRXWEB_SESSION_DIR` | `/tmp/srxweb_sessions` | session directory |
| `SRXWEB_SESSION_TTL` | `6h` | best-effort cleanup |
| `SRXWEB_MAX_BYTES` | `33554432` (32 MB) | request size limit |

`-healthcheck` queries `/healthz` locally and exits with the matching
code:

```sh
./srxtool-server -healthcheck; echo "return code: $?"
```

---

## 3. Server + web site, via Docker

Useful if you don't want to install Go at all, or for a reproducible
deployment.

### 3.0 If `docker compose up --build` returns `unknown flag: --build`

That's the sign that **the Compose v2 plugin isn't installed** —
Debian/Kali's `docker.io` package doesn't bundle it by default. Check:

```sh
docker compose version
```

If that fails, three options:

**a) Install the plugin (recommended)**

```sh
sudo apt update && sudo apt install docker-compose-plugin
docker compose version      # should respond correctly now
```

**b) Use the older `docker-compose` binary (with a dash)**

```sh
sudo apt install docker-compose
docker-compose up --build   # NO space between docker and compose
```

**c) Bypass Compose entirely** — exact manual translation of
`docker-compose.yml` into `docker build` + `docker run`:

```sh
docker build -t srxtool-server:local .

docker run -d \
  --name srxtool \
  -p 127.0.0.1:8080:8080 \
  -e SRXWEB_HOST=0.0.0.0 \
  -e SRXWEB_PORT=8080 \
  -e SRXWEB_SESSION_DIR=/tmp/srxweb_sessions \
  -e SRXWEB_SESSION_TTL=6h \
  --read-only \
  --tmpfs /tmp/srxweb_sessions:size=256m,mode=1700,uid=65532,gid=65532 \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --memory 512m \
  --pids-limit 128 \
  --restart unless-stopped \
  --health-cmd "/srxtool-server -healthcheck" \
  --health-interval 30s --health-timeout 3s --health-retries 3 \
  srxtool-server:local

# stop / cleanup for this path:
docker stop srxtool && docker rm srxtool
```

### 3.1 Build and start (once `docker compose` is available)

```sh
docker compose up --build
```

The service listens only on `127.0.0.1:8080` (see the comment in
`docker-compose.yml` — without the `127.0.0.1:` prefix, Docker would
expose the service to the whole network reachable from the machine).

In the background:

```sh
docker compose up --build -d
docker compose logs -f
```

### 3.2 Check that it's running

```sh
curl -s http://127.0.0.1:8080/healthz
# -> ok

ss -tlnp | grep 8080
# should show 127.0.0.1:8080, NEVER 0.0.0.0:8080
```

### 3.3 Stop / clean up

```sh
docker compose down
docker compose down --rmi local   # + removes the locally built image
```

### 3.4 After a code change

```sh
docker compose up --build
```

### 3.5 Docker troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `unknown flag: --build` | Compose v2 plugin missing (common on Kali/Debian) | see section 3.0 |
| `port is already allocated` | something already listening on 8080 (see section 4.2) | change the host port in `docker-compose.yml`, or stop the other process |
| Healthcheck never `healthy` | `SRXWEB_HOST` misconfigured, or slow startup | `docker compose logs`; check `SRXWEB_HOST=0.0.0.0` in the compose file |
| `read-only file system` at startup | write path not covered by the `tmpfs` | check that `SRXWEB_SESSION_DIR` exactly matches the path mounted as `tmpfs` |
| `permission denied` reading/writing session files, or `-healthcheck`/`/api/analyze` failing silently despite the container being `healthy` | the `tmpfs` mount has no `uid`/`gid`, so it's owned by `root:root` with `mode=1700` (owner-only) — the `nonroot` user (uid 65532 in `distroless/static-debian12:nonroot`) is locked out of its own session directory | make sure the `tmpfs` line includes `uid=65532,gid=65532` (already set in `docker-compose.yml`; add it too if you're running a manual `docker run`, see section 3.0.c) |

---

## 4. Running several of these paths side by side

The CLI (`srxtool`, `configdump`) never opens a network port: it can run
at the same time as anything else with no special configuration.

### 4.1 Common case: server for interactive use, CLI for scripting

```sh
# Terminal A — the web service runs continuously (Docker or local, doesn't matter)
docker compose up -d

# Terminal B — one-off or scripted analyses, without touching the server
go build -o srxtool ./cmd/srxtool
./srxtool audit my-conf.txt --json /tmp/out.json
```

### 4.2 Two servers at once (comparing a local build against the Docker image)

You need two different ports, otherwise they fight over 8080:

```sh
# Terminal A — Docker on its usual port
docker compose up -d          # -> 127.0.0.1:8080

# Terminal B — local build on a different port
go build -o srxtool-server ./cmd/server
SRXWEB_HOST=127.0.0.1 SRXWEB_PORT=8090 SRXWEB_SESSION_DIR=/tmp/srxweb-dev \
  ./srxtool-server               # -> 127.0.0.1:8090

curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8090/healthz
```

### 4.3 Cleanly stopping

```sh
# Ctrl-C in the local server's terminal (clean shutdown handled by
# signal.NotifyContext in cmd/server/main.go, SIGTERM/SIGINT)
docker compose down
```

---

## Quick summary

```sh
# The simplest: pure CLI, zero Docker, zero server
go build -o srxtool ./cmd/srxtool
./srxtool audit config.xml --json audit.json --fix fix.set

# If you want the web site instead
go build -o srxtool-server ./cmd/server
./srxtool-server                        # -> http://0.0.0.0:8080

# Or via Docker
docker compose up --build -d            # see section 3.0 on error
```
