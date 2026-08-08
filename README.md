# srxtool-go

**Hardening audit, inventory, and rule management for Juniper SRX
configurations — internal tool, no external dependency.**

A full Go rewrite of a Python toolbox (`srxtool.py` / `srxaudit.py` /
`app.py`), with rule #1 being to **never diverge** from the original's
functional behavior: same audit checks, same codes, same severities,
same inventory model, same generated migration commands. Every port was
verified against Python **actually run**, not read from memory — see
[`docs/09-migration-et-parite.md`](docs/09-migration-et-parite.md) for
the details, function by function.

```
go build ./...      # zero external dependency, stdlib only
go vet ./...         # clean
go test ./... -race   # clean
```

## What it does

Three tools chained on the same SRX configuration (whatever format is
supplied — raw `show configuration`, `| display set`, or
`| display xml`: detection is automatic):

| Tool | Role | Read-only? |
|---|---|---|
| **Inventory** | VLAN → zone → addresses → policies classification | ✅ yes |
| **Audit** | ~24 fixed hardening checks, findings sorted by severity, suggested fixes | ✅ yes |
| **Rules** | Detection of IP-named objects (rename) + removal of never-matched rules (cleanup) | ⚠️ the only `set`/`delete` command generator |

**No command is ever pushed to the device.** Each tool only reads a conf
and writes results (JSON, text, XLSX, `set`/`delete` commands) that the
user reviews and loads themselves, always paired with an exact rollback
when commands are generated.

Accessible **as a pure command line** (`cmd/srxtool` — equivalent of the
original Python scripts, no server, no Docker required) or via an HTTP
server + embedded web frontend (`cmd/server`), designed to run
**locally, with no authentication** — the only security boundary is the
network (`127.0.0.1` only, see [`docker-compose.yml`](docker-compose.yml)).

## Quick start

The full runbook (pure CLI, local server, Docker, and how to run them
side by side — every command verified) is in
[`docs/RUNBOOK.md`](docs/RUNBOOK.md). In short:

```sh
# The simplest: pure CLI, zero Docker, zero server
go build -o srxtool ./cmd/srxtool
./srxtool audit config.xml --json audit.json --fix fix.set
./srxtool inventory config.xml
./srxtool rename-suggest config.xml --csv plan.csv

# If you want the web site instead
go build -o srxtool-server ./cmd/server
SRXWEB_HOST=127.0.0.1 SRXWEB_PORT=8080 ./srxtool-server
# -> http://127.0.0.1:8080

# Or via Docker (localhost only, see docker-compose.yml)
docker compose up --build
```

Server environment variables: see
[`internal/api/README.md`](internal/api/README.md#variables-denvironnement-cmdserver).

### Shell tab-completion

`scripts/srxtool-completion.bash` / `.zsh` complete subcommands, flags,
and file-path arguments for the pure-CLI binary. Add one line to your
`~/.bashrc` or `~/.zshrc`:

```sh
source /path/to/srxtool-go/scripts/srxtool-completion.bash   # bash
source /path/to/srxtool-go/scripts/srxtool-completion.zsh    # zsh
```

## Architecture

A single binary, three business domains decoupled into internal
packages (no hidden cross-dependency — each could be extracted into a
separate service with no rewrite):

```
                    ┌─────────────────────┐
                    │  internal/config     │  Junos parsing (xml/curly/set)
                    │  → unified model      │  → unified model, blocking for the rest
                    └──────────┬───────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                       ▼
┌───────────────┐   ┌───────────────────┐   ┌────────────────────┐
│  inventory      │   │  audit             │   │  rules              │
│  (read-only)     │   │  (read-only)        │   │  (generates set/delete) │
└───────┬─────────┘   └─────────┬──────────┘   └──────────┬──────────┘
        │                       │                          │
        └──────────────┬────────┴──────────┬───────────────┘
                        ▼                    ▼
                 internal/xlsx        internal/junosname
              (shared XLSX writer)  (name quoting/validation)
                        │
                        ▼
              internal/api + internal/session
              (HTTP, no authentication, path-traversal-
               hardened file sessions)
                        │
                        ▼
                      web/
              (static frontend, embedded at build time)
```

Package-by-package detail: each `internal/` folder has its own
`README.md` with the decisions made and their rationale.

```
cmd/server/            HTTP entry point — wiring, environment variables
cmd/srxtool/             pure CLI — equivalent of the Python scripts (audit/inventory/rename/cleanup), no server
cmd/configdump/           dev tool: JSON dump of the parsed model

internal/config/        task 01 — Junos parsing → unified model. Blocking for everything else.
internal/xlsx/           homegrown XLSX writer (zero dependency), shared by inventory+audit
internal/inventory/       VLAN → zone → addresses → policies
internal/audit/            catalog of fixed hardening checks
internal/junosname/         Junos name quoting/validation, shared by audit+rules
internal/rules/               rename + cleanup — the ONLY set/delete command generator
internal/session/               file sessions, hardened against path traversal
internal/api/                    HTTP handlers, middleware, routing

web/                              static frontend (vanilla HTML/CSS/JS), embedded via go:embed

reference/                         original Python — read-only, never run in production,
                                    consulted as the behavior spec
scripts/                            regenerate the golden files from reference/
testdata/fixtures/                   example confs (xml/curly/set)
testdata/golden/                      reference outputs, compared by the tests

docs/                                  task notes: parity, Docker, tests/CI
```

## Project status

| Domain | Package | Status |
|---|---|---|
| Junos parsing | `internal/config` | ✅ parity verified via golden files on 4 fixtures |
| Inventory | `internal/inventory`, `internal/xlsx` | ✅ parity verified on `inv.json` + live Python run |
| Audit | `internal/audit` | ✅ **exact** parity on `audit.json` (24 check codes) |
| Rules (rename + cleanup) | `internal/rules`, `internal/junosname` | ✅ parity verified via live Python run |
| HTTP API + sessions | `internal/api`, `internal/session` | ✅ tested under real conditions (compiled binary, queried via curl) |
| Frontend | `web/` | ✅ served by the real binary, verified |
| Docker | `Dockerfile`, `docker-compose.yml` | ⚠️ written to spec, **never built or run** (Docker unavailable during development — see [`docs/07-docker.md`](docs/07-docker.md)) |
| CI | `.github/workflows/ci.yml` | ✅ build/vet/test/fuzz verified; `govulncheck`/`gosec` not verifiable locally (see [`docs/08-tests-ci.md`](docs/08-tests-ci.md)) |

Two points are flagged honestly rather than hidden: the Docker image
never ran in the environment where the project was written, and two
security-analysis tools (`govulncheck`, `gosec`) couldn't be run for
lack of network access to `proxy.golang.org`. Both will work normally
in GitHub Actions CI or on your machine — to be verified before any
deployment, see the linked docs above.

## Before publishing to your own GitHub

The Go module currently uses a placeholder import path
(`github.com/local/srxtool-go`, see `go.mod`). Before pushing to your
repo, rename it to match the real URL:

```sh
NEW_PATH="github.com/YOUR-ACCOUNT/YOUR-REPO"
grep -rl 'github.com/local/srxtool-go' --include='*.go' . | \
  xargs sed -i "s#github.com/local/srxtool-go#${NEW_PATH}#g"
sed -i "1s#.*#module ${NEW_PATH}#" go.mod
go build ./...   # check that everything still compiles
```

## Developing

```sh
make build            # go build ./...
make test              # go test ./... -cover
make race               # go test ./... -race
make fuzz                # fuzz the conf parser (30s)
make fuzz-rules           # fuzz the CSV/hitcount parsers (40s)
make lint                 # go vet + gofmt -l
make golden                # regenerate the golden models from reference/*.py
make golden-audit           # regenerate the golden audits from reference/*.py
make docker-build             # requires Docker
```

To contribute: see [`CONTRIBUTING.md`](CONTRIBUTING.md), which details
the parity rule, the expected code style, and a list of contribution
ideas to get started.

## License

[GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later).

You're free to use, study, modify, and redistribute this software. In
exchange, derivative works must stay open under the same terms — and
since srxtool-go is server software, this obligation extends to network
use:

> **If you run a modified version of srxtool-go and let other people
> interact with it over a network, you must offer them the source code
> of your modified version.** (AGPL, section 13.)

In practice, for common cases:

| What you do | What you owe |
|---|---|
| Run it as is, on your machine or internal network | Nothing |
| Modify it and use it privately, alone | Nothing |
| Modify it and let colleagues use it on your network | The source code of your version, to those users |
| Offer it as a hosted service to customers | The source code of your version, to those users |
| Embed it in a distributed product | The whole work must be AGPL-compatible |

Analyzing your own firewall configurations with srxtool-go creates no
obligation, and the generated reports belong to you.

This license choice is deliberate: srxtool-go is server software whose
value rests on a maintained catalog of hardening checks. The AGPL
guarantees that improvements made to this catalog flow back to everyone
who depends on it. Some organizations forbid internal use of AGPL
software — if that blocks a legitimate use case for you, open an issue
to discuss it.

**Before publishing**: replace `<YOUR NAME OR ORGANIZATION>` in
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) with the actual rights
holder. If this project was developed on company time or with company
resources, the company likely holds the economic rights and must
approve publication and the license choice. `reference/` contains a
read-only copy of the original Python that served as the spec — check
its own license before republishing.
