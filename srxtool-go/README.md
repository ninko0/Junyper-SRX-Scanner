# srxtool

**Static analysis toolkit for Juniper SRX firewall configurations.**

srxtool reads an SRX configuration export and tells you what is in it, what is
wrong with it, and how to fix it — without ever touching the device. Every
output is a file you review yourself before loading anything.

> **Status: rewrite in progress.** A working Python implementation exists in
> [`reference/`](reference/) and is being rewritten in Go as a containerised
> web service. See [Project status](#project-status) and [`docs/`](docs/).

---

## Table of contents

- [Why](#why)
- [The three tools](#the-three-tools)
- [Supported input formats](#supported-input-formats)
- [Quick start](#quick-start)
- [Project status](#project-status)
- [Repository layout](#repository-layout)
- [Security model](#security-model)
- [Contributing](#contributing)
- [License](#license)

---

## Why

Firewall configurations rot. Rules outlive the projects that justified them,
address objects get named after IP addresses instead of services, `any/any/any`
permits survive audits because nobody dares touch them, and cleartext protocols
stay enabled years after the migration that was supposed to remove them.

srxtool answers three questions about an SRX config, offline and repeatably:

1. **What is actually in here?** (inventory)
2. **What is dangerous?** (audit)
3. **What should change, and what are the exact commands?** (rules)

It is deliberately read-only. It never connects to a device, never pushes
configuration, and never executes the commands it generates. The output is
text you review, then load yourself under `configure private` with
`commit check`.

## The three tools

### 1. Inventory

Builds the map: **VLAN → zone → addresses → policies**.

- Resolves L3 interfaces to zones, VLANs to subnets, address objects to the
  policies and address-sets that reference them
- Flags orphan VLANs (no L3 interface, or no zone attached) — a common symptom
  of half-finished migrations
- Outputs: text report, JSON, XLSX workbook

### 2. Audit

Runs a fixed catalogue of ~25 hardening checks and returns findings ranked by
severity (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`).

| Family | Examples |
|---|---|
| `POL-*` | `any/any/any` permits, `application any`, inbound-from-external to `any`, obsolete cleartext protocols, missing logging on permit/deny |
| `ZONE-*` | external zone without a screen, screen referenced but undefined, `host-inbound-traffic system-services all`, management services exposed externally |
| `SYS-*` | Telnet, FTP, finger, rlogin, rsh, TFTP, `xnm-clear-text`, SSH root login, SSHv1, HTTP J-Web, no remote syslog, no NTP, no login banner |
| `SNMP-*` | default `public`/`private` communities, read-write access, no SNMPv3 |

Each finding carries: severity, check code, location in the config, a
recommendation, a reference (NIST SP 800-41, CIS Juniper, NIS2, internal
policy), and — where it can be done safely — suggested `set`/`delete` commands.

Outputs: text report, JSON, XLSX (colour-coded by severity), and a
remediation file. Commands requiring a human decision are emitted commented
out, never as ready-to-paste lines.

### 3. Rules

The only tool that generates configuration changes intended to be loaded.
Two capabilities:

**Rename** — finds address objects named after raw IPs (`10.20.20.50/32`
literally used as the object name), suggests a service-oriented name derived
from the zone, the application role inferred from the policies using it, or an
optional reverse-DNS lookup. Two phases: export a CSV plan → you fill in the
`new_name` column → generate the commands.

The generated migration is always **create → repoint every reference →
delete**, never an in-place rename, so the configuration stays valid at every
intermediate step. A rollback file is always produced.

**Cleanup** — cross-references the inventory with a `show security policies
hit-count` export and proposes removing never-matched rules. Guardrails are
deliberate and on by default:

- `deny`/`reject` rules with 0 hits are **kept** (0 hits on a deny is a good
  sign, not dead weight) unless explicitly overridden
- policies with no matching hit-count entry are listed and skipped, never
  deleted
- glob include/exclude filters
- every deletion batch ships with a rollback file and a checklist of
  false-positive causes (recent counter reset, cluster failover, observation
  window shorter than seasonal traffic)

## Supported input formats

All three are auto-detected — you paste or upload whatever your export
produced:

| Format | Command on the SRX |
|---|---|
| XML | `show configuration \| display xml` |
| Curly-brace | `show configuration` |
| Set | `show configuration \| display set` |

For the cleanup tool, additionally:
`show security policies hit-count | display xml`.

## Quick start

### Python (current, working)

```bash
cd reference/
python3 srxtool.py inventory config.xml --json inv.json --xlsx inv.xlsx
python3 srxaudit.py config.xml --json audit.json --fix fixes.set
```

No third-party dependencies — Python 3 standard library only.

### Go service (target)

```bash
docker compose up --build
# then open http://127.0.0.1:8080
```

The service binds to `127.0.0.1` only. See [Security model](#security-model).

## Project status

The Python implementation in `reference/` is functional and is the behavioural
specification. The Go rewrite is planned as ten independent tasks, each
documented so it can be picked up without reading the whole history:

| Task | Scope |
|---|---|
| [00](docs/00-overview-et-architecture.md) | Architecture, stack, cross-cutting principles |
| [01](docs/01-parser-config-junos.md) | `internal/config` — Junos parser (blocking) |
| [02](docs/02-tool-inventory.md) | `internal/inventory` |
| [03](docs/03-tool-audit.md) | `internal/audit` |
| [04](docs/04-tool-rules.md) | `internal/rules` |
| [05](docs/05-api-http-et-securite-owasp.md) | HTTP API, sessions, OWASP hardening |
| [06](docs/06-frontend-statique.md) | Static frontend |
| [07](docs/07-docker-et-conteneurisation.md) | Docker, compose |
| [08](docs/08-tests-fuzzing-et-ci.md) | Tests, fuzzing, CI |
| [09](docs/09-migration-et-parite.md) | Python↔Go parity checklist |

Start with [`docs/INDEX.md`](docs/INDEX.md).

> Task documents are currently written in French, matching the working
> language of the original implementation. Translation is welcome — see
> [CONTRIBUTING.md](CONTRIBUTING.md).

## Repository layout

```
.
├── cmd/server/          # Go entrypoint (single binary)
├── internal/
│   ├── config/          # Junos parsing: XML, curly-brace, set → common model
│   ├── inventory/       # Tool 1 — read-only
│   ├── audit/           # Tool 2 — read-only
│   ├── rules/           # Tool 3 — the only command generator
│   ├── xlsx/            # Shared XLSX writer
│   ├── api/             # HTTP handlers, routing, security middleware
│   └── session/         # Per-analysis working directories
├── web/                 # Static frontend (no server-side templating)
├── docs/                # Task specifications, one per unit of work
├── reference/           # Python implementation — spec, never executed
└── testdata/
    ├── fixtures/        # Sample configs in all three formats
    └── golden/          # Expected outputs, used as regression baselines
```

Each `internal/` package is self-contained: business logic takes a parsed
model and returns data, with no I/O and no HTTP awareness. That keeps them
testable in isolation and makes it possible to split them into separate
services later without rewriting them.

## Security model

**Current deployment target: localhost only, no authentication.** The only
barrier is the network.

- The service binds to `127.0.0.1` and the compose file publishes
  `127.0.0.1:8080:8080`. Dropping that prefix would expose the service to
  every network the host can reach — the single most important line in the
  compose file.
- Container runs non-root, read-only filesystem, all capabilities dropped,
  `no-new-privileges`, with memory and PID limits.
- Session identifiers are full-entropy UUIDs. Download paths are validated
  against a whitelist, not derived from user input.
- Upload size limits, request timeouts, and rate limiting are enforced
  server-side regardless of what the client does.
- Uploaded configurations are untrusted input: the parser is fuzzed for
  robustness, and object names taken from user-filled CSVs are validated
  before ever appearing in a generated command.

Before exposing this beyond localhost you would need, at minimum:
authentication, TLS via a reverse proxy, and per-session ownership checks.
Those are deliberately not implemented yet rather than implemented badly.

**Reporting a vulnerability:** see [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow, coding conventions, and how to add a new audit check.

The single rule that matters most: **the Go implementation must not silently
diverge from the Python reference.** Any intentional behavioural difference
goes in the table at the bottom of
[`docs/09-migration-et-parite.md`](docs/09-migration-et-parite.md) with its
justification.

## License

[GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later).

You are free to use, study, modify, and redistribute this software. In
exchange, derivative works must stay open under the same terms — and because
srxtool is network server software, that obligation extends to network use:

> **If you run a modified version of srxtool and let others interact with it
> over a network, you must offer those users the source code of your modified
> version.** (AGPL section 13.)

In practice, for the common cases:

| What you do | What you owe |
|---|---|
| Run it unmodified on your own machine or internal network | Nothing |
| Modify it and use it privately, alone | Nothing |
| Modify it and let colleagues use it over your network | Source of your version, to those users |
| Offer it as a hosted service to customers | Source of your version, to those users |
| Ship a product that embeds it | The whole work must be AGPL-compatible |

Analysing your own firewall configurations with srxtool creates no obligation
of any kind, and the reports it generates are yours.

This license was chosen deliberately: srxtool is server software whose value
is a curated catalogue of hardening checks. AGPL keeps improvements to that
catalogue flowing back to everyone who relies on it. Note that some
organisations prohibit AGPL software internally — if that blocks a legitimate
use case for you, open an issue and let's discuss it.

### Contributors and copyright

Replace `srxtool contributors` in [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)
with the actual copyright holder before publishing. If this was developed on
company time or with company resources, your employer likely holds the
economic rights and must approve both the publication and the license choice.
See [`NOTICE`](NOTICE) for the per-file header to add to new source files.
