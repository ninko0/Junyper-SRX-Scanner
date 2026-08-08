# 09 — Functional parity checklist (Python → Go)

## Goal

A living document. The rewrite's goal: **avoid divergences** from
Python's behavior. Any deliberate divergence is documented here with
its rationale, never introduced silently.

## Method actually followed

Not just a code review of Go against Python: for each task, the
reference Python (`reference/*.py`) was **run directly** on the
fixtures and on scenarios built for the occasion, and compared byte for
byte or field by field against the Go output. Three tools dedicated to
this:

- `scripts/gen_golden_model.py` — replays `srxtool.parse_config()` +
  `srxaudit.parse()` (union of the two models) on the 4 fixtures →
  `testdata/golden/model-*.json`
- `scripts/gen_golden_audit.py` — replays `check_policies`/
  `check_zones`/`check_system` on the 4 fixtures →
  `testdata/golden/audit-*.json`
- Ad hoc comparisons (not embedded as tests, done once then locked in
  as inline goldens in the Go tests) for rename and cleanup, for lack
  of a pre-supplied Python golden covering these cases.

## Parsing (task 01) — ✅ complete

- [x] Identical format detection on the 4 fixtures (xml / curly / set)
      — `TestDetectFormat`, `display set` fixture added
      (`sample-display-set.txt`, hand-derived from `sample2.txt` — **not**
      a real device export, to be replaced if the opportunity arises).
- [x] `find_config_root`: `<configuration>` under `rpc-reply` —
      `TestXMLSample`.
- [x] `family inet { address }` correctly extracted.
- [x] Inline list `key [ v1 v2 v3 ];`: Python **removes** the brackets
      from the token list (doesn't "expand" them), and only for the
      first pair on the line — reproduced identically, including the
      unclosed-bracket case (`TestSplitTokens`).
- [x] `host-inbound-traffic { system-services { ... } }` → flat list, 3
      unified spellings (`TestCValuesFourForms`).
- [x] `address-book { global { ... } }` vs zone address-book — **see
      divergence #1**: Python silently loses the objects in this case,
      fixed on the Go side.
- [x] VLAN with no `l3-interface` → `zone: null`, `l3_addresses: []`
      (`TestOrphanVLAN`, fixtures' VLAN99/VLAN20).
- [x] `ConfigFormatError` raised under the same conditions
      (`TestFormatErrors`, `TestAllowEmpty`).
- [x] `warnings` identical down to the word, Python's `repr()` included
      (`pyRepr()` in Go reproduces the escaping format).
- [x] `CONF-GROUPS-INHERITANCE` / `SYS-NO-LO0-FILTER`: **don't exist**
      in the reference code (zero occurrence, verified by searching
      `reference/`) — nothing to port, these would be new features to
      decide on separately.
- [x] `defusedxml`: not applicable in Go. `encoding/xml` loads no DTD,
      resolves no external entity, rejects undeclared entities
      (`Strict=true`); `CharsetReader` restricted to UTF-8/ASCII
      (`TestMalformedXML`).

**Automated parity**: `TestGoldenModelAllFixtures` — identical across
the 4 fixtures, warnings included.

## Inventory (task 02) — ✅ complete

- [x] Zones/VLANs/policies identical across the 4 fixtures.
- [x] Orphan VLANs detected identically (`TestOrphanVLANInReport`).
- [x] `address_objects`: same objects, same `references` — compared
      directly against `inv.json` (`TestGoldenInvJSON`) **and** via a
      live Python run on `sample-show-config.txt` (not covered by the
      supplied golden).
- [x] Text report: equivalent structure (`TestReportTextStructure`).

**Decision**: homegrown XLSX writer (`internal/xlsx`), zero third-party
dependency, shared with `audit`. Workbook verified openable and correct
with `openpyxl`.

## Audit (task 03) — ✅ complete, exact parity

All 24 check codes are ported and verified:

- [x] `POL-ANY-ANY`, `POL-APP-ANY`, `POL-BROAD-ADDR`, `POL-INBOUND-ANY`,
      `POL-OBSOLETE-APP` (`OBSOLETE_APPS` table complete: telnet, ftp,
      tftp, rlogin, rsh, http, snmp, snmp-agentx, ldap),
      `POL-NOLOG-PERMIT`, `POL-NOLOG-DENY`
- [x] `ZONE-NO-SCREEN`, `ZONE-NO-SCREEN-INT`, `ZONE-SCREEN-MISSING`,
      `ZONE-HIB-ALL`, `ZONE-HIB-MGMT-EXT`, `ZONE-HIB-PROTO-ALL`
- [x] `SYS-TELNET`, `SYS-FTP`, `SYS-FINGER`, `SYS-RLOGIN`, `SYS-RSH`,
      `SYS-TFTP-SERVER`, `SYS-XNM-CLEAR-TEXT` (all 7 dynamically
      generated, `flaggedServices` table made explicit in Go so none
      gets lost in a `grep`)
- [x] `SYS-SSH-ROOT`, `SYS-SSH-V1`, `SYS-WEBMGMT-HTTP`, `SYS-NO-SYSLOG`,
      `SYS-NO-NTP`, `SYS-NO-BANNER`
- [x] `SNMP-DEFAULT-COMM`, `SNMP-RW`, `SNMP-NO-V3`
- [x] Identical sort order (severity, then check, then location) —
      `TestSortOrder`.
- [x] **Field-by-field comparison against `audit.json`: 100% identical.**
      This settles task 03's open question — `sample-show-config.txt`
      is indeed `audit.json`'s source conf, confirmed with zero gap.
- [x] `recommendation`/`reference` texts reused verbatim.

**Automated parity**: `TestGoldenAuditAllFixtures` across the 4 fixtures.

**Notable point, tested explicitly rather than discovered in
production**: the `SNMP-*` checks are skipped if `system {}` is absent
from the conf, even when `snmp {}` exists (`if m["system"] is not None:
check_system(...)` in Python).
`TestSystemAbsentSkipsSNMPToo` / `TestSystemPresentEnablesSNMP`.

`EXTERNAL_ZONE_HINT` is case-sensitive (`Untrust` ≠ `untrust`) —
`TestExternalZoneHintCaseSensitive`, kept as is.

## Rules — rename (task 04) — ✅ complete

- [x] `ip_named` — verified on 13 cases against live Python (prefixes
      `h-`/`host_`/`net_`/`addr_`, masks `/`/`_`/`-`, rejection of
      prefixes >6 letters, rejection of out-of-range octets, `name ==
      prefix` case): identical.
- [x] `app_role` — 13 roles verified (web, ssh, rdp, db, ldap, dns,
      mail, file, ntp, snmp, log), including the priority order between
      hints.
- [x] `suggest_name` — format `{zone}-{role}-{octet}` /
      `{zone}-host-{octet}` verified, including the no-zone case
      (`srv` fallback).
- [x] `--suggest` CSV — **byte-identical** to `rename-plan.csv`
      (verified with `od -c`, Python's CRLF (`csv.writer`) explicitly
      reproduced on the Go side).
- [x] `--from-map` workflow: create → repoint EVERY reference → delete
      — verified via a live Python run on a fixture with a policy +
      address-set, output **identical character for character**
      (`TestApplyRenameMapMatchesPython`).
- [x] Rollback: exact inverse, verified in the same test.
- [x] `UnsafeNameError` / `validate_new_name` — dangerous names rejected
      line by line in the CSV (the rest of the file keeps being
      processed, like in Python), `TestReadRenameMapCSVValidatesNames`.

## Rules — cleanup (task 04) — ✅ complete

- [x] `parse_hitcount` — XML and CLI text, tolerant of tag-name
      variants by suffix (like Python).
- [x] Deny/reject with 0 hits kept by default, `--include-deny` to
      force — `TestCleanupDenyKeptByDefault`.
- [x] `--only`/`--exclude` — `TestCleanupOnlyAndExclude`.
- [x] Policies with no hit-count → `Unknown`, never deleted —
      `TestCleanupUnknownNeverDeleted`.
- [x] Guard-rail banner present **in the generated text** (≥90-day
      window, counter reset, seasonality), not just in the logic.
- [x] Systematic rollback, verified via a live Python run
      (`TestCleanupMatchesPython`).

## HTTP API & sessions (task 05) — ✅ complete

- [x] Session: full UUID v4 — **see divergence #2**.
- [x] Strict sid validation (regex) + filename whitelist — actually
      stricter than the task required: the filename read from disk is
      never derived from the URL at all (fixed by the route).
- [x] Symlink-resistant anti-traversal containment —
      `TestSymlinkEscapeBlocked`.
- [x] Explicit path-traversal test (malicious sid/fname → 404) —
      `TestPathTraversal`, including following `ServeMux`'s
      path-cleanup redirects.
- [x] Size overrun rejected cleanly — `TestMaxBodySize`.
- [x] Verified under real conditions: binary compiled and started,
      queried via `curl` (`/healthz`, `/api/analyze` with a real
      fixture), clean shutdown on `SIGTERM`.

## Frontend (task 06) — ✅ complete

- [x] Severity palette identical to the XLSX export.
- [x] Zero `innerHTML` on API content (verified by searching `app.js`).
- [x] Served by the real binary, verified (`GET /`, `/style.css`,
      `/app.js` → 200 with the right content types).

## Docker (task 07) — ⚠️ not verifiable in this environment

- [x] Static build (`CGO_ENABLED=0`) verified — real, functional
      static binary.
- [ ] **Docker image never built or run**: Docker absent from the
      environment where this project was written. To be done by the
      user before any deployment (`docker compose build && docker
      compose up`, then `ss -tlnp | grep 8080`).

## CI (task 08) — ⚠️ partially verifiable in this environment

- [x] `go build`/`go vet`/`gofmt`/`go test -race` — all green locally.
- [x] Fuzzing `internal/config` (conf) and `internal/rules` (hitcount,
      rename CSV) — ~270k cumulative runs, no panic.
- [ ] **`govulncheck`/`gosec` never run here**: require
      `proxy.golang.org`, absent from the sandbox's network allowlist
      (`403 Forbidden`, verified by actually trying the command). The
      CI YAML includes them; they'll run in GitHub Actions.

## Deliberate divergences

| # | Area | Python behavior | Go behavior | Rationale |
|---|---|---|---|---|
| 1 | `address-book { global { ... } }` | global book **empty**, objects silently lost | objects and address-sets read correctly | Form produced by a standard `show configuration`. Reproduced, the bug would make rename generate a plan that doesn't repoint global references → commands breaking the conf. Locked in by `TestAddressBookForms` (task 01). |
| 2 | Session identifier | truncated to 12 hex chars | full UUID v4 (32 hex) | No authentication layered on top (localhost-only deployment): the session identifier is a capability secret, it must keep its full entropy (task 05). |
| 3 | JSON key order | dict insertion order | lexicographic order (Go maps) | No functional effect; deterministic and diffable outputs. Golden comparison is done on parsed structures, never byte for byte, for this exact reason (except `rename-plan.csv`, a CSV, where row order follows an explicit sort key on both sides). |
| 4 | Audit and rules `Run()` error | `UnsafeNameError` bubbles up via a Python exception, `sys.exit(4)` in CLI | `Run()`/`Cleanup()`/`ApplyRenameMap()` return `(result, error)` instead of just `result` as the task MDs suggested | Swallowing this error to fit a simpler signature would work against the security control itself: better to fail loudly than suggest a dangerous command (tasks 03/04). |

## Python behaviors kept despite being surprising — to be validated by the user

None was "fixed" unilaterally; documented because they have real
business impact and could be mistaken for Go bugs if they weren't.

1. **Line-by-line curly-brace parser.** A full stanza that fits on a
   single line (`system { services { ssh { root-login deny; } } }`,
   line 1 of `sample2.txt`) isn't read. Real but limited impact: a
   normally indented `show configuration` never falls into this case.
2. **`inactive:` parsed as active** (with a warning) — cautious for the
   audit, wrong for the inventory.
3. **`deactivate` ignored** in `display set` format (with a warning),
   same consequence.
4. **`SNMP-*` skipped if `system{}` is absent**, even if `snmp{}`
   exists (task 03).
5. **`EXTERNAL_ZONE_HINT` is case-sensitive** — an `Untrust` zone is
   never treated as external by this heuristic (task 03).
6. **Zone interfaces in XML**: only the `<interfaces><name>x</name>`
   form is read, not `<interfaces>x</interfaces>` (fidelity to both
   original Python parsers).

## Remaining work (no known functional blocker)

- Replace `sample-display-set.txt` with a real `| display set` export.
- Richer XML fixture (VLANs, global address-book, screens) —
  `sample.xml` supplied with the project is very thin on the XML side.
- Verify `govulncheck`/`gosec`/the Docker image in an environment with
  full network access / Docker available (see sections above).
- Dedicated fuzzing for the hitcount's XML parser (stdlib's
  `encoding/xml` has its own robustness, but not explicitly tested here
  beyond `FuzzParseHitcount`, which already covers both formats via the
  same fuzzed input).
