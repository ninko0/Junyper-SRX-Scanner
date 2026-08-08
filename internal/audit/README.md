# `internal/audit` — hardening check catalog (task 03)

Port of `check_policies`, `check_zones`, `check_system`,
`build_report_text`, `build_findings_json`, `build_fix_text`,
`export_findings_xlsx` (`srxaudit.py`).

## API

```go
findings, err := audit.Run(model)                 // full catalog, sorted
findings = audit.FilterMinSeverity(findings, audit.High)
audit.ReportText(findings, model)                   // human-readable report
b, _ := audit.FindingsJSON(findings)                 // audit.json format
audit.FixText(findings)                              // set/delete fixes
audit.ExportXLSX(findings, w)                        // workbook, via internal/xlsx
```

## Deliberate signature divergence

`Run` returns `([]Finding, error)`, not `[]Finding` as suggested in task
03. A policy or SNMP community name containing an injection character
(`;`, brace, newline) makes `q()` fail with `UnsafeNameError` on the
Python side — and **aborts the whole audit**, as in the CLI
(`sys.exit(4)`). Swallowing this error to match the suggested signature
would defeat the point of the check itself: better an audit that fails
loudly than one that suggests a dangerous fix command.
`TestUnsafeNameAborts` locks in this behavior.

## Python behavior kept, worth noting

`check_system` is only called `if m["system"] is not None`. Consequence:
**the `SNMP-*` checks are skipped if `system {}` is absent from the
configuration, even when `snmp {}` exists elsewhere.** This isn't a
porting bug — it's the exact Python behavior — but it's surprising, so
it's explicitly tested (`TestSystemAbsentSkipsSNMPToo`,
`TestSystemPresentEnablesSNMP`) rather than silently fixed.

`EXTERNAL_ZONE_HINT` (zones considered external by name heuristic) is
compared **case-sensitively**: a zone named `Untrust` doesn't match
`untrust`. Kept as-is (`TestExternalZoneHintCaseSensitive`).

## `Tree` interface: a gap filled during this task

The system checks (`SNMP-DEFAULT-COMM`, `SNMP-RW`) need the name of an
SNMP community, carried by the header on the text side
(`community NAME { ... }`) and by a `<name>` element on the XML side. The
`Tree` interface set up in task 01 didn't expose it: `SubAll` returns
subtrees without their header. Added `Tree.SubAllNamed(key) []NamedTree`
in `internal/config` (not just `internal/audit`) so this problem, generic
to navigating any named container, gets solved once rather than worked
around locally here.

## Parity

`scripts/gen_golden_audit.py` replays `srxaudit.check_policies` +
`check_zones` + `check_system` on the 4 fixtures.
`TestGoldenAuditAllFixtures` compares the full set of findings (by
severity+check+location) and, for each, the title/recommendation/
reference/fix fields.

State at the time of the original port (task 03/09): **identical across
all 4 fixtures**, verified against the French reference Python.

Since then, backlog item 3 (English pass) translated the finding text in
`checks_policy_zone.go`/`checks_system.go` to English. The 4
`testdata/golden/audit-*.json` fixtures were regenerated from this
package's own translated output (not from Python, which stays French as
the parity oracle) — see the comment on `TestGoldenAuditAllFixtures` in
`golden_test.go`. The check remains a genuine regression guard (same
checks trigger under the same conditions, same structure), it's just no
longer a byte-for-byte comparison against Python text.

`sample-show-config.txt` matched **exactly** the project-provided
`audit.json` golden at the time of the original port — settling task 03's
open question ("identify which source conf reproduces `audit.json` —
probably something close to `sample-show-config.txt`, to confirm"): it is
indeed that one.

## XLSX writer

Reuses `internal/xlsx` (task 02) — eliminates the `FILLS`/`write_xlsx`
duplication that existed identically in `srxaudit.py` and `srxtool.py`.
Workbook verified readable by `openpyxl`.

## Out of scope (per task 03)

No generation of commands *automatically executable without review*:
`Fix`, as in Python, remains suggested text, often commented out with `#`
when a human-supplied value is required. Generating reliable,
bulk-executable commands is `internal/rules`'s job (task 04).
