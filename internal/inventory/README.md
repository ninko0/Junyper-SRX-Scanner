# `internal/inventory` — VLAN → zone → addresses → policies (task 02)

Port of `build_address_index()`, `build_inventory_model()`,
`build_inventory_report_text()`, and `export_inventory_xlsx()`
(`srxtool.py` L745-1254).

## API

```go
res := inventory.Build(model)      // config.Model -> *Result
res.ReportText()                    // human-readable report
b, _ := res.JSON()                  // inv.json format
res.ExportXLSX(w)                   // workbook, streamable (io.Writer)
```

Read-only, no direct disk write: JSON and text are returned in memory,
the XLSX is written to an `io.Writer` supplied by the caller — the HTTP
layer (task 05) can stream directly to the response with no temporary
file.

## Decision: homegrown XLSX writer (`internal/xlsx`)

Manual implementation (zip + raw XML) rather than `excelize`. The format
produced by Python is deliberately minimal (inline strings, no formulas,
a fixed fill palette): a mature library brings nothing we couldn't
already do correctly, and zero third-party dependency reduces the
supply-chain surface — consistent with the original project's
stdlib-only spirit and with the `distroless` image targeted in task 07.
The package is shared with `audit` (task 03), eliminating the
`FILLS`/OOXML-writing duplication that existed identically in
`srxaudit.py` and `srxtool.py`.

Manually verified (`archive/zip` + `openpyxl`) that the produced
workbook opens correctly and that each tab's content matches what's
expected.

## Parity

`TestGoldenInvJSON` compares the produced JSON against `inv.json`
(golden fixture, `sample2.txt`) field by field — **identical**.

Additional verification, not embedded as a test (requires the reference
Python interpreter): direct run of `srxtool.build_inventory_model()` on
`sample-show-config.txt` — also **identical** on `vlans`, `zones`,
`policies`, `address_objects`.

## Point of attention: orphan VLANs

`TestOrphanVLANInReport` checks that the text report explicitly flags
VLAN99 (`sample2.txt`) as lacking an L3 zone — this is the warning
Python surfaces, and task 09 requires preserving it identically.

The `NO L3 ZONE` / `OK` status with color coding only exists in the
XLSX export (VLANs tab), not in the text report — faithful to Python
(`build_inventory_report_text` colors nothing, that's
`export_inventory_xlsx`'s job).

## Extension beyond parity: `application_objects` / `application_sets`

Added for `mcd-elkbased` (a separate, downstream project — see its
`docs/decisions.md`): `inv.json` now also carries `application_objects`
(custom `applications { application NAME {...} }` definitions,
protocol/destination-port) and `application_sets` (`application-set`
member lists), extracted the same way `address_objects` is — see
`config.Model.Applications`/`ApplicationSets`,
`buildApplicationObjects`/`buildApplicationSetObjects` in
`inventory.go`.

This is a deliberate **addition**, not a parity target: the reference
Python `srxtool.py` never extracted this (it only ever needed application
*names* for the policy view, never their port), so there is no golden
value to match here — `TestGoldenInvJSON` only compares
`vlans`/`zones`/`policies`/`address_objects`, deliberately excluding these
two new keys. Junos's *predefined* applications (`junos-https`,
`junos-ssh`...) are never in this list either — they're wired into the
OS, not declared in the configuration; a small, explicitly non-exhaustive
table of the common ones lives on the consumer side
(`mcd-elkbased/internal/inventory`), not here — this package only ever
extracts what a configuration actually declares.

## Out of scope (per task 02)

No detection of IP-named objects (`ip_named`/`suggest_name`): that
belongs to `internal/rules` (task 04), which will import `inventory` to
reuse `Build()` rather than re-duplicating `build_address_index`.
