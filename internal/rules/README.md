# `internal/rules` — rename + cleanup (task 04)

The only one of the three tools that generates `set`/`delete` commands
meant to be loaded manually onto the device. Never executed automatically.

## Sub-capability A: rename

```go
cands := rules.DetectIPNamedObjects(inventory.Build(model), model)
rules.WriteSuggestCSV(cands, useDNS, w)               // phase 1: plan CSV
mapping, rejected, _ := rules.ReadRenameMapCSV(r)       // phase 2: read the filled-in CSV
setCmds, rollback, err := rules.ApplyRenameMap(cands, mapping)
```

Always a 3-step workflow per object — **never an in-place rename**: create
the new object → repoint EVERY reference (src/dst policies + address-set
members) → delete the old one. An exact (inverse) rollback is always
produced.

Reuses `internal/inventory` (`Build().AddressObjects`, `.Usages`) rather
than duplicating `build_address_index` — explicitly required by task 04.

## Sub-capability B: cleanup

```go
hits, _ := rules.ParseHitcount(r)   // XML or CLI text, auto-detected
res, err := rules.Cleanup(policies, hits, rules.CleanupOptions{
    Only: "old-*", Exclude: []string{"TEMP-keep"}, IncludeDeny: false,
})
// res.Candidates / .KeptDeny / .Excluded / .Unknown / .SetCommands / .Rollback
```

Guard rails kept identical:
- deny/reject at 0 hits **kept by default** (`IncludeDeny` to force)
- policies with no matching hit-count → `Unknown`, never removed
- guard-rail banner (≥ 90-day window, counter reset, seasonality)
  **in the generated text itself**, not just in the logic
- rollback always rebuilt from the classification

## Name validation

`internal/junosname` (new, shared with `internal/audit` — as in Python
where `srxaudit` imports `q()` from `srxtool`) carries `Quote()` (`q()`)
and `ValidateNewName()` (`validate_new_name()`). An invalid `new_name` in
the CSV is **rejected line by line** (message kept), not an error that
stops the whole file — identical Python behavior.

## Parity

Verified by actually running the reference Python (not just by reading the
code):
- `TestApplyRenameMapMatchesPython`: same commands, same order, same
  rollback as `srxtool.cmd_rename()`'s `--from-map` phase on a fixture with
  a policy + address-set. The comment/banner text was translated to
  English as part of backlog item 3 (English pass), so this is no longer a
  byte-for-byte match against the French Python output — the check is now
  structural/logical (same commands, same order), not textual.
- `WriteSuggestCSV` still produces a CSV in the same shape as
  `rename-plan.csv` (verified with `od -c`, CRLF included — Python's
  `csv.writer` uses `\r\n` by default, Go's `encoding/csv` doesn't,
  explicitly matched).
- `IPNamed` checked against Python's `ip_named()` on 13 cases (optional
  prefixes, `/`, `_`, `-` masks, rejecting prefixes > 6 letters, rejecting
  out-of-range octets) — identical.
- `Cleanup` checked against `cmd_cleanup()` on a two-policy scenario at
  hit-count 0 (one with log, one without) — identical deletion commands
  and rollback (modulo the English banner text, see above).

## Out of scope (per task 04)

No execution of the generated commands — this package never talks to the
network except rename's optional PTR lookup (`PTRLookup`), isolated,
non-blocking, bounded to 2s (explicit timeout, absent on the Python side,
which inherited the system DNS timeout).
