# Multi-vendor architecture (backlog item 2)

## What was done

The backlog's goal is to open the tool to devices other than SRX
(FortiGate first), without inventory, audit, cleanup, or rename having
to know the original vendor. This task lays down the boundary and the
socket where a future parser plugs in — **without implementing
FortiGate**, for the reason laid out below.

### `internal/vendors` — the registry

Two minimal interfaces:

```go
type ConfigParser interface {
    Vendor() Vendor
    ParseConfig(data []byte, opts config.Options) (*config.Model, error)
}

type CounterParser interface {
    Vendor() Vendor
    ParseCounters(data []byte) (map[rules.PolicyKey]rules.HitInfo, error)
}
```

A vendor registers itself in its own `init()` via
`RegisterConfigParser` / `RegisterCounterParser` — never through a
hardcoded switch elsewhere in the repo. `DetectConfig(data, opts)` tries
every registered parser and returns the one that succeeds:

- **0 successes** → `UnrecognizedFormatError` (per-vendor detail in
  `Attempts`);
- **1 success** → the model and the matched `Vendor`;
- **2+ successes** → `AmbiguousFormatError` — this is the explicit
  fallback the backlog calls for ("automatic detection... with fallback
  to an explicit choice in case of ambiguity"), it's up to the caller to
  offer a choice via `ParseConfigAs(vendor, data, opts)`.

**Key decision: no separate detection heuristic.** `ParseConfig` itself
acts as the detector — if it fails, the input simply isn't within its
scope. Alternative considered and rejected: a distinct `Detect()` method
based on content patterns (keywords like `security {`, `config firewall
policy`, etc.). Rejected for two reasons: (1) Junos already has its
"empty model = error" guard rail (`config.assertModelNotEmpty`, see task
01), which does exactly this job — duplicating it in a separate
heuristic is needless redundancy; (2) with no real sample of the
competing format, any detection heuristic written "from the docs" would
be guessed, not verified — exactly the pitfall the backlog asks to avoid
for the common model ("Design the common model from real data, not from
documentation").

### `internal/vendors/junos` — the only implementation so far

Pure adapter, no parsing logic: delegates to `internal/config` (already
verified against the reference Python) and
`internal/rules.ParseHitcount` (see backlog item 1's fix). Zero behavior
change for current users — verified by golden tests comparing the
direct call (`config.Parse`) against the call through the registry
(`vendors.DetectConfig`) on the same configuration
(`internal/vendors/junos/junos_test.go`).

### HTTP wiring point

`internal/api/handlers.go` imports `internal/vendors/junos` for side
effect (explicit comment in the file: "adding a vendor = adding a line
here"), and the three handlers that accept a configuration upload
(`handleAnalyze`, `handleRenameSuggest`, `handleRenameApply`) call
`vendors.DetectConfig` instead of `config.Parse` directly. Observable
behavior unchanged (same error messages, same HTTP codes) — verified by
the existing `internal/api` suite, run unmodified.

### What deliberately didn't change

- **The CLI (`cmd/srxtool`)** keeps calling `config.Parse` directly.
  It's already a Junos-named, Junos-scoped tool; routing it through the
  registry wouldn't bring anything as long as a second vendor doesn't
  exist, and would have added churn with no benefit for this task. To
  reconsider once a second vendor is actually implemented and a decision
  is needed on how to expose it in the CLI (dedicated subcommand?
  auto-detection like on the HTTP side? explicit `--vendor` flag?).
- **The hit-count reconciliation (`handleCleanup`)** keeps calling
  `rules.ParseHitcount` directly, not through `CounterParser`/the
  registry. Reason: unlike `ParseConfig`, `ParseHitcount` doesn't return
  an error on unrecognized content — it returns an empty map (this is
  exactly the symptom of backlog item 1's bug, worked around for Junos
  but not a guarantee that generalizes to a second format without a
  close look). Routing counters by automatic detection on this basis
  would just have moved the risk of a silent false "0 removable" one
  notch over, not resolved it. The `CounterParser` interface exists and
  Junos registers with it (so the extension point is ready), but the
  HTTP wiring stays direct until a second counter format forces the
  question to be settled properly.
- **The hardening reference catalog (`internal/audit`)** hasn't moved:
  it stays built on `config.Model` (the common model), so it's already
  reusable as is by a future vendor that feeds the same model — but its
  content (the rules themselves) stays Junos-specific, as the backlog
  asks ("the current catalog is junos-only; a per-platform set will be
  needed, not an attempt at generalization").

## What's left to do (out of scope for this task)

The backlog sets an explicit prerequisite: **get a real (anonymized)
FortiGate conf and an equivalent counter export before writing
anything**, in order to design the common model from real data. This
data wasn't available at the time of this task — nothing FortiGate-
specific was therefore written or guessed. Once the real conf is
available:

1. Write `internal/vendors/fortigate`: a parser of FortiGate syntax
   (`config firewall policy` / `edit` / `next`...) into `config.Model`.
2. Check along the way whether `config.Model` needs to be extended to
   stay the "smallest useful common denominator" between the two
   vendors (likely candidate: address/service objects have different
   conventions at Fortinet — to confirm on the real conf, not to
   anticipate here).
3. Build the golden files by hand from the real conf (no reference
   Python on the FortiGate side — to document as such in the tests, see
   the backlog: "golden files built by hand... and documented as such").
4. Decide, with a real FortiGate counter format in hand, how to route
   `ParseCounters` by automatic detection without reintroducing backlog
   item 1's bug.
5. Start the FortiGate hardening catalog, separate from the Junos
   catalog.
