# Contributing to srxtool-go

Thanks for your interest. This project has one constraint that
overrides everything else: **it must not diverge** from the original
Python's behavior (`reference/srxtool.py`, `reference/srxaudit.py`,
`reference/app.py`), except for deliberate, documented, justified
divergences. Before proposing a change, read
`docs/09-migration-et-parite.md` — it's the project's living parity
checklist, and the format to follow if your contribution touches
functional behavior.

## Guiding principle

> A security audit that returns a result slightly different from the
> old tool is worse than useless: nobody knows whether the gap comes
> from a Go bug, a Python bug, or an actual conf change.

Concretely, for any PR that touches `internal/config`, `internal/audit`,
`internal/inventory`, or `internal/rules`:

1. **Don't work from memory on Python's behavior** — actually run
   `reference/*.py` on the case you're interested in and compare the
   output. `scripts/gen_golden_model.py` and `scripts/gen_golden_audit.py`
   show how.
2. If you find a gap with the current Go version: determine whether
   it's a Go bug (to fix) or a Python behavior deliberately not
   reproduced (to document in `docs/09-migration-et-parite.md`'s table,
   with a rationale).
3. If you're fixing a bug **in the original Python** rather than
   reproducing it (like the silent loss of objects in
   `address-book { global { ... } } }`, see divergence #1): explain why
   the cost of reproducing the bug outweighs the benefit of fidelity,
   and add an entry to the divergence table.
4. Add a test that would **lock in the regression** if someone
   accidentally reverted your fix.

## Directory layout, to find your way around quickly

```
cmd/server/            HTTP entry point — wiring, environment variables
cmd/srxtool/             pure CLI (audit/inventory/rename/cleanup), no server or Docker required
cmd/configdump/           dev tool: JSON dump of the parsed model, useful for debugging a parse

internal/config/        task 01 — Junos parsing (xml/curly/set) → unified model. Blocking for everything else.
internal/xlsx/           homegrown XLSX writer, shared by inventory and audit
internal/inventory/       task 02 — VLAN → zone → addresses → policies, read-only
internal/audit/            task 03 — catalog of fixed hardening checks
internal/junosname/         Junos name quoting/validation, shared by audit and rules
internal/rules/               task 04 — rename + cleanup, the ONLY set/delete command generator
internal/session/               task 05 — file session management, hardened against traversal
internal/api/                    task 05 — HTTP handlers, middleware, routing

web/                              task 06 — static frontend (vanilla HTML/CSS/JS), embedded via go:embed

reference/                         original Python — READ-ONLY, never run in production,
                                    never modified in a PR (except to fix a transcription
                                    error from the originally uploaded files)
scripts/                            regenerate the golden files from reference/
testdata/fixtures/                   example confs (xml/curly/set)
testdata/golden/                      reference outputs, compared by the tests

docs/                                  task notes: parity (09), Docker (07), tests/CI (08)
```

Each package has its own `README.md` with the decisions made and their
rationale — start there before diving into the code.

## Expected code style

- **Every Go function ported from the reference Python explicitly cites
  its source** in a comment (`// port of check_zones() (srxaudit.py
  L423-504)`) — not just "logic similar to Python", the precise line.
  This lets anyone check fidelity at a glance without guessing.
- Comments are in English, consistent with the rest of the project
  (translated from the original team's French as part of the project's
  full English translation — see the backlog). Go identifier names stay
  in English (standard Go convention).
- No external dependency without a good reason written in a decision
  comment (see `internal/xlsx/xlsx.go` for an example of what's
  expected: the "homegrown vs. mature lib" choice is justified there,
  not just made).
- `gofmt` and `go vet` must be clean. Run `make lint` before proposing a
  PR.

## Before opening a PR

```sh
make lint            # go vet + gofmt -l
make test             # go test ./... -cover
make race              # go test ./... -race
make fuzz               # if you touch internal/config
make fuzz-rules          # if you touch internal/rules (CSV, hitcount)
```

If your PR touches parsing, audit, inventory, or rules, regenerate and
check the golden files:

```sh
make golden          # internal/config
make golden-audit     # internal/audit
git diff testdata/golden/   # should be empty, unless you're deliberately
                             # introducing a documented divergence
```

## Contribution ideas to get started

Listed with their level, drawn from `docs/09-migration-et-parite.md`:

- **Easy** — replace `testdata/fixtures/sample-display-set.txt`
  (hand-derived) with a real `show configuration | display set` export
  from a test device.
- **Easy** — enrich `testdata/fixtures/sample.xml`, which today covers
  neither VLANs, nor global address-books, nor screens on the XML side.
- **Medium** — dedicated fuzzer for the hit-count XML parser
  (`internal/rules.ParseHitcount`), beyond what `FuzzParseHitcount`
  already covers.
- **Medium** — verify `govulncheck`/`gosec` locally (requires network
  access to `proxy.golang.org`, which wasn't available in the
  environment where the project was written) and address any findings.
- **Big chunk** — actually build and run the Docker image (never done
  for lack of available Docker during initial writing, see
  `docs/07-docker.md`), and automate the `ss -tlnp | grep 8080`
  verification described in that same document.

## License

The project is under [AGPL-3.0-or-later](LICENSE). Every contribution
is subject to the same terms. If you add a new source file, the header
to use is in [`NOTICE`](NOTICE) — not mandatory file by file while the
project stays small (the root notice covers the whole work), but
welcome.

## Reporting a bug

Specify whether the disagreement is with the **current Go**'s behavior
or with the **reference Python**'s behavior — both are useful to know,
but the handling differs (direct fix vs. a divergence decision to
document). A minimal fixture that reproduces the gap helps enormously.
