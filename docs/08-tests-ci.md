# Tests, fuzzing & CI (task 08)

## What exists

- **Unit tests per package** — written along the way through tasks
  01-05 (see each package's README for details). The whole repo passes
  `go test ./... -race -cover`.
- **Golden files** — `testdata/golden/`: `inv.json`, `audit.json`,
  `rename-plan.csv` (supplied with the project) + `model-*.json` /
  `audit-*.json` (regenerated from `reference/*.py` by
  `scripts/gen_golden_model.py` and `scripts/gen_golden_audit.py`).
- **Fuzzing** — `internal/config/fuzz_test.go` (`FuzzParse`, the conf
  itself, the most critical surface), `internal/rules/fuzz_test.go`
  (`FuzzParseHitcount`, `FuzzReadRenameMapCSV` — the hit-count export
  and the manually filled-in CSV are also unreliable inputs). Starting
  corpus = real fixtures/scenarios. They verify a single property: no
  panic, whatever the input. ~90k cumulative runs in 30s across
  `rules`'s two fuzzers, no failure.
- **HTTP integration tests** — `internal/api/api_test.go`, one test per
  route via `net/http/httptest`, including the explicit path-traversal
  test required by this task (`TestPathTraversal`) and a size-overrun
  test (`TestMaxBodySize`).
- **`Makefile`** — targets `build`, `test`, `race`, `fuzz`, `lint`,
  `vuln`, `sec`, `golden`, `golden-audit`, `docker-build`, `clean`.
- **`.github/workflows/ci.yml`** — build, vet, gofmt, tests with the
  race detector, short fuzzing (30s), `govulncheck`, `gosec`
  (informative, `continue-on-error` until there's a baseline of
  accepted findings), then a Docker job that builds the image and
  checks that `/healthz` responds.

## Honest limitation of this environment

`govulncheck` and `gosec` install via `go run module@latest`, which goes
through `proxy.golang.org` — **absent from this sandbox's network
allowlist** (`403 Forbidden: Host not in allowlist`). Verified by
actually trying the command, not assumed. These two steps therefore
**could not be run here**; they will run normally in GitHub Actions,
which has full network access. Nothing in the code depends on their
result — only remote CI can confirm they pass.

Same as for Docker (task 07): this is a limitation of the development
environment, not of the project — to be verified on the first push to a
real repository.

## What's still missing for full coverage of task 08

- `staticcheck` isn't in the pipeline (only `go vet` + `gofmt`) — same
  network limitation as `govulncheck`/`gosec` (see above).
