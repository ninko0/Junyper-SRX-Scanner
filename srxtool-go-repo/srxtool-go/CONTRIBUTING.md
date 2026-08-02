# Contributing to srxtool

Thanks for taking the time. This document covers what you need to know to make
a change that will be merged without a lot of back-and-forth.

## Ground rules

1. **Never push to a device.** srxtool reads configurations and writes files.
   No code path may open a connection to network equipment, and no generated
   command may be executed by the service itself. If a feature seems to need
   it, open an issue first — it is an architectural decision, not an
   implementation detail.

2. **Do not silently diverge from the Python reference.** The implementation
   in `reference/` is the behavioural specification during the Go rewrite. If
   your change makes Go behave differently, that is fine — but it must be
   recorded in the divergence table at the bottom of
   `docs/09-migration-et-parite.md` with a justification.

3. **Treat every input as hostile.** Configuration exports, hit-count exports,
   and user-filled CSVs all come from outside. Parse defensively, validate
   before use, and never build a shell command or a file path from unvalidated
   input.

## Getting set up

### Python reference (works today)

```bash
cd reference/
python3 srxtool.py inventory ../testdata/fixtures/sample.xml
python3 srxaudit.py ../testdata/fixtures/sample-show-config.txt
```

Standard library only. No virtualenv needed.

### Go service (in progress)

```bash
go build ./...
go test ./... -race -cover
make lint          # go vet + staticcheck + gosec
make fuzz          # short fuzzing run on the parser
```

## Repository conventions

- **Business logic packages** (`internal/config`, `inventory`, `audit`,
  `rules`) are pure: they take a parsed model, return data structures, and
  perform no file or network I/O. This is what makes them testable and
  reusable. I/O belongs in `internal/api` and `cmd/server`.
- **No server-side HTML templating.** The frontend is static and consumes
  JSON. This is a deliberate security boundary, not a style preference.
- Exported identifiers get doc comments. Unexported ones get comments when the
  *why* is not obvious from the code.
- Errors are wrapped with context (`fmt.Errorf("parsing zone %q: %w", ...)`)
  and inspected with `errors.Is`/`errors.As`, never by string matching.
- Error messages returned to HTTP clients are generic. Details go to the
  server log with a request ID.

## How to add a new audit check

This is the most common contribution, so here is the full path:

1. Pick a check code following the existing families: `POL-*` for policies,
   `ZONE-*` for zones, `SYS-*` for system services, `SNMP-*` for SNMP. Use a
   new prefix only for a genuinely new family (e.g. `NAT-*`).
2. Add the check in `internal/audit/checks.go`. It must produce a `Finding`
   with all fields populated: severity, check code, `Where` (the config path,
   in Junos hierarchy notation), a recommendation phrased as an action, and a
   reference to an actual standard or internal policy — not just "best
   practice".
3. If a fix can be expressed safely, add it to `Fix`. **If the fix requires a
   human decision (an IP, an object name, a threshold), emit it commented out
   with `#`.** A remediation file must never contain a line that would be
   wrong to paste blindly.
4. Add two tests: one configuration that triggers the check, one that does
   not. Table-driven tests are preferred.
5. Add the code to the checklist in `docs/09-migration-et-parite.md`.
6. Document it in the README table if it introduces a new family.

Severity guidance, roughly as applied by the existing checks:

| Severity | Meaning |
|---|---|
| `CRITICAL` | Exploitable from an untrusted zone, or removes filtering entirely |
| `HIGH` | Cleartext credentials, management plane exposure, broad permits |
| `MEDIUM` | Missing logging, weak-but-authenticated protocols, hygiene gaps |
| `LOW` | Defence-in-depth and operational quality (banner, NTP, internal screens) |
| `INFO` | Observations with no direct security impact |

The same rule of thumb used throughout: a finding is `CRITICAL` rather than
`HIGH` when the affected zone is externally facing, either by name heuristic
or because one of its interfaces carries a public address.

## How to add support for a new input format

`internal/config` has one file per format (`xml.go`, `curly.go`, `set.go`),
all producing the same `Model`. Add a file, add detection to the dispatcher,
add a fixture in `testdata/fixtures/`, and confirm the resulting model matches
what the other formats produce for an equivalent configuration. That
equivalence test is the point — a format that parses but produces a subtly
different model is worse than one that fails loudly.

## Tests

- Unit tests per package, table-driven where practical.
- Golden files in `testdata/golden/` guard against regression. If your change
  legitimately alters an output, regenerate the golden file **in a separate
  commit** so reviewers can see the diff on its own.
- The parser is fuzzed (`internal/config/fuzz_test.go`). Fuzz targets assert
  robustness only — no panics, no hangs, no unbounded memory — not
  correctness.
- Path traversal, oversized upload, and malformed input tests are part of the
  suite, not optional extras.

## Pull requests

- One logical change per PR. A new check, a parser fix, and a refactor are
  three PRs.
- CI must be green: build, vet, tests with `-race`, `govulncheck`, `gosec`.
- Describe *why*, not just *what*. For audit checks, cite the standard.
- If your change touches security-relevant code (parsing, path handling,
  command generation, HTTP middleware), say so explicitly in the description
  so it gets the review it deserves.

## Documentation

Task specifications in `docs/` are currently in French, from the original
implementation. English translation is a genuinely useful contribution — one
document per PR, keeping the file numbering and structure so cross-references
stay valid.

## License of contributions

srxtool is licensed under the **GNU AGPL v3.0 or later**. By submitting a pull
request you agree that your contribution is licensed under the same terms
(inbound = outbound). There is no CLA and no copyright assignment — you keep
the copyright on what you write.

Two practical consequences:

- New source files should carry the AGPL header shown in [`NOTICE`](NOTICE).
- Do not paste code from other projects unless it is AGPL-compatible. MIT,
  BSD, ISC, Apache 2.0 and GPLv3 code can be incorporated (keeping their
  notices); GPLv2-only, proprietary, or unlicensed snippets from forums and
  answer sites cannot.

If you are contributing on company time, confirm your employer allows it
before you open the PR — AGPL contributions are the kind some legal
departments have opinions about.

## Reporting bugs

Include: the input format (XML / curly-brace / set), a **redacted** minimal
configuration that reproduces the issue, what you expected, and what you got.

Never paste a real production configuration into a public issue. Redact
addresses, hostnames, community strings, and policy names — a config export is
a network blueprint.
