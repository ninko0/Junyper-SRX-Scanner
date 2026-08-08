# `internal/api`, `internal/session`, `cmd/server` — task 05

## Routes

```
POST /api/analyze                          -> {session_id, source_format, warnings, audit{}, inventory{}, downloads{}}
GET  /api/sessions/{sid}/inventory/report.{txt,json,xlsx}   [?as=custom-name]
GET  /api/sessions/{sid}/audit/report.{txt,json,xlsx}       [?as=custom-name]
GET  /api/sessions/{sid}/audit/fix.set                      [?as=custom-name]
POST /api/rules/rename/suggest              -> CSV (text/csv, Content-Disposition attachment) [as=custom-name form field]
POST /api/rules/rename/apply                -> {set_commands[], rollback[], rejected[], applied}
POST /api/rules/cleanup                     -> {candidates[], kept_deny[], excluded[], unknown[], set_commands[], rollback[]}
GET  /healthz
```

`?as=`/`as=`: optional, renames the downloaded file (see "Renaming a
download before saving it" below) — never affects which file is read.

Router: Go 1.22 stdlib `net/http.ServeMux` (`"METHOD /path"` patterns,
`{sid}` wildcards) — not `chi`. Task 05's decision settled in favor of
"zero routing dependency": the routes are simple, an external router
wouldn't add anything here. Benefit verified by test
(`TestMethodNotAllowed`): an undeclared method on a route returns 405
automatically, with no extra code.

## `internal/session`: the most sensitive part of this task

**Full UUID v4** session identifier (32 hex chars, full entropy) — not the
12-character truncation from the old `app.py`, documented as a deliberate
divergence in MD 09: with no authentication layered on top, the session
identifier is a capability secret.

The file name read from disk is **never** derived from the URL: each
download route fixes its internal file name at routing time
(`sessionFileInternalName`, a literal map in `handlers.go`), the URL only
ever supplying `sid`. This is stricter than the "whitelist" described in
task 05 — there isn't even a variable file name to filter.

Containment survives a session directory later replaced by a symlink
(`filepath.EvalSymlinks` + prefix comparison): `TestSymlinkEscapeBlocked`
creates a real symlink pointing outside `BaseDir` and checks that reading
fails instead of following it — this is the historical class of flaw in
`app.py` (`os.path.basename("..") == ".."`).

## Renaming a download before saving it (backlog item 4)

Every session-file download route (`GET
/api/sessions/{sid}/{tool}/{kind}`) and `POST /api/rules/rename/suggest`
accept an optional client-supplied name for the file the browser saves —
`?as=` as a query parameter for the first, an `as` form field for the
second (it's a `POST`). Both feed `sanitizeDownloadName`
(`internal/api/filename.go`) before being written to the
`Content-Disposition` header:

- only the final path element of the client's input is kept
  (`filepath.Base`), so a traversal attempt like `../../etc/passwd`
  collapses to `passwd`;
- any extension the client typed is discarded — the real one (derived
  from the fixed, server-chosen `kind`, never from client input) is
  always forced back on, so a rename can never make a `.txt` report
  masquerade as a `.xlsx` or vice versa;
- everything outside a conservative charset (letters, digits, space,
  `_`, `-`, `.`) is replaced with `_`;
- a result with no letter or digit left, or an empty input, falls back
  to the server's own internal file name.

**This name is only ever a response header value.** It is never passed
to `session.Manager.ReadPath`/`WritePath`, never used to build a
filesystem path, and never changes which file is actually served — the
server-side lookup key stays the fixed `sessionFileInternalName` entry
picked by the route itself (see above). `TestSessionFileDownloadRename`
locks this in: renaming a download must leave the response body
byte-identical to the un-renamed one.

The frontend (`web/app.js`) exposes this as a "rename downloads" text
input next to each download group; typing there appends `?as=` to the
relevant links (session-file downloads) or fills the `as` form field
(the rename-plan CSV). The client-generated downloads that have no
server-side file behind them at all (`rename.set`, `cleanup.set`, and
their rollbacks — built in the browser from JSON the API already
returned) get their own lightweight client-side sanitizer
(`clientRenamedFilename` in `app.js`), which is UX-only, not a security
boundary — there is no path or session lookup for it to protect.

## Middleware

- OWASP headers (strict CSP with no `unsafe-inline`, `nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, restrictive
  `Permissions-Policy`). No HSTS (plain HTTP on localhost).
- `http.MaxBytesReader` on the whole request body (32 MB by default,
  configurable via `SRXWEB_MAX_BYTES`).
- Per-IP rate limiting (homegrown token bucket, `golang.org/x/time/rate`
  skipped to avoid an extra external dependency for something this
  simple) on `/api/analyze` and `/api/rules/*`.
- Explicit timeouts on `http.Server` (`ReadTimeout`, `ReadHeaderTimeout`,
  `WriteTimeout`, `IdleTimeout`) — never Go's defaults, which are
  infinite.
- Global `recover()`: any panic becomes a generic 500 + log entry, never a
  process crash.
- Errors: a single type exposed to the client (`{"error": "generic
  message"}`), never a raw `err.Error()` from an internal package —
  verified by `TestAnalyzeBadFormat`, which checks that no server path
  leaks.

## No authentication (assumed, cf MD 05)

Explicitly documented in the code (`session.go`): if authentication is
added later, the session-owner check (`OWNER_FILE` from the old `app.py`)
will need to be reintroduced before any exposure beyond `localhost`.

## Tests

`internal/api/api_test.go` covers, via `net/http/httptest` (no real network
server in the tests):
- full happy path `analyze` → download of each of the 7 files
- **explicit path traversal**: `..`, `%2f` encoding, a syntactically valid
  but nonexistent sid, a malformed sid — `ServeMux`'s path-cleanup
  redirect (301) is followed to its actual destination before judging the
  result, the way a client following redirects would; all of them end up
  at 404, no content leak
- size overflow (400, never a panic)
- full `rename/suggest` → `rename/apply` cycle
- `cleanup` (candidates/kept deny/excluded/unknown)
- rate limiting, security headers, 405 on an undeclared method
- **download renaming** (`TestSessionFileDownloadRename`,
  `TestRenameSuggestDownloadRename`): sanitized `Content-Disposition`,
  forced extension, and a byte-identical body regardless of the "as"
  value — plus `internal/api/filename_test.go`'s unit tests on
  `sanitizeDownloadName` itself (traversal collapse, unsafe-character
  replacement, length cap, no path separator or quote ever survives)

Additional manual verification (outside the automated suite): the
`cmd/server` binary was actually built and started
(`SRXWEB_HOST=127.0.0.1`), queried via `curl` on `/healthz` and
`/api/analyze` with a real fixture — correct JSON response, clean shutdown
on `SIGTERM` (graceful shutdown verified in the logs).

## Environment variables (`cmd/server`)

| Variable | Default | Role |
|---|---|---|
| `SRXWEB_HOST` | `0.0.0.0` | listening interface (actual containment comes from Docker port mapping, task 07) |
| `SRXWEB_PORT` | `8080` | port |
| `SRXWEB_SESSION_DIR` | `/tmp/srxweb_sessions` | sessions directory |
| `SRXWEB_SESSION_TTL` | `6h` | best-effort cleanup |
| `SRXWEB_MAX_BYTES` | `33554432` (32 MB) | request size limit |

`-healthcheck`: queries `/healthz` locally and exits with the appropriate
code — needed for the Docker `HEALTHCHECK` of a `distroless` image with no
`curl`/`wget` (task 07).
