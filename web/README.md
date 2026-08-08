# `web/` — static frontend (task 06)

Vanilla HTML/CSS/JS, no client framework or rendering server — eliminates
the class of SSTI risk that the old `app.py`'s `render_template_string`
had.

## Structure

- `index.html` — single page, 3 tabs (Analyze / Rules-rename / Rules-cleanup)
- `style.css` — severity palette **identical** to `internal/xlsx`
  (`--crit`/`--high`/etc. reuse the ARGB colors from `FILLS`): visual
  consistency between the UI and the Excel exports, explicitly requested by
  task 06.
- `app.js` — fetch/DOM logic, no dependencies
- `embed.go` — `web` is a real Go package (`//go:embed index.html style.css
  app.js`), imported by `cmd/server`. No separate volume to manage in
  production.

## Security constraints respected

- **No inline JS, no `eval`**: `app.js` is an external file, loaded via
  `<script src="/app.js">`, consistent with the
  `Content-Security-Policy: default-src 'self'` set server-side (task 05)
  — manually verified (the CSP would block any inline script if inline JS
  had been added by mistake).
- **Systematic escaping**: any content coming from the API (policy names,
  error messages, conf-parsing warnings) goes through `textContent`, never
  `innerHTML` — grepping `app.js`: zero occurrences of `innerHTML`.
- **Download links**: use the URLs returned by `/api/analyze` as-is
  (`data.downloads.*`, containing the server-generated `sid`) — never
  rebuilt from user input.
- **Client-side validation in addition to, not instead of**, server-side
  validation: file fields are `required`, but all the actual validation
  (format, size) stays in `internal/api`/`internal/config`.

## Content kept from the old template

- The warning banner (`#warn-banner`) shows `source_format` + `warnings` —
  useful to know whether the conf was read as XML/curly/set and whether
  there are parsing warnings (cf task 06, content-preservation section).
- The colored severity badges (`.b-crit`, `.b-high`, `.b-med`, `.b-low`,
  `.b-info`) — same colors as the XLSX palette.
- The removable candidates / kept deny / excluded / ignored breakdown for
  cleanup, in the same information order as `cmd_cleanup()`'s console
  report.

## Verification

The real binary (`cmd/server`) was started and queried via `curl`:
`GET /` returns `text/html`, `GET /style.css` returns `text/css`,
`GET /app.js` returns `text/javascript`, all with 200; a nonexistent route
returns 404 (no directory listing, `http.FileServer` over an embedded
`fs.FS` rather than the disk — no arbitrary filesystem path is ever
reachable).

## Out of scope (per task 06)

No build step (webpack/vite): vanilla JS is enough for this size of
interface. No browser end-to-end tests (Selenium/Playwright) — the HTTP
tests in `internal/api` cover the API contract this frontend consumes; the
frontend itself was verified manually (see above).
