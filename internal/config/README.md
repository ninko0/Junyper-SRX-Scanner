# `internal/config` — Junos configuration parsing (task 01)

Ports `srxtool.py` / `srxaudit.py`'s multi-format parsing to Go into a
single data model, reused by `inventory`, `audit`, and `rules`.

## API

```go
m, err := config.Parse(data, config.Options{})          // automatic detection
m, err := config.ParseReader(r, config.Options{MaxBytes: 32 << 20})
f     := config.DetectFormat(data)                      // "xml" | "curly" | "set"
```

Errors: `errors.Is(err, config.ErrFormat)` (equivalent of
`ConfigFormatError`), `errors.As(err, &fe)` for details
(`*config.FormatError`), `errors.Is(err, config.ErrTooLarge)` for size
overruns.

`Options.AllowEmpty` reproduces `--allow-empty`. **Never enable it by
default on the HTTP API side**: the "empty model" guard rail exists
precisely so an unreadable file doesn't produce a 0-finding audit, i.e. a
clean bill of health issued for a device that was never actually analyzed.

## Three design decisions

### 1. The AST stays the Python one

`Node` exactly reproduces the Python structure:

```
node = {"children": [(header_tokens, child_node), ...],
        "leaves":   [(key, [vals]), ...]}
```

The temptation was to normalize the three formats into a token trie. That's
more elegant, and it's wrong: the business logic relies on multi-token
headers (`from-zone A to-zone B`, `family inet`) and on the leaf/block
distinction. Changing the tree's shape would silently break the entire
layer built on top of it, which task 09 forbids.

The `CChildren/CChild/CLeaf/CValues/CHas/CBareNames/CBareValue` helpers are
1:1 ports of `cchildren/cchild/cleaf/cvalues/chas/cbare_names/cbare_value`,
nil-safe (Python's `if node is None` becomes a tolerated nil receiver).

### 2. One model, where Python had two

`srxtool.parse_config()` and `srxaudit.parse()` parsed the **same** conf
twice, with two partially redundant models. `config.Model` is their union:
`units/vlans/zones/global_books/policies` (srxtool) plus `screens`,
`system_services`, `protocols`, `screen`, `public` per zone and `logs` per
policy (srxaudit). JSON tags reuse the Python keys identically, so
comparison against the golden files stays direct.

### 3. A `Tree` interface instead of `isinstance(system, dict)`

On the Python side, every audit check redoes this test by hand:

```python
services = cchild(system, "services") if isinstance(system, dict) \
           else kid(system, "services")
```

repeated at every access, in every check — so a fix could be applied to one
format and not the other. Here, `*Node` (text) and `*XMLNode` (XML)
implement the same `Tree` interface: task 03 will write a single code path.

Careful in Go: an interface holding a nil pointer **is not** nil. Use
`config.Exists(t)` for the equivalent of Python's `is not None`.

## Security

- **Bounded size before parsing** (`Options.MaxBytes`, 32 MB by default,
  like the old `app.py`), enforced independently of the HTTP server.
- **XXE not applicable**: `encoding/xml` loads no DTD and resolves no
  external entity; an undeclared entity fails the document (`Strict=true`).
  A restrictive `CharsetReader` prevents any input-driven decoder
  selection. Conclusion for checklist 09: `defusedxml`-style hardening has
  no necessary equivalent here. Test: `TestMalformedXML`.
- **Bounded XML depth** (`MaxXMLDepth`, 512).
- **No panic on malformed input**: fuzzed property (`FuzzParse`, corpus =
  real fixtures + adversarial seeds).
- Error messages never echo back the input content.

## Parity

`TestGoldenModelAllFixtures` compares the Go model, field by field, against
the golden files produced by the reference Python implementation on the 4
fixtures (`scripts/gen_golden_model.py` regenerates them). Current result:
identical, warnings included.

`TestCrossFormatEquivalence` checks that the same conf written in curly
braces and in `display set` produces exactly the same model.

### Deliberate divergences

| # | Subject | Python | Go | Rationale |
|---|---|---|---|---|
| 1 | `address-book { global { ... } }` | global address book **empty**: objects are silently lost | objects read correctly | This is the form produced by a standard `show configuration`. Reproducing the bug would make task 04 generate a rename plan that doesn't repoint global references — i.e. commands that break the device's conf. Locked in by `TestAddressBookForms`. |
| 2 | JSON key order | insertion order | lexicographic order (Go maps) | No functional effect; golden comparison is done on parsed structures, not byte-for-byte. Makes outputs deterministic and diffable. |

### Python behaviors kept despite being questionable

To be explicitly decided with the user, **not modified** for now:

- The curly-brace parser is **line by line**: a full stanza that fits on a
  single line (`system { services { ssh { root-login deny; } } }`, line 1
  of `sample2.txt`) isn't read, it produces a warning instead. This
  fixture's `system` is therefore empty, on both the Python and Go sides.
- `inactive:` stanzas are parsed **as if they were active** (flagged by a
  warning). Cautious for an audit, wrong for an inventory.
- `deactivate` lines in the `display set` format are ignored, the matching
  stanza remaining considered active.
- Zone interfaces in XML: only the `<interfaces><name>x</name>` form is
  read, not `<interfaces>x</interfaces>` (fidelity to both Python parsers).
