package config

import (
	"fmt"
	"strings"
)

// maxParserWarnings reproduces the warn() cap (25) from parse_curly_text /
// parse_set_text: beyond that, only the final summary warnings are kept.
const maxParserWarnings = 25

type warnBuf struct{ list []string }

func (w *warnBuf) warn(msg string) {
	if len(w.list) < maxParserWarnings {
		w.list = append(w.list, msg)
	}
}

// force adds a summary warning without going through the cap (like
// Python's final warnings.append() calls).
func (w *warnBuf) force(msg string) { w.list = append(w.list, msg) }

// parseCurlyText is the port of parse_curly_text() (srxtool.py L113-171).
//
// Parses line by line (not character by character): this is Python's
// behavior, including its limitations (an opening brace must end the
// line). Reproducing it identically is deliberate — a "smarter" parser
// would accept confs that Python rejects, which is exactly the kind of
// divergence the rewrite must avoid.
func parseCurlyText(text string) (*Node, []string) {
	root := newNode()
	stack := []*Node{root}
	var w warnBuf
	skipped, inactive := 0, 0

	for lineno, raw := range strings.Split(text, "\n") {
		lineno++
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "/*") {
			continue
		}
		if strings.HasPrefix(line, "inactive:") {
			inactive++
			line = strings.TrimSpace(strings.TrimPrefix(line, "inactive:"))
			if line == "" {
				continue
			}
		}
		if line == "}" || line == "};" {
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			} else {
				w.warn(fmt.Sprintf("line %d: extra closing brace (malformed conf)", lineno))
			}
			continue
		}
		if strings.HasSuffix(line, "{") {
			header := splitTokens(strings.TrimSpace(strings.TrimSuffix(line, "{")))
			if len(header) == 0 {
				w.warn(fmt.Sprintf("line %d: unnamed block, ignored", lineno))
				continue
			}
			node := newNode()
			stack[len(stack)-1].addChild(header, node)
			stack = append(stack, node)
			continue
		}
		if strings.HasSuffix(line, ";") {
			toks := splitTokens(strings.TrimSpace(strings.TrimSuffix(line, ";")))
			if len(toks) > 0 {
				stack[len(stack)-1].addLeaf(toks[0], toks[1:])
			}
			continue
		}
		skipped++
		w.warn(fmt.Sprintf("line %d not parsed: %s", lineno, pyRepr(truncRunes(line, 70))))
	}

	if len(stack) > 1 {
		w.force(fmt.Sprintf("%d block(s) never closed: the end of the conf may have been misattached", len(stack)-1))
	}
	if skipped > 0 {
		w.force(fmt.Sprintf("%d line(s) not parsed in total — result potentially incomplete", skipped))
	}
	if inactive > 0 {
		w.force(fmt.Sprintf("%d 'inactive:' stanza(s) were parsed as if they were active", inactive))
	}
	return root, w.list
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// pyRepr mimics Python's repr() for a simple string (single quotes), so
// the warning messages shown in the UI stay identical to the Python
// version's.
func pyRepr(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\'':
			b.WriteString(`\'`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}
