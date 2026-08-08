package config

import "errors"

// errUnbalancedQuote corresponds to the ValueError raised by shlex.split()
// on an unclosed quote.
var errUnbalancedQuote = errors.New("unclosed quote")

// shlexSplit reproduces shlex.split(s, posix=True) as used by
// _split_tokens() (srxtool.py L90-105 / srxaudit.py L99-111).
//
// POSIX shlex rules followed:
//   - splits on whitespace (whitespace_split=True, like shlex.split)
//   - single quotes: everything is literal, no escaping
//   - double quotes: only \" and \\ are escaped, everything else is
//     literal
//   - outside quotes: \x produces x literally
//   - '#' is NOT a comment (comments=False by default)
//   - an unclosed quote is an error (ValueError on the Python side)
func shlexSplit(s string) ([]string, error) {
	var (
		out   []string
		cur   []rune
		open  bool // a token is in progress (allows producing "" for `""`)
		quote rune
	)
	rs := []rune(s)
	flush := func() {
		if open {
			out = append(out, string(cur))
			cur = cur[:0]
			open = false
		}
	}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				cur = append(cur, r)
			}
		case quote == '"':
			if r == '\\' && i+1 < len(rs) && (rs[i+1] == '"' || rs[i+1] == '\\') {
				i++
				cur = append(cur, rs[i])
			} else if r == '"' {
				quote = 0
			} else {
				cur = append(cur, r)
			}
		case r == '\\':
			if i+1 < len(rs) {
				i++
				cur = append(cur, rs[i])
			}
			open = true
		case r == '\'' || r == '"':
			quote = r
			open = true
		case r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '\f' || r == '\v':
			flush()
		default:
			cur = append(cur, r)
			open = true
		}
	}
	if quote != 0 {
		return nil, errUnbalancedQuote
	}
	flush()
	return out, nil
}

// whitespaceSplit is the fallback Python uses (`toks = s.split()`) when
// shlex fails.
func whitespaceSplit(s string) []string {
	var out []string
	start := -1
	for i, r := range s {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '\f' || r == '\v' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

// splitTokens is the exact port of _split_tokens().
//
// Important fidelity point: the brackets of an inline list
// `key [ v1 v2 v3 ]` aren't "expanded" into multiple statements, they're
// simply REMOVED from the token list — and only for the FIRST pair
// encountered, exactly as in Python. The values therefore become multiple
// values of the same key, which cvalues() knows how to read back.
func splitTokens(s string) []string {
	toks, err := shlexSplit(s)
	if err != nil {
		toks = whitespaceSplit(s)
	}
	i := indexOf(toks, "[")
	if i < 0 {
		return toks
	}
	j := indexOfFrom(toks, "]", i)
	if j < 0 {
		j = len(toks)
	}
	out := make([]string, 0, len(toks))
	out = append(out, toks[:i]...)
	out = append(out, toks[i+1:j]...)
	if j+1 <= len(toks) {
		out = append(out, toks[j+1:]...)
	}
	return out
}

func indexOf(ss []string, v string) int { return indexOfFrom(ss, v, 0) }

func indexOfFrom(ss []string, v string, from int) int {
	for i := from; i < len(ss); i++ {
		if ss[i] == v {
			return i
		}
	}
	return -1
}
