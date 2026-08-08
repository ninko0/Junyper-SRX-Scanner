package config

import (
	"fmt"
	"strings"
)

// setNamedContainers: port of _SET_NAMED_CONTAINERS (srxtool.py L180-183).
// Deliberately narrow list: adding one keyword too many breaks the
// grouping (e.g. "vlan" would swallow the "members" of
// 'family ethernet-switching vlan members VLAN10').
var setNamedContainers = map[string]struct{}{
	"security-zone": {}, "policy": {}, "address": {}, "address-set": {},
	"ids-option": {}, "community": {}, "unit": {}, "family": {}, "host": {},
	"instance": {}, "rule": {}, "rule-set": {},
	// applications { application NAME { ... term NAME { ... } }
	//                application-set NAME { ... } }
	// Without these, "application"/"application-set"/"term" fall through
	// to the generic single-token descend and the name token ends up as
	// its own nested block instead of joining the header — CChildren(...)
	// then strips an empty header and extract_text.go's applications
	// block silently reads nothing. Verified safe against every other
	// "application" usage (policy match blocks) via Node.CValues, which
	// aggregates leaves and child headers identically either way — see
	// docs/decisions.md.
	"application": {}, "application-set": {}, "term": {},
}

// parseSetText is the port of parse_set_text() (srxtool.py L186-254):
// rebuilds the generic tree from a flattened 'display set' conf.
func parseSetText(text string) (*Node, []string) {
	root := newNode()
	var w warnBuf
	skipped, deactivated := 0, 0

	// descend: port of descend() — reuses the existing block if the
	// header is strictly identical, otherwise creates a new one.
	descend := func(node *Node, header []string) *Node {
		for _, c := range node.Children {
			if equalTokens(c.Header, header) {
				return c.Node
			}
		}
		c := newNode()
		node.addChild(header, c)
		return c
	}

	for lineno, raw := range strings.Split(text, "\n") {
		lineno++
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		toks := splitTokens(line)
		if len(toks) == 0 {
			continue
		}
		if toks[0] == "deactivate" {
			deactivated++
			continue
		}
		if toks[0] != "set" {
			skipped++
			w.warn(fmt.Sprintf("line %d ignored (doesn't start with 'set'): %s",
				lineno, pyRepr(truncRunes(line, 70))))
			continue
		}

		toks = toks[1:]
		node, i, n := root, 0, len(toks)
		if n == 0 {
			w.warn(fmt.Sprintf("line %d: 'set' with no argument", lineno))
			continue
		}
		for i < n {
			t := toks[i]
			// "from-zone A to-zone B" = a single 4-token block
			if t == "from-zone" && i+3 < n && toks[i+2] == "to-zone" {
				node = descend(node, cloneTokens(toks[i:i+4]))
				i += 4
				continue
			}
			if i == n-1 { // last token -> bare identifier
				node.addLeaf(t, nil)
				i++
				continue
			}
			if _, ok := setNamedContainers[t]; ok { // "<keyword> <name>"
				node = descend(node, cloneTokens(toks[i:i+2]))
				i += 2
				continue
			}
			node = descend(node, []string{t})
			i++
		}
	}

	if skipped > 0 {
		w.force(fmt.Sprintf("%d line(s) not parsed in total — result potentially incomplete", skipped))
	}
	if deactivated > 0 {
		w.force(fmt.Sprintf("%d 'deactivate' line(s) ignored: the matching stanza is parsed as active", deactivated))
	}
	return root, w.list
}

func equalTokens(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cloneTokens(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// looksLikeXML: port of looks_like_xml() (srxtool.py L257).
func looksLikeXML(text string) bool {
	t := strings.TrimLeft(text, " \t\r\n\f\v")
	return strings.HasPrefix(truncRunes(t, 200), "<")
}

// looksLikeSetFormat: port of looks_like_set_format() (srxtool.py L261-275).
func looksLikeSetFormat(text string) bool {
	setlines, other := 0, 0
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "set ") || strings.HasPrefix(line, "delete ") ||
			strings.HasPrefix(line, "deactivate ") {
			setlines++
		} else {
			other++
		}
		if setlines+other > 400 {
			break
		}
	}
	min3 := other
	if min3 < 3 {
		min3 = 3
	}
	return setlines > 0 && setlines >= min3
}

// parseTextAuto: port of parse_text_auto(). Returns (tree, warnings, format).
func parseTextAuto(text string) (*Node, []string, string) {
	if looksLikeSetFormat(text) {
		root, warnings := parseSetText(text)
		return root, warnings, "set"
	}
	root, warnings := parseCurlyText(text)
	return root, warnings, "curly"
}
