package config

import "sort"

// NamedTree associates an identifier with a subtree: the name carried by
// the text header (`community NAME { ... }`) or by the XML <name> element.
type NamedTree struct {
	Name string
	Node Tree
}

// Tree is the navigation abstraction common to both configuration
// representations: the text tree (*Node) and the XML tree (*XMLNode).
//
// On the Python side, every audit check redid this test by hand:
//
//	services = cchild(system, "services") if isinstance(system, dict) \
//	           else kid(system, "services")
//
// repeated on every access, in every check. A single interface here: tasks
// 02/03/04 write a single code path, and a fix can no longer be applied to
// one format and not the other.
//
// Semantic mapping (verified function by function):
//
//	Sub         -> cchild()      / kid()
//	SubAll      -> cchildren()   / kids()
//	SubAllNamed -> cchildren()+header / kids()+<name>
//	Val         -> cleaf()       / txt()
//	Vals        -> cvalues()     / name_list()
//	Has         -> chas()        / kid() is not None
//	Names       -> cbare_names() / children's names
//
// Nuance kept as-is: on `telnet;` (text) Val returns ("", true) while on
// `<telnet/>` (XML) Val returns ("", false) — just as cleaf() returns True
// where txt() returns None. The checks that matter use Has, never Val,
// exactly as in Python.
type Tree interface {
	Sub(key string) Tree
	SubAll(key string) []Tree
	SubAllNamed(key string) []NamedTree
	Val(key string) (string, bool)
	Vals(key string) []string
	Has(key string) bool
	Names() []string
	IsNil() bool
}

// Exists replaces Python's `is not None`. Indispensable in Go: an
// interface holding a nil pointer isn't itself nil.
func Exists(t Tree) bool { return t != nil && !t.IsNil() }

// ValOr returns the key's value, or def if absent.
func ValOr(t Tree, key, def string) string {
	if v, ok := t.Val(key); ok {
		return v
	}
	return def
}

// --- Tree implementation for the text tree ---------------------------------

func (n *Node) IsNil() bool { return n == nil }

func (n *Node) Sub(key string) Tree { return n.CChild(key) }

func (n *Node) SubAll(key string) []Tree {
	cs := n.CChildren(key)
	out := make([]Tree, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Node)
	}
	return out
}

// SubAllNamed: the name of a named container ("community NAME { ... }") is
// the first remaining token of the header AFTER CChildren has stripped the
// key itself. If none remains ("key { NAME; }" block, the display-set form
// of a named container with no second level), we fall back to CBareValue —
// same logic as cbare_value() on the Python side.
func (n *Node) SubAllNamed(key string) []NamedTree {
	cs := n.CChildren(key)
	out := make([]NamedTree, 0, len(cs))
	for _, c := range cs {
		name := ""
		if len(c.Header) > 0 {
			name = c.Header[0]
		} else if v, ok := c.Node.CBareValue(); ok {
			name = v
		}
		out = append(out, NamedTree{Name: name, Node: c.Node})
	}
	return out
}

func (n *Node) Val(key string) (string, bool) { return n.CLeaf(key) }
func (n *Node) Vals(key string) []string      { return n.CValues(key) }
func (n *Node) Has(key string) bool           { return n.CHas(key) }
func (n *Node) Names() []string               { return n.CBareNames() }

// --- utilities ---------------------------------------------------------

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func strPtr(s string) *string { return &s }
