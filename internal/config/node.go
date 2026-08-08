package config

// Node is the generic tree produced by the text parsers, an exact port of
// the Python structure:
//
//	node = {"children": [(header_tokens, child_node), ...],
//	        "leaves":   [(key, [vals]), ...]}
//
// Deliberately NOT converted into a trie: the business code (audit,
// inventory, rules) relies on the header/leaf distinction and on
// multi-token headers (`from-zone A to-zone B`, `family inet`). Changing
// the tree's shape here would silently break everything built on top of
// it.
type Node struct {
	Children []Child `json:"children"`
	Leaves   []Leaf  `json:"leaves"`
}

// Child is a `header... { ... }` block.
type Child struct {
	Header []string `json:"header"`
	Node   *Node    `json:"node"`
}

// Leaf is a terminal `key vals...;` statement.
type Leaf struct {
	Key  string   `json:"key"`
	Vals []string `json:"vals"`
}

func newNode() *Node { return &Node{} }

func (n *Node) addChild(header []string, c *Node) {
	n.Children = append(n.Children, Child{Header: header, Node: c})
}

func (n *Node) addLeaf(key string, vals []string) {
	n.Leaves = append(n.Leaves, Leaf{Key: key, Vals: vals})
}

// CChildren: port of cchildren(). Returns the blocks whose first header
// token equals key, with the header STRIPPED of that first token (as in
// Python: `[(h[1:], c) for h, c in ...]`).
func (n *Node) CChildren(key string) []Child {
	if n == nil {
		return nil
	}
	var out []Child
	for _, c := range n.Children {
		if len(c.Header) > 0 && c.Header[0] == key {
			out = append(out, Child{Header: c.Header[1:], Node: c.Node})
		}
	}
	return out
}

// CChild: port of cchild(). First matching block, or nil.
func (n *Node) CChild(key string) *Node {
	r := n.CChildren(key)
	if len(r) == 0 {
		return nil
	}
	return r[0].Node
}

// bareNames: port of _bare_names() — a block's bare identifiers, i.e. the
// value-less leaves and the single-token headers.
func (n *Node) bareNames() []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, l := range n.Leaves {
		if len(l.Vals) == 0 {
			out = append(out, l.Key)
		}
	}
	for _, c := range n.Children {
		if len(c.Header) == 1 {
			out = append(out, c.Header[0])
		}
	}
	return out
}

// CBareValue: port of cbare_value(). The single value of a `key { value; }`
// block (a form typical of the 'display set' output). ok=false if the
// block doesn't have exactly one bare identifier.
func (n *Node) CBareValue() (string, bool) {
	names := n.bareNames()
	if len(names) == 1 {
		return names[0], true
	}
	return "", false
}

// CLeaf: port of cleaf(). Reads a key regardless of its form:
//
//	`key value;` | `key { value; }` | `key value { ... }`
//
// Python returns True (bool) when the key exists with no value; here that
// corresponds to (value="", ok=true). Business comparisons like
// cleaf(x,"root-login") == "allow" therefore stay equivalent.
func (n *Node) CLeaf(key string) (string, bool) {
	if n == nil {
		return "", false
	}
	for _, l := range n.Leaves {
		if l.Key == key {
			return joinSpace(l.Vals), true
		}
	}
	for _, c := range n.Children {
		if len(c.Header) > 0 && c.Header[0] == key {
			if len(c.Header) > 1 {
				return joinSpace(c.Header[1:]), true
			}
			if v, ok := c.Node.CBareValue(); ok {
				return v, true
			}
			return "", true
		}
	}
	return "", false
}

// CLeafString returns the key's value, or def if absent. A key present
// with no value returns "" (equivalent of Python's True).
func (n *Node) CLeafString(key, def string) string {
	if v, ok := n.CLeaf(key); ok {
		return v
	}
	return def
}

// CValues: port of cvalues(). Unifies the four possible spellings:
//
//	`key v;` | `key [ v1 v2 ];` | `key { v1; v2; }` | `key v1; key v2;`
//
// Deduplicates while preserving first-appearance order (as in Python).
func (n *Node) CValues(key string) []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, l := range n.Leaves {
		if l.Key == key {
			out = append(out, l.Vals...)
		}
	}
	for _, c := range n.Children {
		if len(c.Header) > 0 && c.Header[0] == key {
			out = append(out, c.Header[1:]...)
			out = append(out, c.Node.bareNames()...)
		}
	}
	return dedup(out)
}

// CHas: port of chas().
func (n *Node) CHas(key string) bool {
	if n == nil {
		return false
	}
	for _, l := range n.Leaves {
		if l.Key == key {
			return true
		}
	}
	for _, c := range n.Children {
		if len(c.Header) > 0 && c.Header[0] == key {
			return true
		}
	}
	return false
}

// CBareNames: port of cbare_names() — all leaf keys + all first header
// tokens (unlike _bare_names, with no filtering).
func (n *Node) CBareNames() []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, l := range n.Leaves {
		out = append(out, l.Key)
	}
	for _, c := range n.Children {
		if len(c.Header) > 0 {
			out = append(out, c.Header[0])
		}
	}
	return out
}

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func joinSpace(ss []string) string {
	switch len(ss) {
	case 0:
		return ""
	case 1:
		return ss[0]
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += " " + s
	}
	return out
}
