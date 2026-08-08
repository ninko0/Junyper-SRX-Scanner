package config

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// XMLNode reproduces an ElementTree element: local name, text (the chardata
// BEFORE the first child, like `el.text` in Python) and ordered children.
type XMLNode struct {
	Tag      string
	Text     string
	Children []*XMLNode
}

// decodeXML builds the tree from an XML stream.
//
// Security (cf. task 01, "XML-specific security" section):
//   - encoding/xml resolves NO external entity and loads no DTD: the XXE
//     class from xml.etree/lxml doesn't apply here. This is the conclusion
//     to report in checklist 09 regarding defusedxml.
//   - undeclared internal entities cause an error (Strict=true by default),
//     they are not expanded.
//   - CharsetReader only accepts UTF-8/ASCII: no external decoder is
//     invoked based on an input-controlled encoding declaration.
//   - depth is bounded (maxXMLDepth) so a deeply nested input can't blow up
//     memory.
func decodeXML(data []byte, maxDepth int) (*XMLNode, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "utf-8", "utf8", "us-ascii", "ascii", "":
			return input, nil
		}
		return nil, fmt.Errorf("unsupported XML encoding: %q", charset)
	}

	root := &XMLNode{Tag: "#document"}
	stack := []*XMLNode{root}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) > maxDepth {
				return nil, fmt.Errorf("maximum XML depth exceeded (%d)", maxDepth)
			}
			n := &XMLNode{Tag: t.Name.Local}
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			cur := stack[len(stack)-1]
			// ElementTree's `el.text`: only the text preceding the first
			// child.
			if len(cur.Children) == 0 {
				cur.Text += string(t)
			}
		}
	}
	if len(root.Children) == 0 {
		return nil, fmt.Errorf("XML document with no root element")
	}
	return root.Children[0], nil
}

// kids: port of kids().
func (x *XMLNode) kids(name string) []*XMLNode {
	if x == nil {
		return nil
	}
	var out []*XMLNode
	for _, c := range x.Children {
		if c.Tag == name {
			out = append(out, c)
		}
	}
	return out
}

// kid: port of kid().
func (x *XMLNode) kid(name string) *XMLNode {
	if x == nil {
		return nil
	}
	for _, c := range x.Children {
		if c.Tag == name {
			return c
		}
	}
	return nil
}

// txt: port of txt() — non-empty text of the first child named `name`.
func (x *XMLNode) txt(name string) (string, bool) {
	c := x.kid(name)
	if c == nil {
		return "", false
	}
	s := strings.TrimSpace(c.Text)
	if s == "" {
		return "", false
	}
	return s, true
}

// nameList: port of name_list() — values of a list, in the form
// `<tag><name>x</name></tag>` or `<tag>x</tag>`.
func (x *XMLNode) nameList(tag string) []string {
	var out []string
	for _, c := range x.kids(tag) {
		n, ok := c.txt("name")
		if !ok {
			n = strings.TrimSpace(c.Text)
		}
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

// addrRef: port of addr_ref() — the name of an address reference in a
// policy, or its raw text (`any`).
func (x *XMLNode) addrRef() string {
	if n, ok := x.txt("name"); ok {
		return n
	}
	return strings.TrimSpace(x.Text)
}

// findConfigRoot: port of find_config_root() — locates <configuration>
// wherever it is (under <rpc-reply>, etc.), via a prefix walk like
// ET.iter().
func findConfigRoot(root *XMLNode) *XMLNode {
	if root == nil {
		return nil
	}
	if root.Tag == "configuration" {
		return root
	}
	var walk func(n *XMLNode) *XMLNode
	walk = func(n *XMLNode) *XMLNode {
		if n.Tag == "configuration" {
			return n
		}
		for _, c := range n.Children {
			if r := walk(c); r != nil {
				return r
			}
		}
		return nil
	}
	if r := walk(root); r != nil {
		return r
	}
	return root
}

// --- Tree implementation for the XML tree ----------------------------------

func (x *XMLNode) IsNil() bool { return x == nil }

func (x *XMLNode) Sub(key string) Tree { return x.kid(key) }

func (x *XMLNode) SubAll(key string) []Tree {
	ks := x.kids(key)
	out := make([]Tree, 0, len(ks))
	for _, k := range ks {
		out = append(out, k)
	}
	return out
}

// SubAllNamed: the name is carried by the child <name> element, as
// everywhere else in Junos XML (txt(el, "name")).
func (x *XMLNode) SubAllNamed(key string) []NamedTree {
	ks := x.kids(key)
	out := make([]NamedTree, 0, len(ks))
	for _, k := range ks {
		name, _ := k.txt("name")
		out = append(out, NamedTree{Name: name, Node: k})
	}
	return out
}

func (x *XMLNode) Val(key string) (string, bool) { return x.txt(key) }
func (x *XMLNode) Vals(key string) []string      { return x.nameList(key) }
func (x *XMLNode) Has(key string) bool           { return x.kid(key) != nil }

func (x *XMLNode) Names() []string {
	if x == nil {
		return nil
	}
	out := make([]string, 0, len(x.Children))
	for _, c := range x.Children {
		out = append(out, c.Tag)
	}
	return out
}
