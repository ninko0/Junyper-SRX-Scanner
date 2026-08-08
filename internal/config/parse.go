package config

import (
	"io"
	"strings"
)

// DefaultMaxBytes mirrors the upload limit from the old app.py (32 MB).
// The limit is also applied here, not just at the HTTP layer, so the
// package stays testable and usable independently of the server (task 01).
const DefaultMaxBytes int64 = 32 << 20

// DefaultMaxXMLDepth bounds the accepted XML nesting depth.
const DefaultMaxXMLDepth = 512

// Options controls the parsing guard rails.
type Options struct {
	// MaxBytes: maximum accepted size (0 => DefaultMaxBytes).
	MaxBytes int64
	// MaxXMLDepth: maximum XML depth (0 => DefaultMaxXMLDepth).
	MaxXMLDepth int
	// AllowEmpty: equivalent of --allow-empty, disables the "empty
	// model" guard rail. Only expose via CLI, never by default on the
	// API side.
	AllowEmpty bool
}

func (o Options) maxBytes() int64 {
	if o.MaxBytes <= 0 {
		return DefaultMaxBytes
	}
	return o.MaxBytes
}

func (o Options) maxXMLDepth() int {
	if o.MaxXMLDepth <= 0 {
		return DefaultMaxXMLDepth
	}
	return o.MaxXMLDepth
}

// Parse detects the configuration's format and returns the unified model.
//
// Detection order identical to Python (parse_config / parse):
//  1. looks_like_xml on the first 500 characters
//  2. otherwise looks_like_set_format on the whole input
//  3. otherwise curly-brace format
//
// No input, however deliberately malformed, should ever cause a panic:
// any anomaly surfaces as a Go error (a property fuzzed in task 08).
func Parse(data []byte, opts Options) (*Model, error) {
	if int64(len(data)) > opts.maxBytes() {
		return nil, ErrTooLarge
	}

	// Equivalent of open(..., encoding="utf-8", errors="replace"):
	// invalid bytes become U+FFFD instead of making the read fail.
	text := strings.ToValidUTF8(string(data), "\uFFFD")

	var m *Model
	if looksLikeXML(head(text, 500)) {
		root, err := decodeXML(data, opts.maxXMLDepth())
		if err != nil {
			return nil, &FormatError{Format: "xml", Reason: "unreadable XML document: " + err.Error()}
		}
		m = parseConfigXMLTree(findConfigRoot(root))
	} else {
		m = parseConfigText(text)
	}

	if err := assertModelNotEmpty(m, opts.AllowEmpty); err != nil {
		return nil, err
	}
	return m, nil
}

// ParseReader reads at most MaxBytes+1 bytes so it can detect an overflow
// without ever loading more into memory.
func ParseReader(r io.Reader, opts Options) (*Model, error) {
	limit := opts.maxBytes()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	return Parse(data, opts)
}

// DetectFormat returns the format Parse would pick, without building the
// model. Useful to the HTTP layer to reject early content that doesn't
// look like a configuration at all (task 05).
func DetectFormat(data []byte) string {
	text := strings.ToValidUTF8(string(data), "\uFFFD")
	if looksLikeXML(head(text, 500)) {
		return "xml"
	}
	if looksLikeSetFormat(text) {
		return "set"
	}
	return "curly"
}

// head reproduces fh.read(n): n characters, not n bytes.
func head(s string, n int) string { return truncRunes(s, n) }
