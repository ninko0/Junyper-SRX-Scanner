// Package vendors is the "addon" extension point described in the backlog
// (item 2, multi-vendor architecture): a clean boundary between parsing,
// specific to each vendor, and the rest of the tool (inventory, audit,
// cleanup, rename), which only knows the common model (config.Model,
// rules.PolicyKey/HitInfo).
//
// Adding a vendor means writing an internal/vendors/<name> package that
// implements ConfigParser (and CounterParser if the vendor exposes hit
// counters) and registers itself in its init(), then importing it for
// side effect from the entry points (cmd/server, cmd/srxtool) that need
// to support it. Nothing else changes: selection at upload goes through
// DetectConfig, never a hardcoded switch elsewhere.
//
// internal/vendors/junos is the only implementation so far — a port of
// the existing parser, with no behavior change. No second vendor
// (FortiGate was the backlog's first target) is implemented here: the
// backlog itself requires starting from a real, anonymized conf before
// coding anything against its format, a prerequisite not met at the time
// of this task. This package only prepares the socket that future parser
// will plug into.
package vendors

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/rules"
)

// Vendor identifies a vendor ("junos", "fortigate", ...). Used for
// explicit selection (fallback in case of ambiguity) and in
// error/report messages.
type Vendor string

// ConfigParser parses a configuration export into the common model.
// ParseConfig must fail (non-nil error) when the input is clearly not
// within its scope — this failure, not a separate detection step, is
// the signal DetectConfig relies on. This is deliberate: the "empty
// model == error" guard rail (config.assertModelNotEmpty) already
// exists on the Junos side; duplicating it in a separate detection
// heuristic would be redundant, and one we couldn't calibrate anyway
// without real samples of future competing formats.
type ConfigParser interface {
	Vendor() Vendor
	ParseConfig(data []byte, opts config.Options) (*config.Model, error)
}

// CounterParser parses a counter export (Junos hit-count or equivalent)
// into the common PolicyKey -> HitInfo map.
//
// Not wired into multi-vendor automatic detection for now: unlike
// ParseConfig, ParseHitcount (Junos) doesn't return an error on
// unrecognized content, it returns an empty map (this is precisely
// backlog item 1's bug, worked around for the Junos format but not a
// guarantee it generalizes without a second look for a second format).
// Registered here so the interface exists once a second CounterParser
// shows up; the HTTP entry point keeps calling the Junos parser directly
// (see internal/api/handlers.go).
type CounterParser interface {
	Vendor() Vendor
	ParseCounters(data []byte) (map[rules.PolicyKey]rules.HitInfo, error)
}

var (
	mu             sync.RWMutex
	configParsers  = map[Vendor]ConfigParser{}
	counterParsers = map[Vendor]CounterParser{}
)

// RegisterConfigParser registers a configuration parser. Meant to be
// called from the vendor package's init(); panics on an already
// registered vendor (a programming error, not user input — it must
// fail at startup, not in production).
func RegisterConfigParser(p ConfigParser) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := configParsers[p.Vendor()]; dup {
		panic(fmt.Sprintf("vendors: configuration parser already registered for %q", p.Vendor()))
	}
	configParsers[p.Vendor()] = p
}

// RegisterCounterParser: equivalent of RegisterConfigParser for
// counters.
func RegisterCounterParser(p CounterParser) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := counterParsers[p.Vendor()]; dup {
		panic(fmt.Sprintf("vendors: counter parser already registered for %q", p.Vendor()))
	}
	counterParsers[p.Vendor()] = p
}

// ConfigVendors lists the vendors available for configuration parsing,
// sorted for stable display.
func ConfigVendors() []Vendor {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Vendor, 0, len(configParsers))
	for v := range configParsers {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// UnrecognizedFormatError: no registered parser recognized the input.
// Attempts keeps each tried parser's error, for a precise diagnostic
// rather than a generic message once several vendors are registered.
type UnrecognizedFormatError struct {
	Attempts map[Vendor]error
}

func (e *UnrecognizedFormatError) Error() string {
	if len(e.Attempts) == 0 {
		return "no configuration parser registered"
	}
	vs := make([]Vendor, 0, len(e.Attempts))
	for v := range e.Attempts {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, fmt.Sprintf("%s: %v", v, e.Attempts[v]))
	}
	return "unrecognized configuration format (" + strings.Join(parts, "; ") + ")"
}

// AmbiguousFormatError: several parsers accepted the same input.
// Backlog item 2: "automatic detection... with fallback to an explicit
// choice in case of ambiguity" — this type carries that fallback, it's
// up to the caller (CLI/API) to offer the explicit choice via
// ParseConfigAs.
type AmbiguousFormatError struct {
	Vendors []Vendor
}

func (e *AmbiguousFormatError) Error() string {
	vs := make([]string, len(e.Vendors))
	for i, v := range e.Vendors {
		vs[i] = string(v)
	}
	return "ambiguous configuration format, several vendors match (" +
		strings.Join(vs, ", ") + "): explicit selection required"
}

// DetectConfig tries each registered configuration parser and returns
// the one that succeeds, with the resulting common model. Explicit
// error if zero or several parsers accept the input — never a silent
// arbitrary choice (same principle as backlog item 1's guard rail: a
// reconciliation that fails must be a surfaced error).
func DetectConfig(data []byte, opts config.Options) (*config.Model, Vendor, error) {
	mu.RLock()
	parsers := make([]ConfigParser, 0, len(configParsers))
	for _, p := range configParsers {
		parsers = append(parsers, p)
	}
	mu.RUnlock()
	sort.Slice(parsers, func(i, j int) bool { return parsers[i].Vendor() < parsers[j].Vendor() })

	if len(parsers) == 0 {
		return nil, "", &UnrecognizedFormatError{}
	}

	attempts := map[Vendor]error{}
	var matchedVendors []Vendor
	var matchedModel *config.Model
	for _, p := range parsers {
		m, err := p.ParseConfig(data, opts)
		if err != nil {
			attempts[p.Vendor()] = err
			continue
		}
		matchedVendors = append(matchedVendors, p.Vendor())
		matchedModel = m
	}

	switch len(matchedVendors) {
	case 0:
		return nil, "", &UnrecognizedFormatError{Attempts: attempts}
	case 1:
		return matchedModel, matchedVendors[0], nil
	default:
		return nil, "", &AmbiguousFormatError{Vendors: matchedVendors}
	}
}

// ParseConfigAs parses explicitly with the named vendor — the manual
// fallback in case of ambiguity (or simply when the caller already
// knows which device it's dealing with and wants to skip the cost of
// trying every parser).
func ParseConfigAs(v Vendor, data []byte, opts config.Options) (*config.Model, error) {
	mu.RLock()
	p, ok := configParsers[v]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("vendors: unknown vendor %q (available: %v)", v, ConfigVendors())
	}
	return p.ParseConfig(data, opts)
}

// CounterParserFor returns the counter parser registered for a given
// vendor.
func CounterParserFor(v Vendor) (CounterParser, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := counterParsers[v]
	return p, ok
}
