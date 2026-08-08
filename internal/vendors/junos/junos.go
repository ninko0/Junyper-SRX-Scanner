// Package junos is the vendors.ConfigParser/CounterParser implementation
// for Juniper SRX — the only one so far (see internal/vendors package
// doc). Pure adapter: no parsing logic here, everything delegates to
// internal/config and internal/rules, which remain the packages to
// modify for any Junos behavior change. This file only exposes that
// existing behavior behind the common interface, without touching it —
// the multi-vendor refactor must not change the Junos parity already
// verified against the reference Python (backlog task 09/migration).
package junos

import (
	"bytes"

	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/rules"
	"github.com/local/srxtool-go/internal/vendors"
)

// Name is the vendor's identifier, used for explicit selection
// (vendors.ParseConfigAs(junos.Name, ...)) and in error
// messages/reports.
const Name vendors.Vendor = "junos"

type parser struct{}

func (parser) Vendor() vendors.Vendor { return Name }

func (parser) ParseConfig(data []byte, opts config.Options) (*config.Model, error) {
	return config.Parse(data, opts)
}

func (parser) ParseCounters(data []byte) (map[rules.PolicyKey]rules.HitInfo, error) {
	return rules.ParseHitcount(bytes.NewReader(data))
}

// init registers the Junos implementation — the only place this
// package needs to be imported for side effect (see cmd/server/main.go
// and internal/api for the HTTP entry point).
func init() {
	p := parser{}
	vendors.RegisterConfigParser(p)
	vendors.RegisterCounterParser(p)
}
