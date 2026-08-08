package vendors

import (
	"errors"
	"testing"

	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/rules"
)

// fakeParser: test double, never registered globally (each test uses
// its own isolated registry via newTestRegistry, see below) so as not
// to interfere with the real internal/vendors/junos package imported
// elsewhere in the test binary.
type fakeParser struct {
	vendor  Vendor
	matches bool
	model   *config.Model
}

func (f fakeParser) Vendor() Vendor { return f.vendor }

func (f fakeParser) ParseConfig(data []byte, opts config.Options) (*config.Model, error) {
	if !f.matches {
		return nil, errors.New("does not match")
	}
	if f.model != nil {
		return f.model, nil
	}
	return &config.Model{}, nil
}

// withRegistry runs fn against a blank registry, without touching the
// package's global registry (which may already have "junos" registered
// as a side effect elsewhere in the test binary). Saves/restores the
// global maps to keep tests independent of each other and of execution
// order.
func withRegistry(t *testing.T, fn func()) {
	t.Helper()
	mu.Lock()
	savedConfig := configParsers
	savedCounter := counterParsers
	configParsers = map[Vendor]ConfigParser{}
	counterParsers = map[Vendor]CounterParser{}
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		configParsers = savedConfig
		counterParsers = savedCounter
		mu.Unlock()
	})

	fn()
}

func TestDetectConfigSingleMatch(t *testing.T) {
	withRegistry(t, func() {
		want := &config.Model{SourceFormat: "curly"}
		RegisterConfigParser(fakeParser{vendor: "acme", matches: true, model: want})

		m, v, err := DetectConfig([]byte("doesn't matter"), config.Options{})
		if err != nil {
			t.Fatalf("DetectConfig: %v", err)
		}
		if v != "acme" {
			t.Errorf("vendor = %q, expected acme", v)
		}
		if m != want {
			t.Errorf("unexpected model: %+v", m)
		}
	})
}

func TestDetectConfigUnrecognized(t *testing.T) {
	withRegistry(t, func() {
		RegisterConfigParser(fakeParser{vendor: "acme", matches: false})
		RegisterConfigParser(fakeParser{vendor: "beta", matches: false})

		_, _, err := DetectConfig([]byte("nothing recognized"), config.Options{})
		var uf *UnrecognizedFormatError
		if !errors.As(err, &uf) {
			t.Fatalf("expected UnrecognizedFormatError, got %T: %v", err, err)
		}
		if len(uf.Attempts) != 2 {
			t.Errorf("expected 2 attempts, got %d: %+v", len(uf.Attempts), uf.Attempts)
		}
		if uf.Error() == "" {
			t.Error("empty error message")
		}
	})
}

func TestDetectConfigAmbiguous(t *testing.T) {
	withRegistry(t, func() {
		RegisterConfigParser(fakeParser{vendor: "acme", matches: true})
		RegisterConfigParser(fakeParser{vendor: "beta", matches: true})

		_, _, err := DetectConfig([]byte("matches both"), config.Options{})
		var af *AmbiguousFormatError
		if !errors.As(err, &af) {
			t.Fatalf("expected AmbiguousFormatError, got %T: %v", err, err)
		}
		if len(af.Vendors) != 2 {
			t.Errorf("expected 2 vendors, got %d: %v", len(af.Vendors), af.Vendors)
		}
	})
}

func TestDetectConfigNoParsersRegistered(t *testing.T) {
	withRegistry(t, func() {
		_, _, err := DetectConfig([]byte("whatever"), config.Options{})
		var uf *UnrecognizedFormatError
		if !errors.As(err, &uf) {
			t.Fatalf("expected UnrecognizedFormatError, got %T: %v", err, err)
		}
	})
}

func TestParseConfigAsExplicitFallback(t *testing.T) {
	withRegistry(t, func() {
		want := &config.Model{SourceFormat: "xml"}
		RegisterConfigParser(fakeParser{vendor: "acme", matches: true, model: want})
		RegisterConfigParser(fakeParser{vendor: "beta", matches: true})

		// Ambiguity blocks DetectConfig, but the explicit selection
		// (the fallback documented by the backlog) still works.
		m, err := ParseConfigAs("acme", []byte("doesn't matter"), config.Options{})
		if err != nil {
			t.Fatalf("ParseConfigAs: %v", err)
		}
		if m != want {
			t.Errorf("unexpected model: %+v", m)
		}

		if _, err := ParseConfigAs("unknown", nil, config.Options{}); err == nil {
			t.Error("expected an error for an unregistered vendor")
		}
	})
}

func TestRegisterConfigParserDuplicatePanics(t *testing.T) {
	withRegistry(t, func() {
		RegisterConfigParser(fakeParser{vendor: "acme", matches: true})
		defer func() {
			if recover() == nil {
				t.Error("expected a panic on duplicate registration")
			}
		}()
		RegisterConfigParser(fakeParser{vendor: "acme", matches: true})
	})
}

func TestCounterParserForRoundTrip(t *testing.T) {
	withRegistry(t, func() {
		want := map[rules.PolicyKey]rules.HitInfo{
			{FromZone: "a", ToZone: "b", Name: "p"}: {Count: 0, Action: "permit"},
		}
		RegisterCounterParser(counterFakeParser{vendor: "acme", hits: want})

		p, ok := CounterParserFor("acme")
		if !ok {
			t.Fatal("counter parser not found")
		}
		got, err := p.ParseCounters(nil)
		if err != nil {
			t.Fatalf("ParseCounters: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("expected 1 entry, got %d", len(got))
		}

		if _, ok := CounterParserFor("unknown"); ok {
			t.Error("no parser should be found for an unregistered vendor")
		}
	})
}

type counterFakeParser struct {
	vendor Vendor
	hits   map[rules.PolicyKey]rules.HitInfo
}

func (f counterFakeParser) Vendor() Vendor { return f.vendor }
func (f counterFakeParser) ParseCounters(data []byte) (map[rules.PolicyKey]rules.HitInfo, error) {
	return f.hits, nil
}
