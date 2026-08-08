package junosname

import (
	"errors"
	"testing"
)

func TestQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", `""`},
		{"normal-name", "normal-name"},
		{"a name with spaces", `"a name with spaces"`},
		{`a"quote`, `"a\"quote"`},
	}
	for _, c := range cases {
		got, err := Quote(c.in)
		if err != nil {
			t.Fatalf("Quote(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("Quote(%q) = %q, expected %q", c.in, got, c.want)
		}
	}
}

func TestQuoteUnsafe(t *testing.T) {
	for _, in := range []string{"bad;name", "bad\nname", "bad{name", "bad}name"} {
		if _, err := Quote(in); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Quote(%q): expected ErrUnsafeName", in)
		}
	}
}

func TestValidateNewName(t *testing.T) {
	for _, ok := range []string{"a", "a1", "web-corp-01", "a.b:c/d@e+f_g"} {
		if _, err := ValidateNewName(ok, ""); err != nil {
			t.Errorf("ValidateNewName(%q) should pass: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-leading-dash", " space", "a;b", "a b", string(make([]byte, 64))} {
		if _, err := ValidateNewName(bad, ""); err == nil {
			t.Errorf("ValidateNewName(%q) should fail", bad)
		}
	}
}
