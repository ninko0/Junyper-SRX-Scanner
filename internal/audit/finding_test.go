package audit

import (
	"errors"
	"testing"
)

func TestQ(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", `""`},
		{"normal-name", "normal-name"},
		{"a name with spaces", `"a name with spaces"`},
		{`a"quote`, `"a\"quote"`},
	}
	for _, c := range cases {
		got, err := q(c.in)
		if err != nil {
			t.Fatalf("q(%q): unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("q(%q) = %q, expected %q", c.in, got, c.want)
		}
	}
}

func TestQUnsafeName(t *testing.T) {
	for _, in := range []string{"bad;name", "bad\nname", "bad{name", "bad}name", "bad\rname"} {
		_, err := q(in)
		if !errors.Is(err, ErrUnsafeName) {
			t.Errorf("q(%q): expected ErrUnsafeName, got %v", in, err)
		}
	}
}
