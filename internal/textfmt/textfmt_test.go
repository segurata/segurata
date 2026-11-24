package textfmt

import "testing"

func TestOrDash(t *testing.T) {
	if got := OrDash(""); got != "-" {
		t.Errorf(`OrDash("") = %q`, got)
	}
	if got := OrDash("P1"); got != "P1" {
		t.Errorf(`OrDash("P1") = %q`, got)
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{0: "files", 1: "file", 2: "files"} {
		if got := Plural(n, "file", "files"); got != want {
			t.Errorf("Plural(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{{"short", 10, "short"}, {"exactly10!", 10, "exactly10!"}, {"a longer title", 5, "a lo…"}, {"ñañañaña", 4, "ñañ…"}} {
		if got := Truncate(c.in, c.n); got != c.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}
