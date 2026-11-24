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

func TestCount(t *testing.T) {
	for n, want := range map[int]string{0: "0 integrations", 1: "1 integration", 4: "4 integrations"} {
		if got := Count(n, "integration", "integrations"); got != want {
			t.Errorf("Count(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPluralPredicate(t *testing.T) {
	for _, c := range []struct {
		n        int
		in, want string
	}{
		{1, "can read the Notion pages shared with it", "can read the Notion pages shared with it"},
		{15, "can read the Notion pages shared with it", "can read the Notion pages shared with them"},
		{4, "can act on the repositories it is installed on (its permissions need sudo mode to read)",
			"can act on the repositories they are installed on (their permissions need sudo mode to read)"},
		{2, "can act on your repositories again if it is unsuspended", "can act on your repositories again if they are unsuspended"},
		{3, "can act on your behalf within its GitHub App permissions", "can act on your behalf within their GitHub App permissions"},
		{2, "can edit items it has opened", "can edit items they have opened"},
		// Words that contain "it" are left alone.
		{5, "can edit your posts with item limits", "can edit your posts with item limits"},
	} {
		if got := PluralPredicate(c.n, c.in); got != c.want {
			t.Errorf("PluralPredicate(%d, %q) = %q, want %q", c.n, c.in, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"}, {"exactly10!", 10, "exactly10!"}, {"a longer title", 5, "a lo…"}, {"ñañañaña", 4, "ñañ…"},
		// Never inside a code span: the cut moves before the opening backtick.
		{"run `git filter-repo --path x` now", 12, "run…"},
		{"run `ls` and then more", 12, "run `ls` an…"},
	} {
		if got := Truncate(c.in, c.n); got != c.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestClip(t *testing.T) {
	for _, c := range []struct {
		in         string
		n          int
		head, rest string
	}{
		{"Short.", 40, "Short.", ""},
		// Cut at the last sentence end that fits.
		{"Treat it as exposed. Rotate every key. Remove it from history.", 45, "Treat it as exposed. Rotate every key.", "Remove it from history."},
		// A sentence end inside a code span does not count, nor does a cut inside it.
		{"Run `a. b c d e f` then go on and on", 20, "Run `a. b c d e f`…", "…then go on and on"},
		{"Run `a. b c d e f g h` then", 12, "Run…", "…`a. b c d e f g h` then"},
		// No sentence end: the last whole word, with an ellipsis.
		{"one two three four five", 12, "one two…", "…three four five"},
		// Multi-line: the first line is the head, the other lines stay as they are.
		{"Steps:\n1. sign in\n2. revoke", 40, "Steps:", "1. sign in\n2. revoke"},
	} {
		head, rest := Clip(c.in, c.n)
		if head != c.head || rest != c.rest {
			t.Errorf("Clip(%q, %d) = %q, %q; want %q, %q", c.in, c.n, head, rest, c.head, c.rest)
		}
		if len([]rune(head)) > c.n {
			t.Errorf("Clip(%q, %d): head %q is longer than %d", c.in, c.n, head, c.n)
		}
	}
}
