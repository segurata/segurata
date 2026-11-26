// Package textfmt holds the small wording helpers the command-line tables and messages share.
package textfmt

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Terminal makes control characters visible in a value shown to a terminal user.
func Terminal(s string) string {
	if utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsGraphic(r) }) == -1 {
		return s
	}
	quoted := strconv.QuoteToGraphic(s)
	return quoted[1 : len(quoted)-1]
}

// Line writes one line through Terminal.
func Line(w io.Writer, format string, a ...any) {
	fmt.Fprintln(w, Terminal(fmt.Sprintf(format, a...)))
}

func OrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func Plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func Count(n int, one, many string) string {
	return fmt.Sprintf("%d %s", n, Plural(n, one, many))
}

func UpperFirst(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	if size == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[size:]
}

// JoinAnd lists items as prose: "a", "a and b", "a, b and c"; "" for none.
func JoinAnd(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func USD(v float64) string { return fmt.Sprintf("$%.2f", v) }

// pronouns rewrite a predicate about "it" for several, longest first.
var pronouns = []struct {
	re   *regexp.Regexp
	many string
}{
	{regexp.MustCompile(`\bit is\b`), "they are"},
	{regexp.MustCompile(`\bit was\b`), "they were"},
	{regexp.MustCompile(`\bit has\b`), "they have"},
	{regexp.MustCompile(`\bits\b`), "their"},
	{regexp.MustCompile(`\bit\b`), "them"},
}

// PluralPredicate rewrites a predicate about one subject for n of them: "it is shared with it"
// becomes "they are shared with them".
func PluralPredicate(n int, predicate string) string {
	if n == 1 {
		return predicate
	}
	for _, p := range pronouns {
		predicate = p.re.ReplaceAllString(predicate, p.many)
	}
	return predicate
}

// Truncate cuts s to n runes ending in an ellipsis, never inside a `code span`.
func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := n - 1
	if open := openTick(r[:cut]); open >= 0 {
		cut = open
	}
	return strings.TrimRight(string(r[:cut]), " ") + "…"
}

// openTick is the index of the backtick that opens a code span still open at the end of r, or -1.
func openTick(r []rune) int {
	open := -1
	for i, c := range r {
		if c == '`' {
			if open < 0 {
				open = i
			} else {
				open = -1
			}
		}
	}
	return open
}

// Clip splits text into a head of at most n runes, its first line cut at the last sentence or else
// word end that fits and never inside a `code span`, and the rest with its line breaks.
func Clip(s string, n int) (head, rest string) {
	s = strings.TrimSpace(s)
	first, more, _ := strings.Cut(s, "\n")
	first, more = strings.TrimSpace(first), strings.TrimSpace(more)
	r := []rune(first)
	if len(r) <= n {
		return first, more
	}
	sentence, word, inTick := -1, -1, false
	for i := 0; i < n && i < len(r); i++ {
		switch c := r[i]; {
		case c == '`':
			inTick = !inTick
		case inTick:
		case c == ' ' && i > 0 && strings.ContainsRune(".;:!?", r[i-1]):
			sentence, word = i, i
		case c == ' ':
			word = i
		}
	}
	join := func(a, b string) string {
		a, b = strings.TrimSpace(a), strings.TrimSpace(b)
		if b == "" {
			return a
		}
		return a + "\n" + b
	}
	switch {
	case sentence > 0:
		return strings.TrimSpace(string(r[:sentence])), join(string(r[sentence:]), more)
	case word > 0:
		return strings.TrimSpace(string(r[:word])) + "…", join("…"+strings.TrimSpace(string(r[word:])), more)
	}
	t := Truncate(first, n)
	cut := len([]rune(t)) - 1
	return t, join("…"+string(r[cut:]), more)
}
