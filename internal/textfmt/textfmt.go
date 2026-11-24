// Package textfmt holds the small wording helpers the command-line tables and messages share.
package textfmt

import "strings"

// OrDash is s, or "-" when s is empty, for table cells.
func OrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Plural is one when n is 1, else many.
func Plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Truncate cuts s to n runes, the last one an ellipsis, when it is longer. A cut that would fall
// inside a `code span` moves to before its opening backtick, so a command is never shown half.
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

// Clip splits a text into a head of at most n runes and the rest, for views that show the head and
// fold the rest away. The head is the first line; when that is longer than n it ends at the last
// sentence end (". ", "; ", ": ", "! ", "? ") that fits, or else at the last word that fits followed
// by an ellipsis. It never ends inside a `code span`. The rest keeps its line breaks.
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
