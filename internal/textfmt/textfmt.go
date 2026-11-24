// Package textfmt holds the small wording helpers the command-line tables and messages share.
package textfmt

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

// Truncate cuts s to n runes, the last one an ellipsis, when it is longer.
func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
