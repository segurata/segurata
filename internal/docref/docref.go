// Package docref links user-facing text to the project's files on GitHub: a binary installed with
// go install has no copy of the repository, so a repo-relative path would point nowhere.
package docref

import (
	"strconv"
	"strings"
	"unicode"
)

// Repo is the root of the repository's main branch on GitHub; Docs is its docs/ folder.
const (
	Repo = "https://github.com/segurata/segurata/blob/main/"
	Docs = Repo + "docs/"
)

// Anchors are the fragment ids GitHub gives the headings of a Markdown document, so a test can
// check that a link's #anchor exists. Headings inside fenced code blocks are not headings.
func Anchors(markdown string) map[string]bool {
	anchors := map[string]bool{}
	seen := map[string]int{}
	fenced := false
	for _, line := range strings.Split(markdown, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		text := strings.TrimLeft(line, "#")
		if fenced || text == line || !strings.HasPrefix(text, " ") {
			continue
		}
		slug := Slug(text)
		if n := seen[slug]; n > 0 {
			anchors[slug+"-"+strconv.Itoa(n)] = true
		} else {
			anchors[slug] = true
		}
		seen[slug]++
	}
	return anchors
}

// Slug is GitHub's anchor for a heading: lower case, punctuation dropped, spaces as hyphens.
func Slug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(heading)) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}
