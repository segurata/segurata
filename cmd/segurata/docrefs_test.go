package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// docCite is a citation of a document section by heading: `README, "Quickstart"`,
// `docs/architecture.md, "Verbs"`. Comment markers between its lines are joined first.
var (
	docCite      = regexp.MustCompile(`\b((?:[\w-]+/)*[\w-]+\.md|README),\s+"([^"]+)"`)
	commentBreak = regexp.MustCompile(`\n\s*(?://|#)\s*`)
)

// TestCitedHeadingsExist fails on a citation of a section that no heading of the cited document
// has, so a renamed heading cannot leave code and docs pointing nowhere.
func TestCitedHeadingsExist(t *testing.T) {
	const root = "../.."
	headings := map[string]map[string]bool{}
	headingsOf := func(doc string) map[string]bool {
		if h, ok := headings[doc]; ok {
			return h
		}
		raw, err := os.ReadFile(doc)
		if err != nil {
			headings[doc] = nil
			return nil
		}
		h := map[string]bool{}
		for _, line := range strings.Split(string(raw), "\n") {
			if text, ok := strings.CutPrefix(strings.TrimLeft(line, "#"), " "); ok && strings.HasPrefix(line, "#") {
				// "Browser extensions (`browser-extensions`)" is cited as "Browser extensions".
				text, _, _ = strings.Cut(text, " (`")
				h[strings.TrimSpace(text)] = true
			}
		}
		headings[doc] = h
		return h
	}
	cites := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".go" && ext != ".md" && ext != ".py" && ext != "" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if filepath.Ext(path) == "" && !strings.HasPrefix(string(raw), "#!") {
			return nil // a built binary, not a script
		}
		text := commentBreak.ReplaceAllString(strings.ReplaceAll(string(raw), `\"`, `"`), " ")
		for _, m := range docCite.FindAllStringSubmatch(text, -1) {
			cites++
			name := m[1]
			if name == "README" {
				name = "README.md"
			}
			// The citing file's folder first, then the repository root, then docs/.
			var found map[string]bool
			for _, dir := range []string{filepath.Dir(path), root, filepath.Join(root, "docs")} {
				if found = headingsOf(filepath.Join(dir, name)); found != nil {
					break
				}
			}
			rel, _ := filepath.Rel(root, path)
			switch {
			case found == nil:
				t.Errorf("%s cites %s, which does not exist", rel, m[1])
			case !found[m[2]]:
				t.Errorf("%s cites %s, %q: no such heading", rel, m[1], m[2])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cites < 40 {
		t.Fatalf("found only %d citations: the pattern no longer matches how sections are cited", cites)
	}
}
