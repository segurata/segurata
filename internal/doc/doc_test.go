package doc

import (
	"bytes"
	"strings"
	"testing"
)

func TestEscapingHelpers(t *testing.T) {
	if mdCode("a`b") != "`` a`b ``" {
		t.Errorf("code span %q", mdCode("a`b"))
	}
	if safeURL("javascript:alert(1)") || safeURL("https://x.example/\"><b>") || !safeURL("https://x.example/a?b=c") {
		t.Error("safeURL")
	}
	if EscapeMarkdown("a <b> *c*") != `a \<b\> \*c\*` {
		t.Errorf("escape %q", EscapeMarkdown("a <b> *c*"))
	}
}

func TestEveryFormatRendersTheSameContent(t *testing.T) {
	d := &Doc{Title: "t"}
	d.H(1, "Résumé")
	d.P("run ", Code("segurata status"), " now")
	d.List([]Item{{Badge: "P0", Text: "Rotate <key>", Meta: "id 1", Details: []Detail{{Label: "Where", Text: "https://example.com/x", Kind: DLink}}}})
	d.Table([]string{"A", "N"}, [][]Cell{{{Text: "row"}, {Text: "3", Num: true}}})
	for _, f := range []Format{Text, Markdown, HTML} {
		if !f.Valid() {
			t.Fatalf("%s not valid", f)
		}
		var b bytes.Buffer
		if err := Render(&b, d, f); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"segurata status", "P0", "https://example.com/x", "row"} {
			if !strings.Contains(b.String(), want) {
				t.Errorf("%s lacks %q", f, want)
			}
		}
		if f != Text && strings.Contains(b.String(), "<key>") {
			t.Errorf("%s does not escape a title", f)
		}
	}
	if Format("pdf").Valid() || Render(&bytes.Buffer{}, d, "pdf") == nil {
		t.Error("unknown format accepted")
	}
	var text bytes.Buffer
	_ = Render(&text, d, Text)
	if !strings.HasPrefix(text.String(), "RÉSUMÉ\n======\n") {
		t.Errorf("a heading's rule must match its length in characters:\n%s", text.String())
	}
	var md, page bytes.Buffer
	_ = Render(&md, d, Markdown)
	_ = Render(&page, d, HTML)
	if !strings.Contains(md.String(), "| --- | ---: |") || !strings.Contains(page.String(), `<th class="num">N</th>`) {
		t.Errorf("a numeric column is not right-aligned:\n%s\n%s", md.String(), page.String())
	}
}

func TestFoldShowsTheHeadAndFoldsTheRest(t *testing.T) {
	dt := Fold("Next", "Treat it as exposed. Run `git filter-repo --path a.sql --invert-paths` and force-push.\nThen check the breach duty.", 30)
	if dt.Text != "Treat it as exposed." || !strings.Contains(dt.More, "git filter-repo") || !strings.Contains(dt.More, "\nThen check") {
		t.Fatalf("Fold = %+v", dt)
	}
	d := &Doc{Title: "t"}
	d.List([]Item{{Text: "item", Details: []Detail{dt}}})
	want := map[Format][]string{
		Text:     {"Next: Treat it as exposed. […]"},
		Markdown: {"<details><summary>Next: Treat it as exposed.</summary>", "Then check the breach duty.<br>", "</details>"},
		HTML:     {`<details class="detail"><summary><b>Next:</b> Treat it as exposed.</summary>`, "force-push.<br>Then check"},
	}
	for f, ws := range want {
		var b bytes.Buffer
		if err := Render(&b, d, f); err != nil {
			t.Fatal(err)
		}
		for _, w := range ws {
			if !strings.Contains(b.String(), w) {
				t.Errorf("%s lacks %q:\n%s", f, w, b.String())
			}
		}
		if f == Text && strings.Contains(b.String(), "filter-repo") {
			t.Errorf("text shows the folded part:\n%s", b.String())
		}
	}
}
