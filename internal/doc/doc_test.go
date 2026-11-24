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
	d.H(1, d.Title)
	d.P("run ", Code("securizame status"), " now")
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
		for _, want := range []string{"securizame status", "P0", "https://example.com/x", "row"} {
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
}
