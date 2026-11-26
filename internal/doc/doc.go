// Package doc is the document model reports are built with, rendered as terminal text, Markdown or
// a self-contained HTML page, so the formats always say the same thing. Markdown escapes markup in
// titles; HTML escapes everything, links only absolute http(s) URLs, has no script and loads
// nothing.
package doc

import (
	"fmt"
	"strings"

	"github.com/segurata/segurata/internal/textfmt"
)

type blockKind int

const (
	bHeading blockKind = iota
	bPara
	bList
	bTable
)

// span is a run of paragraph text; code spans are commands or ids to copy.
type span struct {
	text string
	code bool
}

// Code marks a part of P as a command or an id.
type Code string

type DetailKind int

const (
	DText DetailKind = iota
	DCode
	DLink
)

// Detail is one labelled line under a list item; More folds under it ("[…]" in terminal text).
type Detail struct {
	Label, Text string
	Kind        DetailKind
	More        string
}

// Fold is a text detail that shows the textfmt.Clip head of text and folds the rest.
func Fold(label, text string, n int) Detail {
	head, more := textfmt.Clip(text, n)
	return Detail{Label: label, Text: head, More: more}
}

// Item is one list entry; Badge is a severity, priority or state.
type Item struct {
	Badge, Text, Meta string
	Details           []Detail
}

type Cell struct {
	Text  string
	Badge bool // text is a severity, priority or state
	Num   bool
}

type block struct {
	kind  blockKind
	level int
	spans []span
	items []Item
	head  []string
	rows  [][]Cell
}

type Doc struct {
	Title  string
	blocks []block
}

// H adds a heading of level 1 to 3.
func (d *Doc) H(level int, text string) {
	d.blocks = append(d.blocks, block{kind: bHeading, level: level, spans: []span{{text: text}}})
}

// P adds a paragraph of strings and Code values.
func (d *Doc) P(parts ...any) {
	var spans []span
	for _, x := range parts {
		switch v := x.(type) {
		case Code:
			spans = append(spans, span{text: string(v), code: true})
		default:
			spans = append(spans, span{text: fmt.Sprint(v)})
		}
	}
	d.blocks = append(d.blocks, block{kind: bPara, spans: spans})
}

// List adds a list unless it is empty.
func (d *Doc) List(items []Item) {
	if len(items) > 0 {
		d.blocks = append(d.blocks, block{kind: bList, items: items})
	}
}

func (d *Doc) Table(head []string, rows [][]Cell) {
	d.blocks = append(d.blocks, block{kind: bTable, head: head, rows: rows})
}

func plain(spans []span) string {
	var b strings.Builder
	for _, s := range spans {
		b.WriteString(s.text)
	}
	return b.String()
}
