// Package doc is the small document model segurata's reports are built with (headings,
// paragraphs, lists, tables) and its three renderers: terminal text, Markdown and a self-contained
// HTML page. A document is built once and rendered by format, so the formats always say the same
// thing. Markdown escapes markup in titles; HTML escapes everything, links only absolute http(s)
// URLs, has no script and loads nothing.
package doc

import (
	"fmt"
	"strings"
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

// DetailKind says how a detail's text renders.
type DetailKind int

const (
	DText DetailKind = iota
	DCode
	DLink
)

// Detail is one labelled line under a list item.
type Detail struct {
	Label, Text string
	Kind        DetailKind
}

// Item is one entry of a list: a badge (severity, priority or state), the text, a muted meta line
// and labelled details.
type Item struct {
	Badge, Text, Meta string
	Details           []Detail
}

// Cell is one table cell.
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

// Doc is a document: a title and its blocks in order.
type Doc struct {
	Title  string
	blocks []block
}

// H adds a heading of the given level (1 to 3).
func (d *Doc) H(level int, text string) {
	d.blocks = append(d.blocks, block{kind: bHeading, level: level, spans: []span{{text: text}}})
}

// P adds a paragraph from strings and Code values.
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

// List adds a list; an empty one adds nothing.
func (d *Doc) List(items []Item) {
	if len(items) > 0 {
		d.blocks = append(d.blocks, block{kind: bList, items: items})
	}
}

// Table adds a table.
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
