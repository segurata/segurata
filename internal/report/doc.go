package report

import (
	"fmt"
	"strings"
)

// A report is built once as a small document (headings, paragraphs, lists, tables) and rendered
// by format, so the three formats always say the same thing.

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

// code marks a span as a command or an id in para.
type code string

type detailKind int

const (
	dText detailKind = iota
	dCode
	dLink
)

type detail struct {
	label, text string
	kind        detailKind
}

// item is one entry of a list: a badge (severity, priority or state), the text, a muted meta line
// and labelled details.
type item struct {
	badge, text, meta string
	details           []detail
}

type cell struct {
	text  string
	badge bool // text is a severity, priority or state
	num   bool
}

type block struct {
	kind  blockKind
	level int
	spans []span
	items []item
	head  []string
	rows  [][]cell
}

type doc struct {
	title  string
	blocks []block
}

func (d *doc) h(level int, text string) {
	d.blocks = append(d.blocks, block{kind: bHeading, level: level, spans: []span{{text: text}}})
}

// p adds a paragraph from strings and code values.
func (d *doc) p(parts ...any) {
	var spans []span
	for _, x := range parts {
		switch v := x.(type) {
		case code:
			spans = append(spans, span{text: string(v), code: true})
		default:
			spans = append(spans, span{text: fmt.Sprint(v)})
		}
	}
	d.blocks = append(d.blocks, block{kind: bPara, spans: spans})
}

func (d *doc) list(items []item) {
	if len(items) > 0 {
		d.blocks = append(d.blocks, block{kind: bList, items: items})
	}
}

func (d *doc) table(head []string, rows [][]cell) {
	d.blocks = append(d.blocks, block{kind: bTable, head: head, rows: rows})
}

func plain(spans []span) string {
	var b strings.Builder
	for _, s := range spans {
		b.WriteString(s.text)
	}
	return b.String()
}
