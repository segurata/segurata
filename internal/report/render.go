package report

import (
	"fmt"
	"html"
	"io"
	"net/url"
	"strings"
	"text/tabwriter"
)

// Format is an output format of `securizame report`.
type Format string

const (
	Text     Format = "text"
	Markdown Format = "md"
	HTML     Format = "html"
)

// Render writes the report in the given format.
func (r *Report) Render(w io.Writer, f Format) error {
	d := r.document()
	switch f {
	case Text:
		renderText(w, d)
	case Markdown:
		renderMarkdown(w, d)
	case HTML:
		renderHTML(w, d)
	default:
		return fmt.Errorf("unknown format %q (text, md or html)", f)
	}
	return nil
}

// --- terminal text ---

func renderText(w io.Writer, d *doc) {
	for _, b := range d.blocks {
		switch b.kind {
		case bHeading:
			t := plain(b.spans)
			switch b.level {
			case 1:
				fmt.Fprintf(w, "%s\n%s\n", strings.ToUpper(t), strings.Repeat("=", len(t)))
			case 2:
				fmt.Fprintf(w, "\n%s\n%s\n", t, strings.Repeat("-", len([]rune(t))))
			default:
				fmt.Fprintf(w, "\n%s\n", t)
			}
		case bPara:
			fmt.Fprintln(w, plain(b.spans))
		case bList:
			for _, it := range b.items {
				lead := "  "
				if it.badge != "" {
					lead += "[" + it.badge + "] "
				}
				fmt.Fprintln(w, lead+it.text)
				if it.meta != "" {
					fmt.Fprintf(w, "      %s\n", it.meta)
				}
				for _, dt := range it.details {
					fmt.Fprintf(w, "      %s: %s\n", dt.label, dt.text)
				}
			}
		case bTable:
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, strings.Join(b.head, "\t"))
			for _, row := range b.rows {
				cells := make([]string, len(row))
				for j, c := range row {
					cells[j] = c.text
				}
				fmt.Fprintln(tw, strings.Join(cells, "\t"))
			}
			tw.Flush()
		}
	}
}

// --- Markdown ---

// mdEscape backslash-escapes the characters Markdown would read as markup, including < so a
// title cannot open an HTML tag in a viewer.
func mdEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\`*_[]<>|#!~", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// mdCode wraps s in a code span long enough not to be closed by backticks inside it.
func mdCode(s string) string {
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	return fence + " " + s + " " + fence
}

func mdSpans(spans []span) string {
	var b strings.Builder
	for _, s := range spans {
		if s.code {
			b.WriteString(mdCode(s.text))
		} else {
			b.WriteString(mdEscape(s.text))
		}
	}
	return b.String()
}

func renderMarkdown(w io.Writer, d *doc) {
	for _, b := range d.blocks {
		switch b.kind {
		case bHeading:
			fmt.Fprintf(w, "%s %s\n\n", strings.Repeat("#", b.level), mdSpans(b.spans))
		case bPara:
			fmt.Fprintf(w, "%s\n\n", mdSpans(b.spans))
		case bList:
			for _, it := range b.items {
				lead := "- "
				if it.badge != "" {
					lead += "**" + mdEscape(it.badge) + "** "
				}
				fmt.Fprintln(w, lead+mdEscape(it.text))
				if it.meta != "" {
					fmt.Fprintf(w, "  - %s\n", mdEscape(it.meta))
				}
				for _, dt := range it.details {
					fmt.Fprintf(w, "  - %s: %s\n", mdEscape(dt.label), mdDetail(dt))
				}
			}
			fmt.Fprintln(w)
		case bTable:
			esc := func(s string) string { return strings.ReplaceAll(mdEscape(s), "\n", " ") }
			head := make([]string, len(b.head))
			sep := make([]string, len(b.head))
			for i, h := range b.head {
				head[i], sep[i] = esc(h), "---"
				if len(b.rows) > 0 && i < len(b.rows[0]) && b.rows[0][i].num {
					sep[i] = "---:"
				}
			}
			fmt.Fprintf(w, "| %s |\n| %s |\n", strings.Join(head, " | "), strings.Join(sep, " | "))
			for _, row := range b.rows {
				cells := make([]string, len(row))
				for i, c := range row {
					cells[i] = esc(c.text)
				}
				fmt.Fprintf(w, "| %s |\n", strings.Join(cells, " | "))
			}
			fmt.Fprintln(w)
		}
	}
}

func mdDetail(dt detail) string {
	switch dt.kind {
	case dCode:
		return mdCode(dt.text)
	case dLink:
		if safeURL(dt.text) {
			return "<" + dt.text + ">"
		}
	}
	return mdEscape(dt.text)
}

// safeURL accepts only absolute http(s) URLs without characters that would break out of a link.
func safeURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && !strings.ContainsAny(s, "<>\" \n")
}

// --- HTML ---

// The page is one file: inline CSS, no script, no external asset, and a CSP that forbids loading
// anything, so opening it never contacts a server.
const htmlHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<title>%s</title>
<style>
:root {
  --bg: #fbfbfa; --fg: #1d1d1f; --muted: #6b6b70; --line: #e3e3e0; --card: #ffffff; --code: #f1f1ee;
  --critical: #b3261e; --high: #c2410c; --medium: #a16207; --low: #2563eb; --info: #6b7280; --ok: #15803d;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #131315; --fg: #e8e8ea; --muted: #9a9aa2; --line: #2c2c30; --card: #1b1b1e; --code: #26262a;
    --critical: #f2b8b5; --high: #fdba74; --medium: #fcd34d; --low: #93c5fd; --info: #a1a1aa; --ok: #86efac;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 1.6rem; margin: 0 0 8px; }
h2 { font-size: 1.2rem; margin: 32px 0 8px; padding-top: 16px; border-top: 1px solid var(--line); }
h3 { font-size: 1rem; margin: 20px 0 8px; }
p { margin: 8px 0; }
code { font: 13px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; background: var(--code);
  padding: 1px 5px; border-radius: 4px; overflow-wrap: anywhere; }
a { color: var(--low); overflow-wrap: anywhere; }
ul { list-style: none; padding: 0; margin: 8px 0; }
li { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; margin: 8px 0; }
.text { overflow-wrap: anywhere; }
.meta { color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }
.detail { font-size: 14px; margin-top: 4px; overflow-wrap: anywhere; }
.detail b { font-weight: 600; }
.badge { display: inline-block; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .03em;
  padding: 0 6px; border-radius: 4px; border: 1px solid currentColor; margin-right: 6px; color: var(--muted); }
.b-critical, .b-P0, .b-error, .b-expired { color: var(--critical); }
.b-high, .b-P1, .b-reauth, .b-missing_credentials { color: var(--high); }
.b-medium, .b-P2, .b-signedout { color: var(--medium); }
.b-low, .b-P3 { color: var(--low); }
.b-resolved, .b-accepted { color: var(--ok); }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%%; font-size: 14px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-weight: 600; white-space: nowrap; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
</style>
</head>
<body>
<main>
`

func badgeHTML(b string) string {
	if b == "" {
		return ""
	}
	return `<span class="badge b-` + html.EscapeString(b) + `">` + html.EscapeString(b) + `</span>`
}

func htmlSpans(spans []span) string {
	var b strings.Builder
	for _, s := range spans {
		if s.code {
			b.WriteString("<code>" + html.EscapeString(s.text) + "</code>")
		} else {
			b.WriteString(html.EscapeString(s.text))
		}
	}
	return b.String()
}

func renderHTML(w io.Writer, d *doc) {
	fmt.Fprintf(w, htmlHead, html.EscapeString(d.title))
	for _, b := range d.blocks {
		switch b.kind {
		case bHeading:
			fmt.Fprintf(w, "<h%d>%s</h%d>\n", b.level, htmlSpans(b.spans), b.level)
		case bPara:
			fmt.Fprintf(w, "<p>%s</p>\n", htmlSpans(b.spans))
		case bList:
			fmt.Fprintln(w, "<ul>")
			for _, it := range b.items {
				fmt.Fprintf(w, `<li><div class="text">%s%s</div>`, badgeHTML(it.badge), html.EscapeString(it.text))
				if it.meta != "" {
					fmt.Fprintf(w, `<div class="meta">%s</div>`, html.EscapeString(it.meta))
				}
				for _, dt := range it.details {
					fmt.Fprintf(w, `<div class="detail"><b>%s:</b> %s</div>`, html.EscapeString(dt.label), htmlDetail(dt))
				}
				fmt.Fprintln(w, "</li>")
			}
			fmt.Fprintln(w, "</ul>")
		case bTable:
			fmt.Fprint(w, `<div class="scroll"><table><thead><tr>`)
			for i, h := range b.head {
				fmt.Fprintf(w, "<th%s>%s</th>", numClass(b, i), html.EscapeString(h))
			}
			fmt.Fprint(w, "</tr></thead><tbody>\n")
			for _, row := range b.rows {
				fmt.Fprint(w, "<tr>")
				for _, c := range row {
					cls, text := "", html.EscapeString(c.text)
					if c.num {
						cls = ` class="num"`
					}
					if c.badge {
						text = badgeHTML(c.text)
					}
					fmt.Fprintf(w, "<td%s>%s</td>", cls, text)
				}
				fmt.Fprint(w, "</tr>\n")
			}
			fmt.Fprintln(w, "</tbody></table></div>")
		}
	}
	fmt.Fprintln(w, "</main>\n</body>\n</html>")
}

func numClass(b block, col int) string {
	if len(b.rows) > 0 && col < len(b.rows[0]) && b.rows[0][col].num {
		return ` class="num"`
	}
	return ""
}

func htmlDetail(dt detail) string {
	t := html.EscapeString(dt.text)
	switch dt.kind {
	case dCode:
		return "<code>" + t + "</code>"
	case dLink:
		if safeURL(dt.text) {
			return `<a href="` + t + `" rel="noreferrer noopener">` + t + `</a>`
		}
	}
	return t
}
