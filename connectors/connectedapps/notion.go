package connectedapps

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/segurata/segurata/connectors/internal/pagetext"
	"github.com/segurata/segurata/internal/finding"
)

// Notion has no URL for Settings › Connections (a dialog). The page with a URL is the active
// workspace's developer connections: internal integrations, their capabilities and owners.
const (
	notionURL    = "https://www.notion.so/profile/integrations"
	notionRevoke = `Open the page, pick the integration and delete it (or remove it from the pages it can reach). Its API token stops working.`
)

// Each table row becomes its cells, each cell its lines.
const notionJS = `(() => ({
  url: location.href, text: document.body ? document.body.innerText : "",
  cells: [...document.querySelectorAll("tr")].map((r) => [...r.querySelectorAll("td")].map((td) => (td.innerText || "").split("\n").map((s) => s.trim()).filter(Boolean))).filter((c) => c.length >= 4 && c[0].length)
}))()`

type notionPage struct {
	URL   string       `json:"url"`
	Text  string       `json:"text"`
	Cells [][][]string `json:"cells"`
}

var (
	notionSignedOutRE = regexp.MustCompile(`/login|^https://www\.notion\.com/?$`)
	notionEmptyRE     = regexp.MustCompile(`(?i)No connections|Sin conexiones`)
	notionInternalRE  = regexp.MustCompile(`^(Internal to|Interna de) `)
)

type notionIntegration struct {
	name, workspace, auth, owner, created string
	scopes                                []string
}

// parseNotionRow reads the cells connection, authorization, owner and created. The first line of
// the connection cell can be the avatar's initial.
func parseNotionRow(cells [][]string) notionIntegration {
	conn, auth, owner, created := cells[0], cells[1], cells[2], cells[3]
	if len(conn) > 2 && len([]rune(conn[0])) == 1 {
		conn = conn[1:]
	}
	n := notionIntegration{name: conn[0], scopes: []string{}, owner: strings.Join(owner, " ")}
	if len(conn) > 1 {
		n.scopes = []string{conn[1]}
	}
	if len(auth) > 0 {
		n.auth = auth[0]
	}
	if len(auth) > 1 {
		n.workspace = notionInternalRE.ReplaceAllString(auth[1], "")
	}
	if len(created) > 0 {
		n.created = created[0]
	}
	return n
}

// notionListed reports whether the page shows the connections table or its empty message.
func notionListed(p notionPage) bool { return len(p.Cells) > 0 || notionEmptyRE.MatchString(p.Text) }

func notion(ctx context.Context, e *env) {
	raw, err := e.b.load(ctx, notionURL, notionJS, func(raw json.RawMessage) bool {
		p, ok := decode[notionPage](raw)
		return ok && (notionSignedOutRE.MatchString(p.URL) || notionListed(p))
	}, 50)
	if err != nil {
		e.fail("", err)
		return
	}
	p, _ := decode[notionPage](raw)
	if p.URL == "" || notionSignedOutRE.MatchString(p.URL) {
		e.status("", finding.StateSignedOut, "not signed in to Notion in the browser: %s", notionURL)
		return
	}
	workspaces := map[string]bool{}
	for _, c := range p.Cells {
		n := parseNotionRow(c)
		workspaces[n.workspace] = true
		e.report(grant{who: n.workspace, scope: n.workspace, resType: "notion_integration", name: n.name, scopes: n.scopes,
			publisher: n.owner, created: pagetext.Date(n.created, e.now), url: notionURL, revoke: notionRevoke,
			extra: map[string]any{"authorization": n.auth}})
	}
	if len(workspaces) == 0 {
		workspaces[""] = true
	}
	names := make([]string, 0, len(workspaces))
	for w := range workspaces {
		names = append(names, w)
	}
	sort.Strings(names)
	for _, w := range names {
		e.status(w, finding.StateOK, "developer connections only; apps added through Settings › Connections have no page to read and are reviewed by hand")
	}
}
