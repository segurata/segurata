// Package connectedapps inventories the third-party apps connected to accounts outside Google:
// GitHub, X, Slack, Notion, Microsoft, Dropbox, Facebook, Instagram and LinkedIn. It reads each
// service's own settings pages over CDP, in background targets of the browser the user is
// already signed in to, and lists GitHub keys with the `gh` CLI.
//
// Read-only by construction: it only navigates and reads. It never clicks a button (not even
// "See more"), never submits a form, loads each listing page once per run, and closes every
// target it opens.
package connectedapps

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const name = "connected-apps"

func init() { connector.Register(&Connector{}) }

// Connector is the built-in connected-apps connector. Its fields are seams for tests; the zero
// value talks to the real browser and the real `gh`.
type Connector struct {
	browser browser
	gh      cli.Runner
	now     func() time.Time
}

func (*Connector) Describe() connector.Description {
	return connector.Description{
		Name:     name,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Apps connected to GitHub, X, Slack, Notion, Microsoft, Dropbox, Facebook, Instagram and LinkedIn, read from the signed-in browser",
		Needs:    []string{"cdp", "cli:gh"},
	}
}

// service is one site whose connected apps this connector reads.
type service struct {
	name string
	run  func(ctx context.Context, e *env)
}

// services in the order they run. The config key "services" picks a subset.
var services = []service{
	{"github", github},
	{"x", xService},
	{"slack", slack},
	{"notion", notion},
	{"microsoft", microsoft},
	{"dropbox", dropbox},
	{"facebook", facebook},
	{"instagram", instagram},
	{"linkedin", linkedin},
}

// selectServices reads config "services": a list of service names, all of them when absent.
func selectServices(cfg map[string]any) ([]service, error) {
	v, ok := cfg["services"]
	if !ok || v == nil {
		return services, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, errors.New(`connected-apps config: "services" must be a list of strings`)
	}
	byName := map[string]service{}
	var known []string
	for _, s := range services {
		byName[s.name] = s
		known = append(known, s.name)
	}
	var out []service
	for _, it := range items {
		n, _ := it.(string)
		s, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("connected-apps config: unknown service %v (known: %s)", it, strings.Join(known, ", "))
		}
		out = append(out, s)
	}
	return out, nil
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	selected, err := selectServices(req.Config)
	if err != nil {
		return err
	}
	b := c.browser
	if b == nil {
		client, err := cdp.Connect(ctx, req.CDPURL)
		if err != nil {
			return err
		}
		defer client.Close()
		b = cdpBrowser{client}
	}
	gh := c.ghRunner()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	for _, s := range services {
		if !slices.ContainsFunc(selected, func(x service) bool { return x.name == s.name }) {
			emit.Scope(s.name, false, `not in the "services" config`)
		}
	}
	for _, s := range selected {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e := &env{service: s.name, b: b, gh: gh, emit: emit, now: now(), seen: map[string]int{}}
		s.run(ctx, e)
	}
	return nil
}

// ghRunner is the injected gh, or the real one behind the read-only allowlist.
func (c *Connector) ghRunner() cli.Runner {
	if c.gh != nil {
		return c.gh
	}
	return cli.Guard(ghAllowlist, cli.Exec{Path: "gh", Timeout: 60 * time.Second})
}

// env is what a service reads with and reports to.
type env struct {
	service string
	b       browser
	gh      cli.Runner
	emit    connector.Emitter
	now     time.Time
	seen    map[string]int // resource keys already used, for ordinals
}

// account labels a service account: "github:octocat", or just "github" when the page did not
// say who is signed in. Findings are scoped to the service, so a status for the bare service name
// (signed out, nobody known) leaves every finding of that service uninspected.
func (e *env) account(who string) string {
	if who == "" {
		return e.service
	}
	return e.service + ":" + who
}

func (e *env) status(who string, st finding.State, format string, args ...any) {
	e.emit.Status(finding.Status{Account: e.account(who), State: st, Detail: fmt.Sprintf(format, args...)})
}

func (e *env) fail(who string, err error) {
	e.status(who, finding.StateError, "%v", err)
}

// grant is one thing a service reports: a connected app, a session or a key.
type grant struct {
	who       string       // service account, see env.account
	scope     string       // what keeps names apart within the service: a Slack workspace, a Notion workspace
	resType   string       // resource type, such as "github_oauth_app"
	kind      finding.Kind // grant for apps, credential for keys and sessions
	name      string
	key       string   // what identifies it when the name can change (a session's IP); defaults to name
	scopes    []string // permissions as the service words them
	count     int      // number of scopes when only the count is shown (Slack)
	publisher string
	orgs      []string // GitHub organizations the app can reach
	created   *time.Time
	lastUsed  *time.Time
	usedText  string // last use as the page words it ("Last used within the last 11 months")
	stale     bool   // last used more than a year ago, from a date or the page's wording
	url       string // page where the owner revokes it
	revoke    string // what to do on that page
	note      string
	extra     map[string]any
}

// report turns a grant into a finding with a stable id: service, resource type and name, plus an
// ordinal for repeated names. Per-load ids (Slack, Facebook and GitHub all have them) never enter it.
func (e *env) report(g grant) {
	ident := g.key
	if ident == "" {
		ident = g.name
	}
	key := e.service + ":" + g.resType + ":" + g.scope + ":" + ident
	n := e.seen[key]
	e.seen[key]++
	id := ident
	if g.scope != "" {
		id = g.scope + "/" + id
	}
	id = e.service + ":" + id
	if n > 0 {
		id += fmt.Sprintf("#%d", n)
	}
	if g.lastUsed != nil && e.now.Sub(*g.lastUsed) > staleAfter {
		g.stale = true
	}
	sev, label := assess(e.service, g)
	title := fmt.Sprintf("%s can %s", g.name, label)
	if g.stale {
		title += " (not used for over a year)"
	}
	ev := map[string]any{"service": e.service}
	if g.scopes != nil {
		ev["scopes"] = g.scopes
	}
	if g.count > 0 {
		ev["scope_count"] = g.count
	}
	if g.publisher != "" {
		ev["publisher"] = g.publisher
	}
	if g.orgs != nil {
		ev["org_access"] = g.orgs
	}
	if g.usedText != "" {
		ev["last_used"] = g.usedText
	}
	if g.note != "" {
		ev["note"] = g.note
	}
	for k, v := range g.extra {
		ev[k] = v
	}
	kind := g.kind
	if kind == "" {
		kind = finding.KindGrant
	}
	summary := g.revoke
	if summary == "" {
		summary = "If you no longer use it, open the page and revoke its access."
	}
	e.emit.Finding(finding.Finding{
		ID:          finding.StableID(name, g.resType, id),
		Account:     e.account(g.who),
		Scope:       e.service,
		Resource:    finding.Resource{Type: g.resType, ID: id, Name: g.name},
		Kind:        kind,
		Severity:    sev,
		Title:       title,
		Evidence:    ev,
		CreatedAt:   g.created,
		LastUsedAt:  g.lastUsed,
		Remediation: finding.Remediation{Summary: summary, URL: g.url},
	})
}

// staleAfter is how long without use raises a grant's severity one level.
const staleAfter = 365 * 24 * time.Hour

// browser loads a page in a background target, polls a JavaScript expression until ready accepts
// its value or tries run out, closes the target and returns the last value. The seam that lets
// tests replace Brave with synthetic pages.
type browser interface {
	load(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int) (json.RawMessage, error)
	// capture is load that also returns the last response, among those the page fetched, whose
	// URL matches re. It reads what the page itself requested; it never sends a request.
	capture(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int, re *regexp.Regexp) (json.RawMessage, *response, error)
}

// response is a body the page fetched. It may hold tokens: parsers decode the fields they need
// and drop the rest, and it is never logged or written.
type response struct {
	status int
	body   []byte
}

type cdpBrowser struct{ c *cdp.Client }

func (b cdpBrowser) load(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int) (v json.RawMessage, err error) {
	err = b.c.WithPage(ctx, url, func(p *cdp.Page) error {
		v, err = p.WaitFor(ctx, expr, ready, tries)
		return err
	})
	return v, err
}

func (b cdpBrowser) capture(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int, re *regexp.Regexp) (v json.RawMessage, resp *response, err error) {
	var mu sync.Mutex
	type hit struct {
		id     string
		status int
	}
	var hits []hit
	finished := map[string]bool{}
	setup := func(p *cdp.Page) error {
		if _, err := p.Send(ctx, "Network.enable", nil); err != nil {
			return err
		}
		p.On("Network.responseReceived", func(raw json.RawMessage) {
			var e struct {
				RequestID string `json:"requestId"`
				Response  struct {
					URL    string `json:"url"`
					Status int    `json:"status"`
				} `json:"response"`
			}
			if json.Unmarshal(raw, &e) == nil && re.MatchString(e.Response.URL) {
				mu.Lock()
				hits = append(hits, hit{e.RequestID, e.Response.Status})
				mu.Unlock()
			}
		})
		p.On("Network.loadingFinished", func(raw json.RawMessage) {
			var e struct {
				RequestID string `json:"requestId"`
			}
			if json.Unmarshal(raw, &e) == nil {
				mu.Lock()
				finished[e.RequestID] = true
				mu.Unlock()
			}
		})
		return nil
	}
	err = b.c.WithPageSetup(ctx, url, setup, func(p *cdp.Page) error {
		if v, err = p.WaitFor(ctx, expr, ready, tries); err != nil {
			return err
		}
		mu.Lock()
		var last *hit
		for i := range hits {
			if finished[hits[i].id] {
				last = &hits[i]
			}
		}
		mu.Unlock()
		if last == nil {
			return nil
		}
		raw, err := p.Send(ctx, "Network.getResponseBody", map[string]any{"requestId": last.id})
		if err != nil {
			return err
		}
		var r struct {
			Body          string `json:"body"`
			Base64Encoded bool   `json:"base64Encoded"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		body := []byte(r.Body)
		if r.Base64Encoded {
			if body, err = base64.StdEncoding.DecodeString(r.Body); err != nil {
				return err
			}
		}
		resp = &response{status: last.status, body: body}
		return nil
	})
	return v, resp, err
}

// decode reads a page value into T; a value of the wrong shape gives the zero T and false.
func decode[T any](raw json.RawMessage) (T, bool) {
	var v T
	return v, json.Unmarshal(raw, &v) == nil
}

// pageHelpers are injected into every listing page. rowOf climbs from a link to the largest
// container that links only to that target (one target can have an icon link and a name link),
// stopping at the first row-like element, so a one-item list does not climb up to <body>. uniq
// drops repeated and empty links. Text-based: no CSS classes beyond GitHub's stable .Box-row.
const pageHelpers = `
  const lines = (el) => (el?.innerText || "").split("\n").map((s) => s.trim()).filter(Boolean);
  const hrefs = (el, sel) => new Set([...el.querySelectorAll(sel)].map((x) => x.href)).size;
  const ROW = "li, tr, [role=row], [role=listitem], .Box-row";
  const rowOf = (a, sel) => { let r = a; while (!r.matches(ROW) && r.parentElement && hrefs(r.parentElement, sel) === 1) r = r.parentElement; return r; };
  const uniq = (sel) => { const m = new Map(); for (const a of document.querySelectorAll(sel)) if (a.innerText.trim() && !m.has(a.href)) m.set(a.href, a); return [...m.values()]; };
  const rows = (sel) => uniq(sel).map((a) => ({name: a.innerText.trim(), href: a.href, lines: lines(rowOf(a, sel))}));
  const page = {url: location.href, title: document.title, text: document.body ? document.body.innerText : ""};
`

// pageTextJS reads only the page URL and its text.
const pageTextJS = `({url: location.href, text: document.body ? document.body.innerText : ""})`

// inPage wraps an expression body that returns an object built from pageHelpers.
func inPage(body string) string { return "(() => {" + pageHelpers + body + "})()" }

// listPage is the common shape of what a listing page's expression returns.
type listPage struct {
	URL   string `json:"url"`
	Title string `json:"title"`
	Text  string `json:"text"`
	Login string `json:"login"`
	Rows  []row  `json:"rows"`
	Next  string `json:"next"`
}

// row is one link and the lines of the row it sits in.
type row struct {
	Name  string   `json:"name"`
	Href  string   `json:"href"`
	Lines []string `json:"lines"`
}

func readyWhen(match func(listPage) bool) func(json.RawMessage) bool {
	return func(raw json.RawMessage) bool {
		p, ok := decode[listPage](raw)
		return ok && match(p)
	}
}
