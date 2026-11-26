// Package connectedapps inventories the third-party apps connected to accounts outside Google,
// reading each service's settings pages in the signed-in browser, and GitHub keys with `gh`.
// It only navigates and reads: it never clicks, never submits a form, and loads each listing
// page once per run.
package connectedapps

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const name = "connected-apps"

func init() { connector.Register(&Connector{}) }

// Connector's zero value talks to the real browser and the real `gh`.
type Connector struct {
	browser browser
	gh      cli.Runner
	now     func() time.Time
	exec    connector.Executor // nil is connector.System
}

func (*Connector) Describe() connector.Description {
	return connector.Description{
		Name:     name,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Apps connected to GitHub, X, Slack, Notion, Microsoft (personal and work), Dropbox, Facebook, Instagram and LinkedIn, read from the signed-in browser",
		Needs:    []string{"cdp", "cli:gh"},
		Theme:    finding.ThemeConnectedApps,
	}
}

type service struct {
	name string
	run  func(ctx context.Context, e *env)
}

// services in the order they run; config "services" picks a subset.
var services = []service{
	{"github", github},
	{"x", xService},
	{"slack", slack},
	{"notion", notion},
	{"microsoft", microsoftPage.run},
	{"microsoft-work", microsoftWork},
	{"dropbox", dropbox},
	{"facebook", facebook},
	{"instagram", instagramPage.run},
	{"linkedin", linkedinPage.run},
}

func selectServices(cfg map[string]any) ([]service, error) {
	names, err := connector.Strings(cfg, "connected-apps", "services")
	if names == nil || err != nil {
		return services, err
	}
	var out []service
	for _, n := range names {
		i := slices.IndexFunc(services, func(s service) bool { return s.name == n })
		if i < 0 {
			var known []string
			for _, s := range services {
				known = append(known, s.name)
			}
			return nil, fmt.Errorf("connected-apps config: unknown service %v (known: %s)", n, strings.Join(known, ", "))
		}
		out = append(out, services[i])
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
		b = client
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

func (c *Connector) ghRunner() cli.Runner {
	if c.gh != nil {
		return c.gh
	}
	return cli.Guard(ghAllowlist, cli.Exec{Path: "gh", Timeout: 60 * time.Second})
}

type env struct {
	service string
	b       browser
	gh      cli.Runner
	emit    connector.Emitter
	now     time.Time
	seen    map[string]int // resource key -> times used, for ordinals
}

// account is "github:octocat", or "github" when nobody is known. A status for the bare service
// name leaves every finding of that service uninspected.
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

// grant is a connected app, a session or a key.
type grant struct {
	who        string // see env.account
	scope      string // keeps names apart within the service: a Slack or Notion workspace
	resType    string
	kind       finding.Kind // "" is KindGrant
	name       string
	key        string   // identity when the name can change; defaults to name
	scopes     []string // as the service words them
	userScopes []string // Slack: the app acts as the person who installed it
	count      int      // when only the count is shown
	publisher  string
	orgs       []string // GitHub organizations it can reach
	created    *time.Time
	lastUsed   *time.Time
	usedText   string // "Last used within the last 11 months"
	stale      bool   // unused for over a year
	url        string // where the owner revokes it
	revoke     string // how
	note       string
	extra      map[string]any
}

// report emits a grant with an id stable across runs: service, type, name and an ordinal for
// repeated names. Per-load ids never enter it.
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
	r := assess(e.service, g)
	sev := r.sev
	title := fmt.Sprintf("%s can %s", g.name, r.label)
	if g.stale {
		title += " (not used for over a year)"
	}
	if g.resType == "notion_integration" && ownIntegration(g.publisher) {
		title += " (your own integration)"
	}
	ev := map[string]any{"service": e.service}
	summary := g.revoke
	if summary == "" {
		summary = "If you no longer use it, open the page and revoke its access."
	}
	action := ""
	if dep, ok := dependencyOf(g); ok {
		title += " (" + dep.label + ")"
		ev["dependency"] = dep.label
		summary = dep.fix
		if len(dep.remove) > 0 {
			action = actionGHDropScopes
		}
	}
	if g.scopes != nil {
		ev["scopes"] = g.scopes
	}
	if g.userScopes != nil {
		ev["user_scopes"] = g.userScopes
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
	e.emit.Finding(finding.Finding{
		ID:          finding.StableID(name, g.resType, id),
		Account:     e.account(g.who),
		Scope:       e.service,
		Resource:    finding.Resource{Type: g.resType, ID: id, Name: g.name},
		Kind:        kind,
		Severity:    sev,
		Blast:       r.blast,
		Title:       title,
		Evidence:    ev,
		CreatedAt:   g.created,
		LastUsedAt:  g.lastUsed,
		Remediation: finding.Remediation{Summary: summary, URL: g.url, Action: action},
	})
}

const staleAfter = 365 * 24 * time.Hour

// browser is *cdp.Client, or synthetic pages in tests.
type browser interface {
	Load(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int) (json.RawMessage, error)
	Capture(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int, re *regexp.Regexp) (json.RawMessage, *cdp.Response, error)
}

// decode reads a page value into T; a value of the wrong shape gives the zero T.
func decode[T any](raw json.RawMessage) T {
	var v T
	if json.Unmarshal(raw, &v) != nil {
		var zero T
		return zero
	}
	return v
}

// readyWhen is match over decoded page values. Every match must be false on the zero value.
func readyWhen[T any](match func(T) bool) func(json.RawMessage) bool {
	return func(raw json.RawMessage) bool { return match(decode[T](raw)) }
}

// load reads url in a hidden page until ready accepts its value, and decodes the last one.
func load[T any](ctx context.Context, e *env, url, expr string, ready func(T) bool, tries int) (T, error) {
	raw, err := e.b.Load(ctx, url, expr, readyWhen(ready), tries)
	return decode[T](raw), err
}

// capture is load that also returns the last response the page fetched whose URL matches re.
func capture[T any](ctx context.Context, e *env, url, expr string, ready func(T) bool, tries int, re *regexp.Regexp) (T, *cdp.Response, error) {
	raw, resp, err := e.b.Capture(ctx, url, expr, readyWhen(ready), tries, re)
	return decode[T](raw), resp, err
}

// pageHelpers are injected into every listing page. rowOf climbs from a link to the largest
// container linking only to its target, stopping at a row-like element so a one-item list does
// not climb to <body>. No CSS classes beyond GitHub's stable .Box-row.
const pageHelpers = `
  const lines = (el) => (el?.innerText || "").split("\n").map((s) => s.trim()).filter(Boolean);
  const hrefs = (el, sel) => new Set([...el.querySelectorAll(sel)].map((x) => x.href)).size;
  const ROW = "li, tr, [role=row], [role=listitem], .Box-row";
  const rowOf = (a, sel) => { let r = a; while (!r.matches(ROW) && r.parentElement && hrefs(r.parentElement, sel) === 1) r = r.parentElement; return r; };
  const uniq = (sel) => { const m = new Map(); for (const a of document.querySelectorAll(sel)) if (a.innerText.trim() && !m.has(a.href)) m.set(a.href, a); return [...m.values()]; };
  const row = (sel) => (a) => ({name: a.innerText.trim(), href: a.href, lines: lines(rowOf(a, sel))});
  const rows = (sel) => uniq(sel).map(row(sel));
  const everyRow = (sel) => [...document.querySelectorAll(sel)].map(row(sel));
  const page = {url: location.href, title: document.title, text: document.body ? document.body.innerText : ""};
`

const pageTextJS = `({url: location.href, text: document.body ? document.body.innerText : ""})`

func inPage(body string) string { return "(() => {" + pageHelpers + body + "})()" }

type listPage struct {
	URL   string `json:"url"`
	Title string `json:"title"`
	Text  string `json:"text"`
	Login string `json:"login"`
	Rows  []row  `json:"rows"`
	Next  string `json:"next"`
}

type row struct {
	Name  string   `json:"name"`
	Href  string   `json:"href"`
	Lines []string `json:"lines"`
}

// fetchedJS also says whether the page has fetched a URL containing path, from its own resource
// timing, so nothing is sent.
func fetchedJS(path string) string {
	return `(() => ({url: location.href, text: document.body ? document.body.innerText : "",
  fetched: performance.getEntriesByType("resource").some((e) => e.name.includes(` + strconv.Quote(path) + `))}))()`
}

type fetchPage struct {
	URL     string `json:"url"`
	Text    string `json:"text"`
	Fetched bool   `json:"fetched"`
}

// twice passes once ready has accepted two values in a row: some pages pass a moment before a
// response or a redirect is done.
func twice[T any](ready func(T) bool) func(T) bool {
	n := 0
	return func(p T) bool {
		if ready(p) {
			n++
		} else {
			n = 0
		}
		return n >= 2
	}
}
