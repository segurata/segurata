package connectedapps

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Every account, app, organization and workspace in these tests is invented.

var now = time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)

// fakeBrowser serves canned page values by URL and records every page it opened.
type fakeBrowser struct {
	mu        sync.Mutex
	pages     map[string]any
	responses map[string]*cdp.Response
	fail      map[string]error
	opened    []string
	// neverReady are given pages the readiness check must reject, so the real browser polls
	// them until its tries run out (a sign-in page with nothing on it, a list never fetched).
	neverReady map[string]bool
	unready    map[string]bool
}

func (b *fakeBrowser) value(url string, ready func(json.RawMessage) bool, tries int) (json.RawMessage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.opened = append(b.opened, url)
	if err := b.fail[url]; err != nil {
		return nil, err
	}
	v, ok := b.pages[url]
	if !ok {
		v = map[string]any{}
	}
	raw, _ := json.Marshal(v)
	// Polled like the real browser: the same value until ready accepts it or tries run out.
	accepted := false
	for i := 0; i < tries && !accepted; i++ {
		accepted = ready(raw)
	}
	if _, given := b.pages[url]; given && !accepted {
		if b.unready == nil {
			b.unready = map[string]bool{}
		}
		b.unready[url] = true
	}
	return raw, nil
}

func (b *fakeBrowser) Load(_ context.Context, url, _ string, ready func(json.RawMessage) bool, tries int) (json.RawMessage, error) {
	return b.value(url, ready, tries)
}

func (b *fakeBrowser) Capture(_ context.Context, url, _ string, ready func(json.RawMessage) bool, tries int, _ *regexp.Regexp) (json.RawMessage, *cdp.Response, error) {
	raw, err := b.value(url, ready, tries)
	if err != nil {
		return nil, nil, err
	}
	return raw, b.responses[url], nil
}

// openedOnce fails the test when any page was loaded more than once: one listing request per
// page load, and no page loaded twice in a run.
func (b *fakeBrowser) openedOnce(t *testing.T) {
	t.Helper()
	seen := map[string]bool{}
	for _, u := range b.opened {
		if seen[u] {
			t.Errorf("%s loaded twice", u)
		}
		seen[u] = true
	}
}

// readiness fails the test when a given page's readiness check did not do what the test says:
// accept the page, or reject one in neverReady.
func (b *fakeBrowser) readiness(t *testing.T) {
	t.Helper()
	for u := range b.pages {
		if b.unready[u] != b.neverReady[u] && slices.Contains(b.opened, u) {
			t.Errorf("%s: ready = %t, want %t", u, !b.unready[u], !b.neverReady[u])
		}
	}
}

type recorder struct {
	findings []finding.Finding
	statuses []finding.Status
	skipped  []finding.Skipped
}

func (r *recorder) Finding(f finding.Finding) { r.findings = append(r.findings, f) }
func (r *recorder) Status(s finding.Status)   { r.statuses = append(r.statuses, s) }
func (r *recorder) Scope(id string, inspected bool, reason string) {
	if !inspected {
		r.skipped = append(r.skipped, finding.Skipped{Scope: id, Reason: reason})
	}
}
func (r *recorder) Log(string) {}

func (r *recorder) byName(t *testing.T, name string) finding.Finding {
	t.Helper()
	for _, f := range r.findings {
		if f.Resource.Name == name {
			return f
		}
	}
	t.Fatalf("no finding named %q in %d findings", name, len(r.findings))
	return finding.Finding{}
}

func (r *recorder) state(account string) []finding.State {
	var out []finding.State
	for _, s := range r.statuses {
		if s.Account == account {
			out = append(out, s.State)
		}
	}
	return out
}

func (r *recorder) detail(account string, st finding.State) string {
	for _, s := range r.statuses {
		if s.Account == account && s.State == st {
			return s.Detail
		}
	}
	return ""
}

// ghFake answers `gh api` calls from a table of path → output or error.
type ghFake map[string]any

func (g ghFake) Run(_ context.Context, args ...string) ([]byte, error) {
	if err := ghAllowlist.Check(args); err != nil {
		return nil, err
	}
	switch v := g[args[len(args)-1]].(type) {
	case string:
		return []byte(v), nil
	case error:
		return nil, v
	}
	return nil, errors.New("unexpected gh call " + strings.Join(args, " "))
}

func noScope(scope string) error {
	return &cli.Error{Cmd: "gh api", Stderr: "gh: This API operation needs the \"" + scope + "\" scope. To request it, run:  gh auth refresh -h github.com -s " + scope, Err: errors.New("exit status 1")}
}

// run inventories the given services against the fakes.
func run(t *testing.T, b *fakeBrowser, gh cli.Runner, svc ...string) *recorder {
	t.Helper()
	cfg := map[string]any{}
	if len(svc) > 0 {
		list := make([]any, len(svc))
		for i, s := range svc {
			list[i] = s
		}
		cfg["services"] = list
	}
	c := &Connector{browser: b, gh: gh, now: func() time.Time { return now }}
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: cfg}, rec); err != nil {
		t.Fatal(err)
	}
	b.openedOnce(t)
	b.readiness(t)
	return rec
}

func rows(rs ...row) []row { return rs }

func page(url, text string, rs []row) map[string]any {
	return map[string]any{"url": url, "title": "", "text": text, "rows": rs}
}
