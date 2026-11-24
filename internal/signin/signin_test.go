package signin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/runtest"
	"github.com/segurata/segurata/internal/tracker"
)

var t0 = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

// webConn is a browser connector: its page for an account is through when the page says "true".
// A "sudo" account gets a brief page.
type webConn struct{ name string }

func (w webConn) Describe() connector.Description {
	return connector.Description{Name: w.name, Needs: []string{"cdp"}}
}
func (webConn) Inventory(context.Context, connector.Request, connector.Emitter) error { return nil }
func (webConn) SignInPage(st finding.Status) (connector.SignInPage, bool) {
	if st.Account == "nopage" {
		return connector.SignInPage{}, false
	}
	return connector.SignInPage{
		URL: "https://web.test/" + st.Account, Do: "sign in to " + st.Account, Expr: "done()",
		Done:  func(raw json.RawMessage) bool { return string(raw) == "true" },
		Brief: st.Account == "sudo",
	}, true
}

// cliConn is a connector without a browser.
type cliConn struct{}

func (cliConn) Describe() connector.Description {
	return connector.Description{Name: "cli", Needs: []string{"cli:tool"}}
}
func (cliConn) Inventory(context.Context, connector.Request, connector.Emitter) error { return nil }

func targetsOf(conns ...connector.Connector) []run.Target {
	var out []run.Target
	for _, c := range conns {
		out = append(out, run.Target{Connector: c})
	}
	return out
}

func setupItem(id, lbl, account string, state finding.State, status tracker.Status, details ...string) *tracker.Item {
	conn, inst, _ := strings.Cut(lbl, ":")
	it := &tracker.Item{ID: id, Kind: tracker.KindSetup, Status: status, Title: lbl + " · " + account,
		Key: "setup:" + lbl + "|" + account + "|" + string(state)}
	for i, d := range details {
		it.Findings = append(it.Findings, tracker.FindingRef{ID: fmt.Sprintf("status:%s#%d", id, i), Connector: conn, Instance: inst, Account: account, Title: d})
	}
	return it
}

func TestCollectPicksPagesAndCommandsOfWatchedAccounts(t *testing.T) {
	items := []*tracker.Item{
		setupItem("T-1", "web", "a@x.com", finding.StateReauth, tracker.Open, "verify it's you"),
		setupItem("T-2", "web", "b@x.com", finding.StateReauth, tracker.Open, "verify it's you"), // unwatched
		setupItem("T-3", "web", "c@x.com", finding.StateReauth, tracker.Done, "verify it's you"), // closed
		setupItem("T-4", "web", "a@x.com", finding.StateError, tracker.Open, "boom"),             // not a sign-in
		setupItem("T-5", "cli", "a@x.com", finding.StateReauth, tracker.Open, "expired: run gcloud auth login for this account"),
		setupItem("T-6", "cli", "a@x.com", finding.StateNoScope, tracker.Open, "run: gh auth refresh -s read:user", "run: gh auth refresh -s admin:gpg_key"),
		setupItem("T-7", "cli", "a@x.com", finding.StateMissingCredentials, tracker.Open, "store it with `security add-generic-password -s x -w`"),
		setupItem("T-8", "web", "a@x.com", finding.StateSignedOut, tracker.Open, "gh is not signed in: run `gh auth login`"),
		setupItem("T-9", "other", "a@x.com", finding.StateReauth, tracker.Open, "not a selected instance"),
		setupItem("T-10", "web", "nopage", finding.StateSignedOut, tracker.Open, "signed out"),
		setupItem("T-11", "cli", "z@x.com", finding.StateReauth, tracker.Open, "sign in again"), // no command, no browser
	}
	nopage := items[9]
	nopage.Next = &tracker.Next{URL: "https://web.test/manual"}
	accounts := func(lbl string) ([]string, bool) {
		if lbl == "web" {
			return []string{"A@x.com", "nopage"}, true
		}
		return nil, false
	}
	targets := targetsOf(webConn{"web"}, cliConn{})

	got := Collect(items, targets, accounts, false, t0)
	var ids []string
	for _, it := range got {
		ids = append(ids, it.TrackerID)
	}
	if want := "T-1 T-5 T-6 T-8 T-10"; strings.Join(ids, " ") != want {
		t.Fatalf("collected %v, want %s", ids, want)
	}
	if p := got[0].Page; p == nil || p.URL != "https://web.test/a@x.com" || got[0].Target != "web" || got[0].Do() != "sign in to a@x.com" {
		t.Fatalf("page item %+v", got[0])
	}
	if got[1].Command != "gcloud auth login a@x.com" || got[1].Page != nil {
		t.Fatalf("command item %+v", got[1])
	}
	if got[2].Command != "gh auth refresh -s read:user && gh auth refresh -s admin:gpg_key" {
		t.Fatalf("both commands of a two-status item: %q", got[2].Command)
	}
	if got[3].Command != "gh auth login" || got[3].Page != nil {
		t.Fatalf("a browser connector's CLI status is a command: %+v", got[3])
	}
	if p := got[4].Page; p == nil || p.URL != "https://web.test/manual" || p.Done != nil || got[4].Do() != "sign in on this page" {
		t.Fatalf("manual page item %+v", got[4])
	}

	withAll := Collect(items, targets, accounts, true, t0)
	if len(withAll) != len(got)+1 || withAll[3].TrackerID != "T-7" || withAll[3].Command != "security add-generic-password -s x -w" {
		t.Fatalf("--all adds the credential command: %+v", withAll)
	}
}

// --- Wait ---

type fakeTab struct {
	mu     sync.Mutex
	values []string // returned in turn; the last one repeats
	err    error    // returned once values run out
	evals  int
}

func (t *fakeTab) Evaluate(context.Context, string) (json.RawMessage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.evals++
	if t.evals > len(t.values) && t.err != nil {
		return nil, t.err
	}
	v := t.values[min(t.evals, len(t.values))-1]
	if v == "throw" {
		return nil, &cdp.EvalError{Text: "Uncaught"}
	}
	return json.RawMessage(v), nil
}

type fakeBrowser struct {
	mu     sync.Mutex
	tabs   map[string]*fakeTab
	opened []string
}

func (b *fakeBrowser) OpenTab(_ context.Context, url string) (Tab, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.opened = append(b.opened, url)
	t, ok := b.tabs[url]
	if !ok {
		return nil, errors.New("refused")
	}
	return t, nil
}

func pageItem(target, account string, done bool) Item {
	p, _ := webConn{}.SignInPage(finding.Status{Account: account})
	if !done {
		p.Done = nil
	}
	return Item{TrackerID: "T-" + account, Title: account, Target: target, Page: &p}
}

func TestWaitNeedsTwoReadsInARowAndStopsWhenAllAreDone(t *testing.T) {
	a := &fakeTab{values: []string{"false", "true", "throw", "true", "true"}}
	b := &fakeTab{values: []string{"true"}}
	br := &fakeBrowser{tabs: map[string]*fakeTab{"https://web.test/a": a, "https://web.test/sudo": b}}
	items := []Item{pageItem("web", "a", true), {TrackerID: "T-cmd", Command: "gcloud auth login"}, pageItem("web", "sudo", true)}
	var done []int
	var progress bytes.Buffer
	out := Wait(context.Background(), br, items, WaitOptions{Interval: time.Millisecond, Progress: &progress, Now: func() time.Time { return t0 },
		OnDone: func(i int) { done = append(done, i) }})
	if !out[0].Done || out[1] != (Outcome{}) || !out[2].Done || !out[0].At.Equal(t0) {
		t.Fatalf("outcomes %+v", out)
	}
	if !reflect.DeepEqual(done, []int{2, 0}) {
		t.Fatalf("OnDone order %v, want the quick page first", done)
	}
	// a: false, true, throw (resets), true, true.
	if a.evals != 5 || b.evals != 2 {
		t.Fatalf("evaluations a=%d b=%d", a.evals, b.evals)
	}
	if !reflect.DeepEqual(br.opened, []string{"https://web.test/a", "https://web.test/sudo"}) {
		t.Fatalf("opened %v", br.opened)
	}
	if s := progress.String(); !strings.Contains(s, "3. done (1 of 2): sudo") || !strings.Contains(s, "1. done (2 of 2): a") {
		t.Fatalf("progress:\n%s", s)
	}
}

func TestWaitEndsOnClosedTabsEnterAndTimeout(t *testing.T) {
	t.Run("closed tab and refused open", func(t *testing.T) {
		closed := &fakeTab{values: []string{"false"}, err: errors.New("No session with given id")}
		br := &fakeBrowser{tabs: map[string]*fakeTab{"https://web.test/a": closed}}
		out := Wait(context.Background(), br, []Item{pageItem("web", "a", true), pageItem("web", "b", true)}, WaitOptions{Interval: time.Millisecond})
		if !out[0].Closed || out[0].Done || out[1].Err == nil {
			t.Fatalf("outcomes %+v", out)
		}
	})
	t.Run("manual page waits for Enter", func(t *testing.T) {
		br := &fakeBrowser{tabs: map[string]*fakeTab{"https://web.test/m": {values: []string{"true"}}}}
		enter := make(chan struct{})
		go func() { time.Sleep(20 * time.Millisecond); close(enter) }()
		start := time.Now()
		out := Wait(context.Background(), br, []Item{pageItem("web", "m", false)}, WaitOptions{Interval: time.Millisecond, Enter: enter})
		if out[0].Done || time.Since(start) < 20*time.Millisecond {
			t.Fatalf("returned early: %+v", out)
		}
		if tab := br.tabs["https://web.test/m"]; tab.evals != 0 {
			t.Fatalf("a page without Done was read %d times", tab.evals)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		br := &fakeBrowser{tabs: map[string]*fakeTab{"https://web.test/a": {values: []string{"false"}}}}
		var progress bytes.Buffer
		out := Wait(context.Background(), br, []Item{pageItem("web", "a", true)}, WaitOptions{Interval: time.Millisecond, Timeout: 20 * time.Millisecond, Progress: &progress})
		if out[0].Done || !strings.Contains(progress.String(), "Stopped waiting (timeout)") {
			t.Fatalf("outcome %+v, progress %q", out, progress.String())
		}
	})
}

func TestReruns(t *testing.T) {
	early := t0.Add(time.Minute)
	items := []Item{
		pageItem("connected-apps", "sudo", true),
		pageItem("google-personal", "a", true),
		{Target: "gcp", Command: "gcloud auth login"},
		pageItem("connected-apps", "microsoft", true),
		pageItem("broken", "x", true),
	}
	out := []Outcome{{Done: true, At: t0}, {}, {}, {Done: true, At: t0.Add(30 * time.Second)}, {Err: errors.New("refused")}}
	// Everything of connected-apps was through before its early run: no second run. Undone pages
	// still rerun their target (the owner may have finished one segurata could not tell).
	if got := Reruns(items, out, map[string]time.Time{"connected-apps": early}); !reflect.DeepEqual(got, []string{"google-personal"}) {
		t.Fatalf("reruns %v", got)
	}
	// Microsoft was done after the early run: connected-apps runs again.
	out[3].At = early.Add(time.Second)
	if got := Reruns(items, out, map[string]time.Time{"connected-apps": early}); !reflect.DeepEqual(got, []string{"connected-apps", "google-personal"}) {
		t.Fatalf("reruns %v", got)
	}
	// Left undone after the early run: not run again.
	out[3] = Outcome{}
	if got := Reruns(items, out, map[string]time.Time{"connected-apps": early}); !reflect.DeepEqual(got, []string{"google-personal"}) {
		t.Fatalf("reruns %v", got)
	}
	if got := Reruns(items, out, nil); !reflect.DeepEqual(got, []string{"connected-apps", "google-personal"}) {
		t.Fatalf("reruns without early runs %v", got)
	}
}

// --- the command ---

type fixture struct {
	dir, out, cfg, trk string
	browser            *fakeBrowser
	connectErr         error
	connected          bool
	mu                 sync.Mutex
	ran                [][]string
	// after is what a rerun reports, by connector instance.
	after map[string][]any
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	x := &fixture{dir: dir, out: filepath.Join(dir, "out"), cfg: filepath.Join(dir, "config.json"), trk: filepath.Join(dir, "tracker.json")}
	cfg := `{"cdp_url": "http://127.0.0.1:9", "connectors": {"web": {"config": {"accounts": ["a@x.com", "sudo"]}}}}`
	if err := os.WriteFile(x.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	st := func(conn, account string, state finding.State, detail string) finding.Status {
		return finding.Status{Type: "status", Connector: conn, Account: account, State: state, Detail: detail}
	}
	runtest.Write(t, filepath.Join(x.out, "2026-11-24", "web.jsonl"),
		st("web", "a@x.com", finding.StateReauth, "verify it's you"),
		st("web", "sudo", finding.StateReauth, "sudo mode"),
		st("web", "b@x.com", finding.StateReauth, "verify it's you"))
	runtest.Write(t, filepath.Join(x.out, "2026-11-24", "cli.jsonl"),
		st("cli", "a@x.com", finding.StateReauth, "credentials expired: run gcloud auth login for this account"))
	x.sync(t)
	x.after = map[string][]any{"web": {st("web", "a@x.com", finding.StateOK, ""), st("web", "sudo", finding.StateOK, ""), st("web", "b@x.com", finding.StateReauth, "verify it's you")}}
	return x
}

func (x *fixture) sync(t testing.TB) int {
	tr, err := tracker.LoadOrNew(tracker.Paths{Tracker: x.trk}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Sync(tracker.SyncOptions{OutDir: x.out}, t0); err != nil {
		t.Fatal(err)
	}
	if err := tr.Save(x.trk); err != nil {
		t.Fatal(err)
	}
	return 0
}

func (x *fixture) cli(t *testing.T, out *bytes.Buffer) CLI {
	var clock sync.Mutex
	now := t0
	return CLI{
		Out: out, Err: out, Config: x.cfg, Paths: tracker.Paths{Tracker: x.trk},
		Now: func() time.Time { // a second per call
			clock.Lock()
			defer clock.Unlock()
			now = now.Add(time.Second)
			return now
		},
		Connectors: []connector.Connector{webConn{"web"}, cliConn{}}, Interval: time.Millisecond,
		Connect: func(context.Context, string) (Browser, func(), error) {
			x.connected = true
			if x.connectErr != nil {
				return nil, nil, x.connectErr
			}
			return x.browser, func() {}, nil
		},
		Inventory: func(_ context.Context, _ config.Config, targets []run.Target, out string) ([]*run.Result, error) {
			var labels []string
			var res []*run.Result
			for _, tg := range targets {
				labels = append(labels, tg.Label())
				runtest.Write(t, filepath.Join(out, "2026-11-25", tg.Label()+".jsonl"), x.after[tg.Label()]...)
				res = append(res, &run.Result{Name: tg.Label()})
			}
			x.mu.Lock()
			x.ran = append(x.ran, labels)
			x.mu.Unlock()
			return res, nil
		},
		Sync: func(string) int { return x.sync(t) },
	}
}

func TestSigninOpensWaitsRerunsAndReportsClosedItems(t *testing.T) {
	x := newFixture(t)
	x.browser = &fakeBrowser{tabs: map[string]*fakeTab{
		"https://web.test/a@x.com": {values: []string{"false", "false", "false", "true"}},
		"https://web.test/sudo":    {values: []string{"true"}},
	}}
	var out bytes.Buffer
	if code := x.cli(t, &out).Run(context.Background(), []string{"--out", x.out}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	s := out.String()
	for _, want := range []string{
		"In the browser:\n  1. web · a@x.com: needs a fresh sign-in: sign in to a@x.com\n     https://web.test/a@x.com",
		"  2. web · sudo: needs a fresh sign-in: sign in to sudo",
		"In your terminal (segurata does not run these):\n  3. cli · a@x.com: needs a fresh sign-in",
		"     gcloud auth login a@x.com\n     then: segurata inventory cli",
		"2. done (1 of 2)", "Running web now, while it lasts.", "1. done (2 of 2)",
		"closed (done): web · a@x.com", "closed (done): web · sudo", "3. T-", "still open: cli · a@x.com",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "b@x.com") {
		t.Errorf("the unwatched account is listed:\n%s", s)
	}
	// The sudo page ran web at once; a@x.com was done after that, so web runs once more.
	if !reflect.DeepEqual(x.ran, [][]string{{"web"}, {"web"}}) {
		t.Fatalf("runs %v", x.ran)
	}
}

func TestSigninListOpensNothing(t *testing.T) {
	x := newFixture(t)
	before, _ := os.ReadFile(x.trk)
	var out bytes.Buffer
	if code := x.cli(t, &out).Run(context.Background(), []string{"--list"}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if x.connected || len(x.ran) > 0 {
		t.Fatal("--list connected to the browser or ran a connector")
	}
	if after, _ := os.ReadFile(x.trk); !bytes.Equal(before, after) {
		t.Fatal("--list changed the tracker")
	}
	if !strings.Contains(out.String(), "segurata signin would open 2 tabs in the browser at http://127.0.0.1:9, wait up to 10m0s, then run web again.") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestSigninWithoutTheBrowserPrintsTheURLsAndStops(t *testing.T) {
	x := newFixture(t)
	x.connectErr = errors.New("connection refused")
	var out bytes.Buffer
	if code := x.cli(t, &out).Run(context.Background(), nil); code != 1 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if len(x.ran) > 0 {
		t.Fatal("ran a connector without the browser")
	}
	s := out.String()
	if !strings.Contains(s, "https://web.test/a@x.com") || !strings.Contains(s, "never another one") || !strings.Contains(s, "then run: segurata inventory web") {
		t.Fatalf("output:\n%s", s)
	}
}

func TestSigninSelectorsAndHelp(t *testing.T) {
	x := newFixture(t)
	var out bytes.Buffer
	if code := x.cli(t, &out).Run(context.Background(), []string{"cli", "--list"}); code != 0 || strings.Contains(out.String(), "web.test") || !strings.Contains(out.String(), "gcloud auth login") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	out.Reset()
	if code := x.cli(t, &out).Run(context.Background(), []string{"nope"}); code != 2 {
		t.Fatalf("unknown selector: exit %d", code)
	}
	out.Reset()
	if code := x.cli(t, &out).Run(context.Background(), []string{"--help"}); code != 0 || !strings.Contains(out.String(), "usage: segurata signin") {
		t.Fatalf("help: exit %d\n%s", code, out.String())
	}
}
