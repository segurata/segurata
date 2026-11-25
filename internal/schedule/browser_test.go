package schedule

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/tracker"
)

// unreachable is the probe of testEnv: no test ever reaches a real browser.
func unreachable(context.Context, string) (cdp.Version, error) {
	return cdp.Version{}, errors.New("cdp: browser not reachable at test: connection refused")
}

// brave answers as Brave would, recording the probe's deadline.
func brave(deadline *time.Time) func(context.Context, string) (cdp.Version, error) {
	return func(ctx context.Context, _ string) (cdp.Version, error) {
		*deadline, _ = ctx.Deadline()
		return cdp.Version{Browser: "Chrome/156"}, nil
	}
}

// runEnds reads the run_end of the latest run of every instance under out, by instance label.
func runEnds(t *testing.T, out string) map[string]finding.RunEnd {
	t.Helper()
	latest, err := run.LatestRuns(out, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ends := map[string]finding.RunEnd{}
	for _, l := range latest {
		o, err := run.Read(l.File)
		if err != nil {
			t.Fatal(err)
		}
		if o.End != nil {
			ends[finding.Label(o.End.Connector, o.End.Instance)] = *o.End
		}
	}
	return ends
}

// Brave not answering: the browser connectors are not run, each configured instance gets a run
// that inspected nothing with the reason as its error, and the log says so in one line. The probe
// is the real one, against a fake CDP address where nothing listens.
func TestRunSkipsTheBrowserConnectorsWhenBraveDoesNotAnswer(t *testing.T) {
	env, r, out := testEnv(t, "darwin")
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	env.Browser, env.Config.CDPURL = cdp.Brave, gone.URL
	env.Config.Connectors = map[string]config.ConnectorConfig{
		"connected-apps:work": {Secrets: map[string]string{"X": "keychain:never-read"}}, "connected-apps:home": {},
	}
	if err := env.Run(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	inv := r.ran(env.Exe, "inventory")
	if len(inv) != 1 || !slices.Equal(inv[0][4:], []string{"hibp", "macos"}) {
		t.Fatalf("inventory calls %v", inv)
	}
	ends := runEnds(t, env.Paths().Out)
	for _, label := range []string{"google-personal", "connected-apps:home", "connected-apps:work"} {
		e, ok := ends[label]
		if !ok || e.Complete || e.Error != reasonUnreachable || len(e.Scopes.Skipped) != 1 ||
			e.Scopes.Skipped[0] != (finding.Skipped{Scope: finding.ScopeAll, Reason: reasonUnreachable}) || e.SecretFingerprints != nil {
			t.Fatalf("%s: run_end %+v (found %v)", label, e, ok)
		}
	}
	if n := strings.Count(out.String(), "skipped "); n != 1 || !strings.Contains(out.String(), "skipped connected-apps google-personal: browser not reachable over CDP\n") {
		t.Fatalf("log:\n%s", out)
	}
	if len(r.ran(osascript, "-e")) != 0 {
		t.Fatal("notified on the first skip")
	}
}

// Brave answering: every connector runs in the one inventory, under the run's deadline, and nothing
// is recorded as skipped.
func TestRunIncludesTheBrowserConnectorsWhenBraveAnswers(t *testing.T) {
	env, r, out := testEnv(t, "darwin")
	var deadline time.Time
	env.Browser = brave(&deadline)
	start := time.Now()
	if err := env.Run(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	inv := r.ran(env.Exe, "inventory")
	if len(inv) != 1 || !slices.Equal(inv[0][4:], []string{"connected-apps", "google-personal", "hibp", "macos"}) {
		t.Fatalf("inventory calls %v", inv)
	}
	if deadline.IsZero() || deadline.After(start.Add(browserProbeTimeout+time.Second)) {
		t.Fatalf("probe deadline %v", deadline)
	}
	if _, ok := runEnds(t, env.Paths().Out)["google-personal"]; ok || strings.Contains(out.String(), "skipped") {
		t.Fatalf("recorded a skip:\n%s", out)
	}
}

// Another browser on the port is never driven: only Brave is.
func TestRunSkipsABrowserThatIsNotBrave(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	env.Browser = func(context.Context, string) (cdp.Version, error) {
		return cdp.Version{}, fmt.Errorf("cdp: the browser at x (Chrome/156) is %w", cdp.ErrNotBrave)
	}
	if err := env.Run(context.Background(), Options{Connectors: []string{"google-personal", "macos"}}); err != nil {
		t.Fatal(err)
	}
	if inv := r.ran(env.Exe, "inventory"); len(inv) != 1 || !slices.Equal(inv[0][4:], []string{"macos"}) {
		t.Fatalf("inventory calls %v", inv)
	}
	if e := runEnds(t, env.Paths().Out)["google-personal"]; e.Error != reasonNotBrave {
		t.Fatalf("run_end %+v", e)
	}
}

// Without a browser connector selected there is nothing to probe; with only browser connectors
// selected and skipped, the tracker still folds their runs in.
func TestRunProbesOnlyForBrowserConnectors(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	env.Browser = func(context.Context, string) (cdp.Version, error) { t.Fatal("probed"); return cdp.Version{}, nil }
	if err := env.Run(context.Background(), Options{Connectors: []string{"macos", "hibp"}}); err != nil {
		t.Fatal(err)
	}
	env.Browser = unreachable
	if err := env.Run(context.Background(), Options{Connectors: []string{"google-personal"}}); err != nil {
		t.Fatal(err)
	}
	if len(r.ran(env.Exe, "inventory")) != 1 || len(r.ran(env.Exe, "track")) != 1 {
		t.Fatalf("calls %v", r.calls)
	}
}

// A skipped run never closes what an earlier run of the browser connector found: not its findings,
// not its reauth status.
func TestASkippedRunResolvesNothing(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	// run.Inventory dates the skipped runs by the wall clock; the sync must not take them as future.
	env.Now, r.now = time.Now, time.Now
	dir := filepath.Join(env.Paths().Out, "2020-01-01")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	earlier := `{"type":"finding","id":"g1","connector":"google-personal","account":"a@example.com","severity":"high","title":"App with full Gmail access","resource":{"type":"oauth_app","id":"app1"},"observed_at":"2020-01-01T00:00:00Z"}
{"type":"status","connector":"google-personal","account":"b@example.com","state":"reauth"}
{"type":"run_end","connector":"google-personal","complete":false,"started_at":"2020-01-01T00:00:00Z","ended_at":"2020-01-01T00:00:01Z","scopes":{"inspected":["a@example.com"],"inspected_count":1,"skipped":[{"scope":"b@example.com","reason":"reauth"}],"skipped_count":1}}
`
	if err := os.WriteFile(filepath.Join(dir, "google-personal.jsonl"), []byte(earlier), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.sync(env.Paths().Out); err != nil {
		t.Fatal(err)
	}
	open := func() int {
		tr, err := tracker.LoadOrNew(env.Tracker, env.Now())
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, it := range tr.Items {
			if it.Active(env.Now()) {
				n++
			}
		}
		return n
	}
	before := open()
	if before < 2 {
		t.Fatalf("the earlier run made %d active items", before)
	}
	if err := env.Run(context.Background(), Options{Connectors: []string{"google-personal"}}); err != nil {
		t.Fatal(err)
	}
	if after := open(); after != before {
		t.Fatalf("active items %d, were %d", after, before)
	}
	tr, err := tracker.LoadOrNew(env.Tracker, env.Now())
	if err != nil {
		t.Fatal(err)
	}
	held := 0
	for _, it := range tr.Items {
		if slices.ContainsFunc(it.History, func(ev tracker.Event) bool { return strings.Contains(ev.Detail, reasonUnreachable) }) {
			held++
		}
	}
	if held == 0 {
		t.Fatal("the sync never saw the skipped run")
	}
}

// One notification once the browser connectors have been skipped for longer than
// browser_stale_days, not one a day after it, and again only after they ran in between.
func TestRunNotifiesOnceWhenTheBrowserConnectorsHaveNotRunForDays(t *testing.T) {
	env, r, out := testEnv(t, "darwin")
	day := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	clock := day
	env.Now = func() time.Time { return clock }
	at := func(d int, probe func(context.Context, string) (cdp.Version, error)) int {
		t.Helper()
		clock, env.Browser = day.Add(time.Duration(d)*24*time.Hour), probe
		if err := env.Run(context.Background(), Options{}); err != nil {
			t.Fatal(err)
		}
		return len(r.ran(osascript, "-e"))
	}
	var ignored time.Time
	for d, want := range []int{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1} {
		if got := at(d, unreachable); got != want {
			t.Fatalf("day %d: %d notifications, want %d", d, got, want)
		}
	}
	note := r.ran(osascript, "-e")[0][2]
	if note != `display notification "browser connectors haven't run in 8 days" with title "segurata" subtitle "browser not reachable over CDP"` {
		t.Fatalf("notification %s", note)
	}
	if !strings.Contains(out.String(), "browser connectors haven't run in 8 days\n") {
		t.Fatalf("log:\n%s", out)
	}
	at(11, brave(&ignored))
	for d := 12; d <= 19; d++ {
		at(d, unreachable)
	}
	if got := at(20, unreachable); got != 2 {
		t.Fatalf("after running again and 9 days skipped: %d notifications", got)
	}

	env.Config.BrowserStaleDays = -1
	if err := os.Remove(env.Paths().BrowserState); err != nil {
		t.Fatal(err)
	}
	at(30, unreachable)
	if got := at(60, unreachable); got != 2 {
		t.Fatalf("browser_stale_days -1 notified: %d", got)
	}
}
