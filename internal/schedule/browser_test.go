package schedule

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/run"
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

// Brave not answering: the inventory still gets every connector, since run.Inventory itself
// refuses to drive anything but Brave and records each browser connector's run as skipped
// (internal/run, TestBrowserConnectorsRunOnlyAgainstBrave). The schedule logs the skip in one
// line. The probe is the real one, against a fake CDP address where nothing listens.
func TestRunLogsTheSkipWhenBraveDoesNotAnswer(t *testing.T) {
	env, r, out := testEnv(t, "darwin")
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	env.Browser, env.Config.CDPURL = cdp.Brave, gone.URL
	if err := env.Run(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	inv := r.ran(env.Exe, "inventory")
	if len(inv) != 1 || !slices.Equal(inv[0][4:], []string{"connected-apps", "google-personal", "hibp", "macos"}) {
		t.Fatalf("inventory calls %v", inv)
	}
	if n := strings.Count(out.String(), "skipped "); n != 1 || !strings.Contains(out.String(), "skipped connected-apps google-personal: browser not reachable over CDP (cdp: browser not reachable at "+gone.URL) {
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
	if deadline.IsZero() || deadline.After(start.Add(run.BrowserProbeTimeout+time.Second)) {
		t.Fatalf("probe deadline %v", deadline)
	}
	if strings.Contains(out.String(), "skipped") {
		t.Fatalf("logged a skip:\n%s", out)
	}
}

// Another browser on the port is logged as the reason of the skip.
func TestRunLogsABrowserThatIsNotBrave(t *testing.T) {
	env, _, out := testEnv(t, "darwin")
	env.Browser = func(context.Context, string) (cdp.Version, error) {
		return cdp.Version{}, fmt.Errorf("cdp: the browser at x (Chrome/156) is %w", cdp.ErrNotBrave)
	}
	if err := env.Run(context.Background(), Options{Connectors: []string{"google-personal", "macos"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "skipped google-personal: "+run.ReasonNotBrave) {
		t.Fatalf("log:\n%s", out)
	}
}

// Without a browser connector selected there is nothing to probe.
func TestRunProbesOnlyForBrowserConnectors(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	env.Browser = func(context.Context, string) (cdp.Version, error) { t.Fatal("probed"); return cdp.Version{}, nil }
	if err := env.Run(context.Background(), Options{Connectors: []string{"macos", "hibp"}}); err != nil {
		t.Fatal(err)
	}
	if len(r.ran(env.Exe, "inventory")) != 1 {
		t.Fatalf("calls %v", r.calls)
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

// The staleness notice is remembered as sent only once it was: a run that stops before notifying
// (the inventory failed) leaves it due for the next run.
func TestTheStalenessNoticeIsNotLostWhenARunStopsEarly(t *testing.T) {
	env, r, _ := testEnv(t, "darwin")
	day := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	clock := day
	env.Now, env.Browser = func() time.Time { return clock }, unreachable
	if err := env.Run(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	clock = day.Add(9 * 24 * time.Hour)
	r.fail = map[string]error{"inventory": errors.New("inventory crashed")}
	if err := env.Run(context.Background(), Options{}); err == nil {
		t.Fatal("a failed inventory must fail the run")
	}
	r.fail = nil
	clock = clock.Add(24 * time.Hour)
	if err := env.Run(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	if n := len(r.ran(osascript, "-e")); n != 1 {
		t.Fatalf("%d notifications, want the one the failed run never sent", n)
	}
}
