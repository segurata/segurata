package schedule

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

var confirmFunc = prompt.Confirm

// Run is one scheduled run, what the agent executes: `segurata inventory` over the selected
// connectors (which ends in a tracker sync), a notification for the P0 and P1 items that sync
// found or reopened, then `segurata report --format md`. Both commands are this same binary, run
// as separate processes so a scheduled run does exactly what the owner would type.
//
// Without --connectors every installed connector is selected. The browser connectors run only when
// Brave answers at cdp_url (probeBrowser); otherwise each gets a run file saying it inspected
// nothing and why, and a notification once they have been skipped for longer than
// browser_stale_days.
//
// The run ends before the next one is due, and the inventory early enough to leave time for the
// report: launchd starts no run while one is still going, so one that hung would stop scheduled
// scanning without a word.
func (e Env) Run(ctx context.Context, o Options) error {
	every, err := o.every()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, every*9/10)
	defer cancel()
	invCtx, cancelInv := context.WithTimeout(ctx, every*8/10)
	defer cancelInv()
	p := e.Paths()
	if err := os.MkdirAll(p.Out, 0o700); err != nil {
		return err
	}
	connectors := o.Connectors
	if len(connectors) == 0 {
		connectors = e.names()
	}
	start := e.Now()
	var skipped, stale string // why the browser connectors were skipped; the notification that is due
	if browser, rest := e.splitBrowser(connectors); len(browser) > 0 {
		var why error
		if skipped, why = e.probeBrowser(invCtx); skipped != "" {
			e.stamp(fmt.Sprintf("skipped %s: %s (%v)", strings.Join(browser, " "), skipped, why))
			e.recordSkipped(invCtx, browser, skipped)
			stale = e.browserSkipped(start)
			connectors = rest
		} else {
			e.browserRan(start)
		}
	}
	// Nothing left to inventory still folds the skipped runs into the tracker.
	inv := []string{"track", "sync", "--out", p.Out}
	if len(connectors) > 0 {
		e.stamp("inventory " + strings.Join(connectors, " "))
		inv = append([]string{"inventory", "--out", p.Out}, connectors...)
	}
	if err := e.Runner.Run(invCtx, e.Exe, inv, e.IO.Out, e.IO.Err); err != nil {
		return fmt.Errorf("%s: %w", inv[0], err)
	}
	fresh, err := e.news(start)
	if err != nil {
		return err
	}
	if len(fresh) > 0 {
		e.stamp(textfmt.Count(len(fresh), "new P0 or P1 item", "new P0 or P1 items"))
		for _, it := range fresh {
			fmt.Fprintf(e.IO.Out, "  [%s] %s %s\n", it.EffectivePriority(), it.ID, it.Title)
		}
		e.notify(ctx, notification(fresh))
	}
	if stale != "" {
		e.stamp(stale)
		e.notify(ctx, appleNotification(stale, skipped))
	}
	e.stamp("report " + p.Report)
	rep := []string{"report", "--format", "md", "--out", p.Report, "--dir", p.Out}
	if err := e.Runner.Run(ctx, e.Exe, rep, e.IO.Out, e.IO.Err); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	e.prune(p.Out)
	return nil
}

// names are every installed connector, sorted: the selection when none is named.
func (e Env) names() []string {
	out := make([]string, 0, len(e.Connectors))
	for _, c := range e.Connectors {
		out = append(out, c.Describe().Name)
	}
	slices.Sort(out)
	return out
}

// notify posts a macOS notification; elsewhere the log line before it is all there is.
func (e Env) notify(ctx context.Context, script string) {
	if e.GOOS != "darwin" {
		return
	}
	if err := e.Runner.Run(ctx, osascript, []string{"-e", script}, e.IO.Out, e.IO.Err); err != nil {
		fmt.Fprintf(e.IO.Err, "notification failed: %v\n", err)
	}
}

// stamp logs one step of the run with the time.
func (e Env) stamp(msg string) {
	fmt.Fprintf(e.IO.Out, "%s %s\n", e.Now().Format("2006-01-02 15:04:05"), msg)
}

// prune removes run files older than the config's keep_runs_days that no latest run needs (run.Prune). A failure is
// logged: the scan itself succeeded.
func (e Env) prune(outDir string) {
	keep := e.Config.RunRetention()
	if keep <= 0 {
		return
	}
	removed, err := run.Prune(outDir, e.Now(), e.Now().Add(-keep))
	if len(removed) > 0 {
		e.stamp(fmt.Sprintf("pruned %d run files older than %s", len(removed), keep))
	}
	if err != nil {
		fmt.Fprintf(e.IO.Err, "pruning %s: %v\n", outDir, err)
	}
}

// news are the open P0 and P1 items that a sync found or reopened at or after start, most urgent
// first: what the inventory's sync recorded.
func (e Env) news(start time.Time) ([]*tracker.Item, error) {
	t, err := tracker.LoadOrNew(e.Tracker, e.Now())
	if err != nil {
		return nil, err
	}
	var out []*tracker.Item
	for _, it := range t.Items {
		if p := it.EffectivePriority(); !it.Active(e.Now()) || p != secretrisk.P0 && p != secretrisk.P1 {
			continue
		}
		if slices.ContainsFunc(it.History, func(ev tracker.Event) bool {
			return (ev.Event == tracker.EvFound || ev.Event == tracker.EvReopened) && !ev.At.Before(start.UTC())
		}) {
			out = append(out, it)
		}
	}
	tracker.Sort(out)
	return out, nil
}

const maxNotified = 3

// notification is the AppleScript that posts one notification naming the new items by title.
// Titles never hold secrets (docs/connectors.md); evidence is never shown.
func notification(fresh []*tracker.Item) string {
	var titles []string
	what := string(fresh[0].EffectivePriority())
	for i, it := range fresh {
		if it.EffectivePriority() != fresh[0].EffectivePriority() {
			what = "P0 or P1"
		}
		switch {
		case i < maxNotified:
			titles = append(titles, it.Title)
		case i == maxNotified:
			titles = append(titles, fmt.Sprintf("and %d more", len(fresh)-maxNotified))
		}
	}
	return appleNotification(strings.Join(titles, "; "), textfmt.Count(len(fresh), "new "+what+" item", "new "+what+" items"))
}

// appleNotification is the AppleScript that posts one notification titled segurata.
func appleNotification(text, subtitle string) string {
	return fmt.Sprintf("display notification %s with title %s subtitle %s",
		appleString(text), appleString("segurata"), appleString(subtitle))
}

// appleString quotes s as an AppleScript string literal.
func appleString(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
