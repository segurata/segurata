package schedule

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/runfile"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

// Run is what the agent executes: `segurata inventory` (which ends in a tracker sync), a
// notification for the P0 and P1 items that sync brought, then `segurata report`, each as the owner
// would type it. Brave is probed too, to log a skip and notify once the browser connectors have
// been skipped for longer than browser_stale_days.
//
// The run ends before the next is due, and the inventory early enough to leave time for the
// report: launchd starts none while one is going, so a hung run would stop scheduled scanning
// without a word.
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
	if err := fileacl.MkdirPrivate(p.Out); err != nil {
		return err
	}
	connectors := o.Connectors
	if len(connectors) == 0 {
		connectors = e.names()
	}
	start := e.Now()
	var skipped, stale string // why the browser connectors are skipped; the notification that is due
	if browser := e.browserSelected(connectors); len(browser) > 0 {
		var why error
		if skipped, why = run.BrowserProblem(invCtx, e.Config.CDPURL, e.Browser); skipped != "" {
			e.stamp(fmt.Sprintf("skipped %s: %s (%v)", strings.Join(browser, " "), skipped, why))
			stale = e.browserSkipped(start)
		} else {
			e.browserRan(start)
		}
	}
	e.stamp("inventory " + strings.Join(connectors, " "))
	inv := append([]string{"inventory", "--out", p.Out}, connectors...)
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
		if e.notify(ctx, appleNotification(stale, skipped)) {
			e.browserNotified()
		}
	}
	e.stamp("report " + p.Report)
	rep := []string{"report", "--format", "md", "--out", p.Report, "--dir", p.Out}
	if err := e.Runner.Run(ctx, e.Exe, rep, e.IO.Out, e.IO.Err); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	e.prune(p.Out)
	return nil
}

func (e Env) names() []string {
	out := make([]string, 0, len(e.Connectors))
	for _, c := range e.Connectors {
		out = append(out, c.Describe().Name)
	}
	slices.Sort(out)
	return out
}

// notify posts a macOS notification, and reports whether the owner was told by it or, elsewhere, by
// the log line before it.
func (e Env) notify(ctx context.Context, script string) bool {
	if e.GOOS != "darwin" {
		return true
	}
	if err := e.Runner.Run(ctx, osascript, []string{"-e", script}, e.IO.Out, e.IO.Err); err != nil {
		fmt.Fprintf(e.IO.Err, "notification failed: %v\n", err)
		return false
	}
	return true
}

func (e Env) stamp(msg string) {
	fmt.Fprintf(e.IO.Out, "%s %s\n", e.Now().Format("2006-01-02 15:04:05"), msg)
}

// prune applies keep_runs_days (runfile.Prune); a failure is only logged, the scan succeeded.
func (e Env) prune(outDir string) {
	keep := e.Config.RunRetention()
	if keep <= 0 {
		return
	}
	removed, err := runfile.Prune(outDir, e.Now(), e.Now().Add(-keep))
	if len(removed) > 0 {
		e.stamp(fmt.Sprintf("pruned %d run files older than %s", len(removed), keep))
	}
	if err != nil {
		fmt.Fprintf(e.IO.Err, "pruning %s: %v\n", outDir, err)
	}
}

// news are the active P0 and P1 items with news since start, most urgent first.
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
		if it.NewsSince(start) {
			out = append(out, it)
		}
	}
	tracker.Sort(out)
	return out, nil
}

const maxNotified = 3

// notification names the new items by title; titles never hold secrets (docs/connectors.md), and
// evidence is never shown.
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

func appleNotification(text, subtitle string) string {
	return fmt.Sprintf("display notification %s with title %s subtitle %s",
		appleString(text), appleString("segurata"), appleString(subtitle))
}

func appleString(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
