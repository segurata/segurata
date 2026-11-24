// Package accept is `segurata accept` and `segurata unaccept`: keep a risk on purpose, such as
// a browser debugging port that local agents need. An accepted finding is still inventoried and
// written to the JSONL (with an "accepted" field) but left out of the summary and of `remediate
// --list` until its acceptance expires. Acceptances live in the tracker, as items with status
// accepted. See docs/architecture.md, "Accepted risks".
package accept

import (
	"flag"
	"fmt"
	"github.com/segurata/segurata/internal/config"
	"io"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/tracker"
)

const (
	acceptUsage   = "usage: segurata accept <finding-id> --reason text [--until YYYY-MM-DD] | segurata accept --list"
	unacceptUsage = "usage: segurata unaccept <finding-id>"
)

// CLI is `segurata accept` and `segurata unaccept`.
type CLI struct {
	Out, Err io.Writer
	Paths    tracker.Paths // zero means tracker.DefaultPaths
	Now      func() time.Time
}

func (c CLI) fail(err error) int {
	fmt.Fprintln(c.Err, err)
	return 1
}

// load loads the tracker; with lock it first takes the tracker lock, held until unlock, for a
// command that saves it.
func (c CLI) load(now time.Time, lock bool) (t *tracker.Tracker, path string, unlock func(), err error) {
	unlock = func() {}
	p, err := c.Paths.Resolve()
	if err != nil {
		return nil, "", unlock, err
	}
	if lock {
		if unlock, err = tracker.Lock(p.Tracker); err != nil {
			return nil, "", func() {}, err
		}
	}
	t, err = tracker.LoadOrMigrate(p, now, c.Err)
	return t, p.Tracker, unlock, err
}

// Accept records a finding of the latest run as an accepted risk, or lists the accepted ones.
func (c CLI) Accept(args []string) int {
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	list := fs.Bool("list", false, "list accepted findings")
	reason := fs.String("reason", "", "why the risk is kept on purpose")
	until := fs.String("until", "", "last day the acceptance applies, YYYY-MM-DD (default: no end)")
	out := fs.String("out", config.DefaultOutDir(), "inventory output directory")
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) > 1 || (len(pos) == 1) == *list {
		fmt.Fprintln(c.Err, acceptUsage)
		return 2
	}
	now := c.Now()
	t, path, unlock, err := c.load(now, !*list)
	defer unlock()
	if err != nil {
		return c.fail(err)
	}
	if *list {
		c.list(t, now)
		return 0
	}
	files, err := remediate.LatestFiles(*out)
	if err != nil {
		return c.fail(err)
	}
	all, err := remediate.Load(files)
	if err != nil {
		return c.fail(err)
	}
	f, err := remediate.Find(all, pos[0])
	if err != nil {
		return c.fail(err)
	}
	it, err := t.AcceptFinding(f, *reason, *until, now)
	if err != nil {
		return c.fail(err)
	}
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "Accepted %s [%s] %s · %s (%s), tracker item %s.\n", f.ID, f.Severity, f.Connector, f.Title, untilText(it.Accepted), it.ID)
	return 0
}

// Unaccept removes an acceptance, so the finding shows again.
func (c CLI) Unaccept(args []string) int {
	fs := flag.NewFlagSet("unaccept", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprintln(c.Err, unacceptUsage)
		return 2
	}
	now := c.Now()
	t, path, unlock, err := c.load(now, true)
	defer unlock()
	if err != nil {
		return c.fail(err)
	}
	it, err := t.Unaccept(pos[0], now)
	if err != nil {
		return c.fail(err)
	}
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "No longer accepted: %s %s · %s (open again).\n", findingID(it), connectorOf(it), it.Title)
	return 0
}

func (c CLI) list(t *tracker.Tracker, now time.Time) {
	items := t.AcceptedItems()
	for _, it := range items {
		state := "accepted"
		if it.AcceptanceExpired(now) {
			state = "acceptance expired"
		}
		fmt.Fprintf(c.Out, "%s  %-18s %-22s %-16s %s\n", findingID(it), state, untilText(it.Accepted), connectorOf(it), it.Title)
		fmt.Fprintf(c.Out, "%18s reason: %s (accepted %s, item %s)\n", "", it.Accepted.Reason, it.Accepted.AcceptedAt.In(now.Location()).Format(time.DateOnly), it.ID)
	}
	fmt.Fprintf(c.Out, "\n%d accepted findings. Show them again with: segurata unaccept <id>\n", len(items))
}

// findingID names an accepted item by its finding, as `accept` was given it.
func findingID(it *tracker.Item) string {
	if len(it.Findings) == 1 {
		return it.Findings[0].ID
	}
	return it.ID
}

func connectorOf(it *tracker.Item) string {
	if len(it.Findings) > 0 {
		return it.Findings[0].Connector
	}
	return "-"
}

func untilText(a *tracker.Acceptance) string {
	if a.Until == "" {
		return "no end date"
	}
	return "until " + a.Until
}
