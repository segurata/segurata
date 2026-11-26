package signin

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

const usage = `usage: segurata signin [connector|instance ...] [--all] [--list] [--timeout 10m] [--out out]
Opens, in the browser at cdp_url, a tab at every page where you have to sign in again or confirm
your identity for a browser connector (open setup items in reauth or signedout), waits while you
do it, reading the pages without typing or clicking anything, then runs those connector instances
again and says which setup items closed. Commands to run in your terminal (gcloud auth login,
gh auth refresh) are listed, never run. Accounts taken out with segurata accounts unwatch are skipped.
  --all       also list the commands of other open setup items (credentials to store)
  --list      only print what it would open and list; opens nothing
  --timeout   stop waiting after this long (Enter stops earlier)
  --out       inventory output directory`

// CLI is `segurata signin`.
type CLI struct {
	Out, Err   io.Writer
	In         io.Reader // Enter stops waiting; read only when TTY
	TTY        bool
	Config     string
	Paths      tracker.Paths // zero means tracker.DefaultPaths
	Now        func() time.Time
	Connectors []connector.Connector
	// Connect opens the browser at cdp_url; it never starts one.
	Connect   func(ctx context.Context, cdpURL string) (Browser, func(), error)
	Inventory func(ctx context.Context, cfg config.Config, targets []run.Target, out string) ([]*run.Result, error)
	Sync      func(out string) int // segurata track sync, its exit code
	Interval  time.Duration        // zero is the default
}

func (c CLI) fail(err error) int { return textfmt.Fail(c.Err, "signin", err) }

func (c CLI) Run(ctx context.Context, args []string) int {
	fs := cliflag.New("signin", c.Err)
	fs.Usage = func() { fmt.Fprintln(c.Err, usage) }
	all := fs.Bool("all", false, "also list the commands of other open setup items")
	list := fs.Bool("list", false, "only print what it would open")
	timeout := fs.Duration("timeout", 10*time.Minute, "stop waiting after this long")
	out := fs.String("out", config.DefaultOutDir(), "inventory output directory")
	selectors, err := cliflag.Parse(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	cfg, err := config.Load(c.Config)
	if err != nil {
		return c.fail(err)
	}
	targets, err := run.Targets(cfg, c.Connectors, selectors)
	if err != nil {
		fmt.Fprintln(c.Err, "signin:", err)
		return 2
	}
	paths, err := c.Paths.Resolve()
	if err != nil {
		return c.fail(err)
	}
	now := c.Now()
	tr, err := tracker.LoadOrNew(paths, now)
	if err != nil {
		return c.fail(err)
	}
	items := collect(tr.Items, targets, cfg.Accounts, *all, now)
	// Pages first, so the numbers read in order.
	withPage := slices.DeleteFunc(slices.Clone(items), func(it item) bool { return it.Page == nil })
	items = append(withPage, slices.DeleteFunc(items, func(it item) bool { return it.Page != nil })...)
	if len(items) == 0 {
		fmt.Fprintln(c.Out, "Nothing to sign in to: no open setup item needs you in the browser or the terminal.")
		return 0
	}
	pages := c.printList(items)
	pageTargets := reruns(items, make([]outcome, len(items)), nil)
	if *list {
		if pages > 0 {
			fmt.Fprintf(c.Out, "\nsegurata signin would open %d %s in the browser at %s, wait up to %s, then run %s again.\n",
				pages, textfmt.Plural(pages, "tab", "tabs"), cfg.CDPURL, *timeout, strings.Join(pageTargets, ", "))
		}
		return 0
	}
	if pages == 0 {
		return 0
	}

	b, closeBrowser, err := c.Connect(ctx, cfg.CDPURL)
	if err != nil {
		fmt.Fprintf(c.Out, "\nThe browser at %s is not reachable (%v). segurata only opens tabs in that browser, never another one: open the pages above yourself, then run: segurata inventory %s\n",
			cfg.CDPURL, err, strings.Join(pageTargets, " "))
		return 1
	}
	defer closeBrowser()

	var mu sync.Mutex
	var wg sync.WaitGroup
	early := map[string]time.Time{}
	var results []*run.Result
	rerun := func(labels []string) {
		res, err := c.Inventory(ctx, cfg, pick(targets, labels), *out)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			fmt.Fprintf(c.Err, "signin: running %s: %v\n", strings.Join(labels, ", "), err)
		}
		results = append(results, res...)
	}
	onDone := func(i int) {
		it := items[i]
		mu.Lock()
		_, ran := early[it.Target]
		if !it.Page.Brief || ran {
			mu.Unlock()
			return
		}
		early[it.Target] = c.Now()
		mu.Unlock()
		fmt.Fprintf(c.Out, "  Running %s now, while it lasts.\n", it.Target)
		wg.Add(1)
		go func() {
			defer wg.Done()
			rerun([]string{it.Target})
		}()
	}

	fmt.Fprintf(c.Out, "\nOpened the pages above in the browser. Waiting until each shows what segurata reads (up to %s", *timeout)
	var enter <-chan struct{}
	if c.TTY {
		fmt.Fprint(c.Out, "; press Enter when you are done")
		enter = readLine(c.In)
	}
	fmt.Fprintln(c.Out, ").")
	outcomes := wait(ctx, b, items, waitOptions{Interval: c.Interval, Timeout: *timeout, Enter: enter, Progress: c.Out, OnDone: onDone, Now: c.Now})
	wg.Wait()

	if labels := reruns(items, outcomes, early); len(labels) > 0 && ctx.Err() == nil {
		fmt.Fprintf(c.Out, "Running %s again.\n", strings.Join(labels, ", "))
		rerun(labels)
	}
	if len(results) == 0 {
		return 0
	}
	run.StatusSummary(c.Out, results)
	if code := c.Sync(*out); code != 0 {
		return code
	}
	return c.report(paths.Tracker, items)
}

// printList returns how many items are pages.
func (c CLI) printList(items []item) int {
	pages := 0
	for _, it := range items {
		if it.Page != nil {
			pages++
		}
	}
	if pages > 0 {
		fmt.Fprintln(c.Out, "In the browser:")
		for i, it := range items {
			if it.Page != nil {
				fmt.Fprintf(c.Out, "  %d. %s: %s\n     %s  (%s)\n", i+1, it.Title, it.Do(), it.Page.URL, it.TrackerID)
			}
		}
	}
	if pages < len(items) {
		fmt.Fprintln(c.Out, "In your terminal (segurata does not run these):")
		for i, it := range items {
			if it.Page == nil {
				fmt.Fprintf(c.Out, "  %d. %s  (%s)\n     %s\n     then: segurata inventory %s\n", i+1, it.Title, it.TrackerID, it.Command, it.Target)
			}
		}
	}
	return pages
}

func (c CLI) report(trackerFile string, items []item) int {
	tr, err := tracker.Load(trackerFile)
	if err != nil {
		return c.fail(err)
	}
	byID := map[string]*tracker.Item{}
	for _, it := range tr.Items {
		byID[it.ID] = it
	}
	fmt.Fprintln(c.Out, "\nSetup items:")
	for i, it := range items {
		t := byID[it.TrackerID]
		switch {
		case t == nil:
			fmt.Fprintf(c.Out, "  %d. %s: gone from the tracker\n", i+1, it.TrackerID)
		case t.Closed():
			fmt.Fprintf(c.Out, "  %d. %s closed (%s): %s\n", i+1, t.ID, t.Status, t.Title)
		default:
			fmt.Fprintf(c.Out, "  %d. %s still open: %s\n", i+1, t.ID, t.Title)
		}
	}
	return 0
}

func pick(targets []run.Target, labels []string) []run.Target {
	var out []run.Target
	for _, l := range labels {
		for _, t := range targets {
			if t.Label() == l {
				out = append(out, t)
			}
		}
	}
	return out
}

// readLine closes the channel on Enter. Closed stdin is not Enter (a non-interactive runner can
// still report a terminal), so the wait then goes on.
func readLine(r io.Reader) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		if enterPressed(r) {
			close(ch)
		}
	}()
	return ch
}

func enterPressed(r io.Reader) bool {
	_, err := bufio.NewReader(r).ReadString('\n')
	return err == nil
}
