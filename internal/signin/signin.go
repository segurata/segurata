// Package signin is `segurata signin`: it opens, in the browser segurata drives, the pages where
// the owner has to sign in again or confirm their identity for a browser connector, waits while
// they do, reading each page and never typing or clicking anything, then runs the affected
// connector instances again and says which setup items closed. Commands the owner has to run in
// a terminal (gcloud auth login, gh auth refresh) are listed, never executed. See README,
// "Signing in".
package signin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/tracker"
)

// Item is one thing the owner does so a connector sees an account again: a page in the browser
// (Page) or a command in their terminal (Command).
type Item struct {
	TrackerID string         // the setup item it clears
	Title     string         // the setup item's title
	Target    string         // the connector instance to run again, by label
	Status    finding.Status // the status it clears
	Page      *connector.SignInPage
	Command   string
}

// Do is what the owner does, in a few words.
func (it Item) Do() string {
	switch {
	case it.Page != nil && it.Page.Do != "":
		return it.Page.Do
	case it.Page != nil:
		return "sign in on this page"
	}
	return "run in your terminal: " + it.Command
}

// signInStates are the states a sign-in clears. noscope counts for commands: the fix is a fresh
// sign-in with more scopes (gh auth refresh -s …).
var (
	pageStates    = []finding.State{finding.StateReauth, finding.StateSignedOut}
	commandStates = []finding.State{finding.StateReauth, finding.StateSignedOut, finding.StateNoScope}
)

// Collect lists what the owner can do about the active setup items of the given connector
// instances, in tracker order: for a status whose detail names a command, that command; for a
// reauth or signedout status of a browser connector, the page its SignInPage names (or the URL
// the item gives, without a way to tell when it is done). Commands count for reauth, signedout
// and noscope statuses, or for any state with all. Accounts the config does not watch (accounts
// is cfg.Accounts) are skipped, as are instances not in targets.
func Collect(items []*tracker.Item, targets []run.Target, accounts func(label string) ([]string, bool), all bool, now time.Time) []Item {
	byLabel := map[string]connector.Connector{}
	for _, t := range targets {
		byLabel[t.Label()] = t.Connector
	}
	var out []Item
	for _, it := range items {
		if it.Kind != tracker.KindSetup || !it.Active(now) {
			continue
		}
		if x, ok := collectOne(it, byLabel, accounts, all); ok {
			out = append(out, x)
		}
	}
	return out
}

func collectOne(it *tracker.Item, byLabel map[string]connector.Connector, accounts func(string) ([]string, bool), all bool) (Item, bool) {
	sts := it.SetupStatuses()
	if len(sts) == 0 {
		return Item{}, false
	}
	st := sts[0]
	lbl := label(st)
	conn, ok := byLabel[lbl]
	if !ok || !watched(accounts, lbl, st.Account) {
		return Item{}, false
	}
	x := Item{TrackerID: it.ID, Title: it.Title, Target: lbl, Status: st}
	var cmds []string
	for _, s := range sts {
		if c := tracker.StatusCommand(s); c != "" && !slices.Contains(cmds, c) {
			cmds = append(cmds, c)
		}
	}
	if len(cmds) > 0 {
		x.Command = strings.Join(cmds, " && ")
		return x, all || slices.Contains(commandStates, st.State)
	}
	if !slices.Contains(pageStates, st.State) || !conn.Describe().NeedsCDP() {
		return Item{}, false
	}
	if si, ok := conn.(connector.SignInner); ok {
		for _, s := range sts {
			if p, ok := si.SignInPage(s); ok {
				x.Status = s
				x.Page = &p
				return x, true
			}
		}
	}
	if it.Next != nil && it.Next.URL != "" {
		x.Page = &connector.SignInPage{URL: it.Next.URL}
		return x, true
	}
	return Item{}, false
}

func label(st finding.Status) string {
	if st.Instance == "" {
		return st.Connector
	}
	return st.Connector + ":" + st.Instance
}

// watched reports whether the config watches the account: true unless the instance has an
// accounts list (segurata accounts watch/unwatch) that leaves it out.
func watched(accounts func(string) ([]string, bool), lbl, account string) bool {
	if accounts == nil || account == "" {
		return true
	}
	list, set := accounts(lbl)
	return !set || slices.ContainsFunc(list, func(a string) bool { return strings.EqualFold(a, account) })
}

// Tab is a page open in the browser whose state can be read.
type Tab interface {
	Evaluate(ctx context.Context, expr string) (json.RawMessage, error)
}

// Browser opens foreground tabs that are never closed: the owner's to use.
type Browser interface {
	OpenTab(ctx context.Context, url string) (Tab, error)
}

// CDP is the Browser at a CDP client: tabs in the browser segurata already drives, never another.
type CDP struct{ *cdp.Client }

func (b CDP) OpenTab(ctx context.Context, url string) (Tab, error) { return b.Client.OpenTab(ctx, url) }

// Outcome is how waiting ended for one item.
type Outcome struct {
	Done   bool      // the page shows what the connector reads
	At     time.Time // when Done was seen
	Closed bool      // the tab went away (closed by the owner) before it was done
	Err    error     // the tab could not be opened
}

// WaitOptions tune Wait. Zero Interval and Timeout take the defaults.
type WaitOptions struct {
	Interval time.Duration   // between two reads of the pages; default 3s
	Timeout  time.Duration   // give up after; default 10 minutes
	Enter    <-chan struct{} // closed when the owner says they are done
	Progress io.Writer
	// OnDone runs as soon as item i is done, before Wait returns: reruns that cannot wait.
	OnDone func(i int)
	Now    func() time.Time
}

// confirmations is how many reads in a row must find a page done: one read can catch a page
// halfway through a redirect.
const confirmations = 2

// Wait opens a tab for every item with a page and reads each until its Done holds on
// confirmations reads in a row, its tab goes away, the owner closes Enter, the timeout passes or
// ctx ends. Pages without Done wait for Enter or the timeout. Outcomes are in items' order;
// items without a page get the zero Outcome.
func Wait(ctx context.Context, b Browser, items []Item, o WaitOptions) []Outcome {
	if o.Interval == 0 {
		o.Interval = 3 * time.Second
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Progress == nil {
		o.Progress = io.Discard
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	out := make([]Outcome, len(items))
	tabs := make([]Tab, len(items))
	streak := make([]int, len(items))
	for i, it := range items {
		if it.Page == nil {
			continue
		}
		if tabs[i], out[i].Err = b.OpenTab(ctx, it.Page.URL); out[i].Err != nil {
			fmt.Fprintf(o.Progress, "  %d. could not open %s: %v\n", i+1, it.Page.URL, out[i].Err)
		}
	}
	pending := func() (auto, manual int) {
		for i, it := range items {
			switch {
			case tabs[i] == nil || out[i].Done || out[i].Closed:
			case it.Page.Done == nil:
				manual++
			default:
				auto++
			}
		}
		return auto, manual
	}
	tick := time.NewTicker(o.Interval)
	defer tick.Stop()
	for {
		auto, manual := pending()
		if auto == 0 && manual == 0 {
			return out
		}
		select {
		case <-ctx.Done():
			fmt.Fprintf(o.Progress, "Stopped waiting (%s).\n", reason(ctx.Err()))
			return out
		case <-o.Enter:
			return out
		case <-tick.C:
		}
		for i, it := range items {
			if tabs[i] == nil || out[i].Done || out[i].Closed || it.Page.Done == nil {
				continue
			}
			v, err := tabs[i].Evaluate(ctx, it.Page.Expr)
			var evalErr *cdp.EvalError
			switch {
			case errors.As(err, &evalErr), err != nil && ctx.Err() != nil:
				streak[i] = 0
			case err != nil:
				out[i].Closed = true
				fmt.Fprintf(o.Progress, "  %d. tab closed before it was done: %s\n", i+1, it.Title)
			case it.Page.Done(v):
				if streak[i]++; streak[i] >= confirmations {
					out[i].Done, out[i].At = true, o.Now()
					n, total := progress(items, out)
					fmt.Fprintf(o.Progress, "  %d. done (%d of %d): %s\n", i+1, n, total, it.Title)
					if o.OnDone != nil {
						o.OnDone(i)
					}
				}
			default:
				streak[i] = 0
			}
		}
	}
}

func reason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "interrupted"
}

// progress counts the pages done and the pages opened.
func progress(items []Item, out []Outcome) (done, total int) {
	for i, it := range items {
		if it.Page != nil && out[i].Err == nil {
			total++
			if out[i].Done {
				done++
			}
		}
	}
	return done, total
}

// Reruns are the connector instances to run once waiting is over, in item order: the target of
// every page item, except a target already run early (early holds when that run started) whose
// pages were all done before then, or left undone. Command items are left to the owner, who runs
// them in a terminal.
func Reruns(items []Item, out []Outcome, early map[string]time.Time) []string {
	var labels []string
	need := map[string]bool{}
	for i, it := range items {
		if it.Page == nil || out[i].Err != nil {
			continue
		}
		if !slices.Contains(labels, it.Target) {
			labels = append(labels, it.Target)
		}
		started, ran := early[it.Target]
		if !ran || out[i].Done && out[i].At.After(started) {
			need[it.Target] = true
		}
	}
	return slices.DeleteFunc(labels, func(l string) bool { return !need[l] })
}
