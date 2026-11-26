// Package signin is `segurata signin`: it opens the pages where the owner signs in again for a
// browser connector, waits while they do, reading but never typing or clicking, then runs those
// connectors again. Terminal commands are listed, never run. See docs/user-guide.md, "Signing in".
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

// item is a page to act on in the browser, or a Command for the terminal.
type item struct {
	TrackerID string // the setup item it clears
	Title     string
	Target    string // the connector instance label to run again
	Status    finding.Status
	Page      *connector.SignInPage
	Command   string
}

func (it item) Do() string {
	switch {
	case it.Page != nil && it.Page.Do != "":
		return it.Page.Do
	case it.Page != nil:
		return "sign in on this page"
	}
	return "run in your terminal: " + it.Command
}

// commandStates are those whose command is a sign-in; noscope's is one with more scopes.
var commandStates = []finding.State{finding.StateReauth, finding.StateSignedOut, finding.StateNoScope}

// collect lists, in tracker order, what the owner can do about the active setup items of targets:
// the command a status names, or the sign-in page of a browser connector (else the item's URL,
// with no way to tell when it is done). all lists commands of every state. Accounts the config
// does not watch are skipped.
func collect(items []*tracker.Item, targets []run.Target, accounts func(label string) ([]string, bool), all bool, now time.Time) []item {
	byLabel := map[string]connector.Connector{}
	for _, t := range targets {
		byLabel[t.Label()] = t.Connector
	}
	var out []item
	for _, it := range items {
		if it.Kind != tracker.KindSetup || !it.Active(now) {
			continue
		}
		if x, ok := collectOne(it, byLabel, accounts, all, now); ok {
			out = append(out, x)
		}
	}
	return out
}

func collectOne(it *tracker.Item, byLabel map[string]connector.Connector, accounts func(string) ([]string, bool), all bool, now time.Time) (item, bool) {
	sts := it.SetupStatuses()
	if len(sts) == 0 {
		return item{}, false
	}
	st := sts[0]
	lbl := tracker.StatusLabel(st)
	conn, ok := byLabel[lbl]
	if !ok || !watched(accounts, lbl, st.Account) {
		return item{}, false
	}
	x := item{TrackerID: it.ID, Title: it.Title, Target: lbl, Status: st}
	if cmds := it.StatusCommands(); len(cmds) > 0 {
		x.Command = strings.Join(cmds, " && ")
		return x, all || slices.Contains(commandStates, st.State)
	}
	if !it.BrowserSignIn(func(string) bool { return conn.Describe().NeedsCDP() }, now) {
		return item{}, false
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
	return item{}, false
}

// watched: true unless the instance's accounts list leaves the account out.
func watched(accounts func(string) ([]string, bool), lbl, account string) bool {
	if accounts == nil || account == "" {
		return true
	}
	list, set := accounts(lbl)
	return !set || slices.ContainsFunc(list, func(a string) bool { return strings.EqualFold(a, account) })
}

type Tab interface {
	Evaluate(ctx context.Context, expr string) (json.RawMessage, error)
}

// Browser opens foreground tabs, never closed: they are the owner's.
type Browser interface {
	OpenTab(ctx context.Context, url string) (Tab, error)
}

type CDP struct{ *cdp.Client }

func (b CDP) OpenTab(ctx context.Context, url string) (Tab, error) { return b.Client.OpenTab(ctx, url) }

type outcome struct {
	Done   bool
	At     time.Time
	Closed bool  // by the owner, before it was done
	Err    error // the tab could not be opened
}

type waitOptions struct {
	Interval time.Duration   // default 3s
	Timeout  time.Duration   // default 10 minutes
	Enter    <-chan struct{} // closed when the owner says they are done
	Progress io.Writer
	OnDone   func(i int) // runs at once, for reruns that cannot wait
	Now      func() time.Time
}

// confirmations: one read can catch a page halfway through a redirect.
const confirmations = 2

// wait reads each item's tab until Done holds on confirmations reads in a row or the tab goes
// away, until Enter, the timeout or ctx. Pages without Done wait for Enter or the timeout.
func wait(ctx context.Context, b Browser, items []item, o waitOptions) []outcome {
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

	out := make([]outcome, len(items))
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
	waiting := func(i int) bool { return tabs[i] != nil && !out[i].Done && !out[i].Closed }
	pending := func() (auto, manual int) {
		for i, it := range items {
			switch {
			case !waiting(i):
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
			if !waiting(i) || it.Page.Done == nil {
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

func progress(items []item, out []outcome) (done, total int) {
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

// reruns are the targets of page items to run once waiting is over, except one already run early
// (early holds when) with no page done after that run started.
func reruns(items []item, out []outcome, early map[string]time.Time) []string {
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
