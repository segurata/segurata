package schedule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/statefile"
)

// browserProbeTimeout bounds the check that Brave answers over CDP before a run includes the
// browser connectors.
const browserProbeTimeout = 15 * time.Second

// Reasons a run skips the browser connectors, written as their run_end error.
const (
	reasonUnreachable = "browser not reachable over CDP"
	reasonNotBrave    = "the browser on the debugging port is not Brave"
)

// splitBrowser separates the selectors ("name" or "name:label") of connectors that drive the
// browser over CDP from the rest. A selector naming no installed connector goes with the rest, for
// the inventory to refuse.
func (e Env) splitBrowser(selectors []string) (browser, rest []string) {
	cdpNames := map[string]bool{}
	for _, c := range e.Connectors {
		if d := c.Describe(); d.NeedsCDP() {
			cdpNames[d.Name] = true
		}
	}
	for _, sel := range selectors {
		name, _, _ := strings.Cut(sel, ":")
		if cdpNames[name] {
			browser = append(browser, sel)
		} else {
			rest = append(rest, sel)
		}
	}
	return browser, rest
}

// probeBrowser says why the browser connectors cannot run now, "" when Brave answers at cdp_url.
// Only Brave is driven: another browser on the port, or none, skips them, and nothing is ever
// started in its place.
func (e Env) probeBrowser(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, browserProbeTimeout)
	defer cancel()
	_, err := e.Browser(ctx, e.Config.CDPURL)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, cdp.ErrNotBrave):
		e.stamp(reasonNotBrave + ": " + err.Error())
		return reasonNotBrave
	}
	e.stamp(reasonUnreachable + ": " + err.Error())
	return reasonUnreachable
}

// skippedConnector stands in for a browser connector a run could not reach: its run ends at once
// with the reason as its error, so its run_end skips every scope ("*") and, failed, proves neither a
// finding nor a status gone. The tracker keeps every item of it; the report lists it as partial.
type skippedConnector struct {
	connector.Connector
	reason string
}

func (s skippedConnector) Inventory(context.Context, connector.Request, connector.Emitter) error {
	return errors.New(s.reason)
}

// recordSkipped writes a run file for every instance the selectors pick, through run.Inventory, as
// a run that inspected nothing for reason. Secrets are not resolved: nothing runs.
func (e Env) recordSkipped(ctx context.Context, selectors []string, reason string) {
	targets, err := run.Targets(e.Config, e.Connectors, selectors)
	if err != nil {
		fmt.Fprintf(e.IO.Err, "recording the skipped browser connectors: %v\n", err)
		return
	}
	for i := range targets {
		targets[i].Connector = skippedConnector{targets[i].Connector, reason}
		targets[i].Instance.Secrets = nil
	}
	results, err := run.Inventory(ctx, e.Config, targets, e.Paths().Out, nil, nil)
	if err != nil {
		fmt.Fprintf(e.IO.Err, "recording the skipped browser connectors: %v\n", err)
		return
	}
	for _, r := range results {
		if _, err := os.Stat(r.File); err != nil {
			fmt.Fprintf(e.IO.Err, "recording the skipped run of %s: %v\n", r.Name, r.Err)
		}
	}
}

// browserState is what scheduled runs remember about the browser connectors, in
// Paths.BrowserState.
type browserState struct {
	// NotRunSince is when the browser connectors last ran on schedule or, if they have not since
	// the file exists, when a run first skipped them.
	NotRunSince time.Time `json:"not_run_since"`
	// Notified is set once the owner was told they have not run in a while; a run that includes
	// them clears it.
	Notified bool `json:"notified,omitempty"`
}

func (e Env) loadBrowserState() browserState {
	var s browserState
	raw, err := os.ReadFile(e.Paths().BrowserState)
	if err == nil {
		err = json.Unmarshal(raw, &s)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(e.IO.Err, "reading %s: %v\n", e.Paths().BrowserState, err)
	}
	return s
}

func (e Env) saveBrowserState(s browserState) {
	if err := statefile.WriteJSON(e.Paths().BrowserState, s); err != nil {
		fmt.Fprintf(e.IO.Err, "writing %s: %v\n", e.Paths().BrowserState, err)
	}
}

// browserRan records that a run included the browser connectors.
func (e Env) browserRan(now time.Time) {
	e.saveBrowserState(browserState{NotRunSince: now.UTC()})
}

// browserSkipped records that a run skipped the browser connectors and returns the text of the
// one notification due when they have not run for longer than the config's browser_stale_days,
// "" otherwise.
func (e Env) browserSkipped(now time.Time) string {
	s := e.loadBrowserState()
	if s.NotRunSince.IsZero() {
		s.NotRunSince = now.UTC()
	}
	stale, idle := e.Config.BrowserStaleAfter(), now.Sub(s.NotRunSince)
	due := stale > 0 && idle > stale && !s.Notified
	if due {
		s.Notified = true
	}
	e.saveBrowserState(s)
	if !due {
		return ""
	}
	return fmt.Sprintf("browser connectors haven't run in %d days", int(idle/(24*time.Hour)))
}
