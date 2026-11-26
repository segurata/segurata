package schedule

import (
	"fmt"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/statefile"
)

// browserSelected are the selectors of connectors that drive the browser.
func (e Env) browserSelected(selectors []string) []string {
	cdpNames := map[string]bool{}
	for _, c := range e.Connectors {
		if d := c.Describe(); d.NeedsCDP() {
			cdpNames[d.Name] = true
		}
	}
	var out []string
	for _, sel := range selectors {
		if name, _, _ := strings.Cut(sel, ":"); cdpNames[name] {
			out = append(out, sel)
		}
	}
	return out
}

// browserState is what scheduled runs remember about the browser connectors.
type browserState struct {
	// NotRunSince is when they last ran, or when a run first skipped them.
	NotRunSince time.Time `json:"not_run_since"`
	Notified    bool      `json:"notified,omitempty"` // cleared by a run that includes them
}

func (e Env) loadBrowserState() browserState {
	var s browserState
	path := e.Paths().BrowserState
	if _, err := statefile.ReadJSON(path, &s); err != nil {
		fmt.Fprintf(e.IO.Err, "reading %s: %v\n", path, err)
	}
	return s
}

func (e Env) saveBrowserState(s browserState) {
	path := e.Paths().BrowserState
	if err := statefile.WriteJSON(path, s); err != nil {
		fmt.Fprintf(e.IO.Err, "writing %s: %v\n", path, err)
	}
}

func (e Env) browserRan(now time.Time) {
	e.saveBrowserState(browserState{NotRunSince: now.UTC()})
}

// browserSkipped records a skip and returns the notification due once the browser connectors have
// not run for longer than browser_stale_days, "" otherwise; it stays due until browserNotified.
func (e Env) browserSkipped(now time.Time) string {
	s := e.loadBrowserState()
	if s.NotRunSince.IsZero() {
		s.NotRunSince = now.UTC()
		e.saveBrowserState(s)
	}
	stale, idle := e.Config.BrowserStaleAfter(), now.Sub(s.NotRunSince)
	if stale <= 0 || idle <= stale || s.Notified {
		return ""
	}
	return fmt.Sprintf("browser connectors haven't run in %d days", int(idle/(24*time.Hour)))
}

func (e Env) browserNotified() {
	s := e.loadBrowserState()
	s.Notified = true
	e.saveBrowserState(s)
}
