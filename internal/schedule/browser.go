package schedule

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/statefile"
)

// browserSelected are the selectors ("name" or "name:label") of connectors that drive the
// browser over CDP.
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
// "" otherwise. It stays due until browserNotified says it was sent.
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

// browserNotified records that the staleness notification was sent.
func (e Env) browserNotified() {
	s := e.loadBrowserState()
	s.Notified = true
	e.saveBrowserState(s)
}
