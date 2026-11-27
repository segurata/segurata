// Package posture reports the outcome of a device's posture checks, the shared shape of the macos
// and windows connectors: a failing check is one setting finding, a passing one a log line, and a
// check that could not run a status for its own scope only.
package posture

import (
	"fmt"
	"maps"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Check is one posture check's outcome. A passing check is logged, not emitted: a finding's
// disappearance is how remediate confirms a fix.
type Check struct {
	ID        string
	Area      string // shared scope of checks one failure skips together; defaults to ID
	Resource  string // the Reporter's Setting type when empty
	Name      string
	OK        bool
	Skip      string        // why the check could not run
	SkipState finding.State // "" is unsupported; error when the tool failed
	Sev       finding.Severity
	Blast     finding.Blast
	Title     string
	Detail    string
	Evidence  map[string]any
	Rem       finding.Remediation
}

func (ch Check) Scope() string {
	if ch.Area != "" {
		return "check:" + ch.Area
	}
	return "check:" + ch.ID
}

// InArea puts every check in one shared scope.
func InArea(area string, chs []Check) []Check {
	for i := range chs {
		chs[i].Area = area
	}
	return chs
}

// Manual is a remediation done by hand.
func Manual(summary string) finding.Remediation { return finding.Remediation{Summary: summary} }

// Reporter emits checks for one device, Host.
type Reporter struct {
	Host    string
	Emit    connector.Emitter
	Setting string // the resource type of a check that names none, such as "macos_setting"
	skipped []Check
}

func (r *Reporter) ReportAll(chs []Check) {
	for _, ch := range chs {
		r.Report(ch)
	}
}

func (r *Reporter) Report(ch Check) {
	switch {
	case ch.Skip != "":
		r.skipped = append(r.skipped, ch)
		return
	case ch.OK:
		r.Emit.Log(fmt.Sprintf("OK %s: %s", ch.ID, ch.Detail))
		return
	}
	ev := map[string]any{"check": ch.ID, "detail": ch.Detail}
	maps.Copy(ev, ch.Evidence)
	typ, name := ch.Resource, ch.Name
	if typ == "" {
		typ = r.Setting
	}
	if name == "" {
		name = ch.ID
	}
	r.Emit.Finding(finding.Finding{
		Account:     r.Host,
		Scope:       ch.Scope(),
		Resource:    finding.Resource{Type: typ, ID: ch.ID, Name: name},
		Kind:        finding.KindSetting,
		Severity:    ch.Sev,
		Blast:       ch.Blast,
		Title:       ch.Title,
		Evidence:    ev,
		Remediation: ch.Rem,
	})
}

// Finish says the device was inspected, except the scope of each check that could not run.
func (r *Reporter) Finish() {
	r.Emit.Status(finding.Status{Account: r.Host, State: finding.StateOK})
	for _, ch := range r.skipped {
		state := ch.SkipState
		if state == "" {
			state = finding.StateUnsupported
		}
		r.Emit.Status(finding.Status{Account: r.Host, Scope: ch.Scope(), State: state, Detail: ch.ID + ": " + ch.Skip})
	}
}
