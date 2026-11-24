// Package remediate is the core of `segurata remediate`: it shows the exact plan for a finding,
// asks for confirmation, applies only the plan that was confirmed and checks afterwards that the
// finding is gone. See docs/architecture.md, "Remediation".
package remediate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/run"
)

// ErrStillPresent means the remediation ran but the connector still reports the finding.
var ErrStillPresent = errors.New("the finding is still reported after applying the remediation")

// ErrUnverified means the remediation ran but the check run did not inspect the finding's scope
// (it stopped early, or skipped that account or repository), so its absence proves nothing.
var ErrUnverified = errors.New("could not verify the fix")

// CredentialsFunc builds the credentials of the connector instance that produced a finding: its
// request (config and resolved secrets) and its unresolved remediation_secrets. External connectors
// and built-ins that implement connector.CredentialedRemediator need it; nothing else calls it.
type CredentialsFunc func(f finding.Finding) (connector.Credentials, error)

// For returns what can remediate f: the core for generic file actions, otherwise its connector. A
// built-in connector implements connector.Remediator (and gets the instance's credentials when it
// implements connector.CredentialedRemediator); an external one must declare the action in
// describe's "remediates", and is wrapped in External with the request from creds.
func For(f finding.Finding, conns []connector.Connector, creds CredentialsFunc) (connector.Remediator, error) {
	action := f.Remediation.Action
	if action == "" {
		return nil, fmt.Errorf("finding %s has no automatable remediation: %s", f.ID, f.Remediation.Summary)
	}
	if (Files{}).Handles(action) {
		return Files{}, nil
	}
	for _, c := range conns {
		if c.Describe().Name != f.Connector {
			continue
		}
		if cr, ok := c.(connector.CredentialedRemediator); ok {
			if creds == nil {
				return nil, errors.New("no credentials for the connector's instance")
			}
			cs, err := creds(f)
			if err != nil {
				return nil, err
			}
			return cr.WithCredentials(cs), nil
		}
		if r, ok := c.(connector.Remediator); ok {
			return r, nil
		}
		e, ok := c.(*connector.External)
		if !ok {
			return nil, fmt.Errorf("connector %s cannot remediate", f.Connector)
		}
		if !slices.Contains(e.Describe().Remediates, action) {
			return nil, fmt.Errorf("external connector %s does not declare the remediation %s in describe (\"remediates\")", f.Connector, action)
		}
		if creds == nil {
			return nil, errors.New("no request for the external connector's instance")
		}
		cs, err := creds(f)
		if err != nil {
			return nil, err
		}
		return External{Conn: e, Req: cs.Request}, nil
	}
	return nil, fmt.Errorf("connector %s is not installed", f.Connector)
}

// Options are the command-line choices of one remediate run.
type Options struct {
	Apply bool // without it the run is a dry run
	Yes   bool // skip the confirmation prompt
	TTY   bool // stdin is a terminal
	IO    connector.IO
	// Sleep waits between checks; nil means time.Sleep.
	Sleep func(time.Duration)
	// Group is every finding one plan fixes with the target, the target included (see Members).
	// Empty means the target alone.
	Group []finding.Finding
}

// ErrNeedsTerminal refuses a plan with an interactive step when nobody is at the terminal.
var ErrNeedsTerminal = errors.New("this plan runs an interactive command (a browser sign-in or a prompt) and stdin is not a terminal: run it from a terminal")

// Members is the group of findings one plan fixes with target: every finding of the same connector
// instance with the same action and Remediation.Group, target first, accepted ones left out. A
// finding without a group is its own group.
func Members(all []finding.Finding, target finding.Finding) []finding.Finding {
	out := []finding.Finding{target}
	if target.Remediation.Group == "" {
		return out
	}
	for _, f := range all {
		if f.ID != target.ID && !f.Hidden() && sameGroup(f, target) {
			out = append(out, f)
		}
	}
	return out
}

func sameGroup(a, b finding.Finding) bool {
	return a.Connector == b.Connector && a.Instance == b.Instance &&
		a.Remediation.Action == b.Remediation.Action && a.Remediation.Group == b.Remediation.Group
}

// planner adapts a Remediator to a group: a GroupRemediator plans the whole group, any other
// remediator only a group of one.
type planner struct {
	r     connector.Remediator
	group []finding.Finding
}

func (p planner) plan(ctx context.Context) (connector.Plan, error) {
	if g, ok := p.r.(connector.GroupRemediator); ok {
		return g.PlanGroup(ctx, p.group)
	}
	if len(p.group) != 1 {
		return connector.Plan{}, fmt.Errorf("%s fixes one finding at a time, but %d share its group", p.group[0].Remediation.Action, len(p.group))
	}
	return p.r.Plan(ctx, p.group[0])
}

// apply carries out confirmed, the plan the owner saw and agreed to, and only that plan: it asks the
// remediator for the plan again, from the state as it is now, and refuses when the two differ. A
// remediator therefore never acts on a stale or altered plan, and none needs a guard of its own.
func (p planner) apply(ctx context.Context, confirmed connector.Plan, io connector.IO) error {
	now, err := p.plan(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(now, confirmed) {
		return errors.New("the plan changed since it was shown: run remediate again to see the current one")
	}
	if g, ok := p.r.(connector.GroupRemediator); ok {
		return g.ApplyGroup(ctx, p.group, confirmed, io)
	}
	return p.r.Apply(ctx, p.group[0], confirmed, io)
}

// A fix often takes a moment to settle: a restarted process can drop its ports for a second and
// open them again. So the check waits first, then requires the finding to be absent in several
// consecutive inventories. Verified 2026-11-23: an AirPlay Receiver change looked fixed on an
// immediate check while ControlCenter restarted, and the ports were back seconds later.
var defaultSleep = time.Sleep

const (
	settleWait   = 5 * time.Second
	settleChecks = 2
)

// Reinventory runs the finding's connector again, read-only, to check the result.
type Reinventory func(ctx context.Context) ([]*run.Result, error)

// Execute shows the plan for f and, only with --apply and a confirmation, applies it and checks
// that the finding is gone.
func Execute(ctx context.Context, f finding.Finding, r connector.Remediator, opt Options, reinventory Reinventory) error {
	group := opt.Group
	if len(group) == 0 {
		group = []finding.Finding{f}
	}
	pl := planner{r: r, group: group}
	p, err := pl.plan(ctx)
	if err != nil {
		return err
	}
	Print(opt.IO.Out, f, p)
	printSection(opt.IO.Out, fmt.Sprintf("Fixes these %d findings:", len(group)), "", groupLines(group))
	if !opt.Apply {
		fmt.Fprintln(opt.IO.Out, "\nDry run: nothing was changed. Run again with --apply to apply this plan.")
		return nil
	}
	if p.Blocked != "" {
		return fmt.Errorf("cannot apply yet: %s", p.Blocked)
	}
	if p.NeedsTerminal() && !opt.TTY {
		return ErrNeedsTerminal
	}
	ok, err := prompt.Confirm(opt.IO.In, opt.IO.Out, opt.Yes, opt.TTY)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(opt.IO.Out, "Not applied.")
		return nil
	}
	if err := pl.apply(ctx, p, opt.IO); err != nil {
		return fmt.Errorf("apply %s: %w", p.Action, err)
	}
	sleep := opt.Sleep
	if sleep == nil {
		sleep = defaultSleep
	}
	fmt.Fprintf(opt.IO.Out, "Applied %s. Checking %d times with a fresh %s inventory, %s apart...\n",
		p.Action, settleChecks, f.Selector(), settleWait)
	for i := 0; i < settleChecks; i++ {
		sleep(settleWait)
		results, err := reinventory(ctx)
		if err != nil {
			return fmt.Errorf("applied, but the check could not run: %w", err)
		}
		present, err := StillPresent(results, group...)
		if errors.Is(err, ErrUnverified) {
			return fmt.Errorf("applied, but %w", err)
		}
		if err != nil {
			return fmt.Errorf("applied, but the check failed: %w", err)
		}
		if present {
			return ErrStillPresent
		}
	}
	if len(group) == 1 {
		fmt.Fprintf(opt.IO.Out, "Fixed: %s no longer reports finding %s.\n", f.Selector(), f.ID)
	} else {
		fmt.Fprintf(opt.IO.Out, "Fixed: %s no longer reports any of the %d findings.\n", f.Selector(), len(group))
	}
	return nil
}

// groupLines names each finding of a group of more than one; a group of one is the Finding line.
func groupLines(group []finding.Finding) []string {
	if len(group) < 2 {
		return nil
	}
	out := make([]string, len(group))
	for i, g := range group {
		out[i] = fmt.Sprintf("%s [%s] %s", g.ID, g.Severity, g.Title)
	}
	return out
}

// StillPresent reports whether a fresh run still needs the remediation of any target: it emits a
// finding with the target's id that still offers the target's action. The same finding without
// that action (a repository whose other problems remain, a grant with fewer scopes) is fixed as far
// as this action goes. A run that could not start is an error, not a pass; one that did not
// inspect a target's scope is ErrUnverified.
func StillPresent(results []*run.Result, targets ...finding.Finding) (bool, error) {
	if len(results) == 0 {
		return false, errors.New("no connector ran")
	}
	want := map[string]string{}
	for _, t := range targets {
		want[t.ID] = t.Remediation.Action
	}
	for _, r := range results {
		if r.Err != nil {
			return false, fmt.Errorf("%s: %w", r.Name, r.Err)
		}
		for _, f := range r.Findings {
			if action, ok := want[f.ID]; ok && f.Remediation.Action == action {
				return true, nil
			}
		}
	}
	for _, r := range results {
		end := r.End
		for _, t := range targets {
			if why, unchecked := finding.CoverageOf(&end).UncheckedFinding(t); unchecked {
				return false, fmt.Errorf("%w: %s", ErrUnverified, why)
			}
		}
	}
	return false, nil
}

// Print shows the exact scope of a plan.
func Print(w io.Writer, f finding.Finding, p connector.Plan) {
	fmt.Fprintf(w, "Finding  %s [%s] %s · %s · %s\n", f.ID, f.Severity, f.Selector(), f.Account, f.Title)
	fmt.Fprintf(w, "Action   %s\n", p.Action)
	fmt.Fprintf(w, "Plan     %s\n", p.Summary)
	runs := "Runs, as you:"
	switch {
	case p.NeedsSudo():
		runs = "Runs (sudo asks for your password on this terminal; segurata never sees it):"
	case p.NeedsTerminal():
		runs = "Runs in your terminal, as you (it is interactive: follow its prompts):"
	}
	printSection(w, runs, "", p.Commands)
	printSection(w, "Requests, sent by segurata:", "", p.Calls)
	printSection(w, "Changes:", "", p.Files)
	printSection(w, "Side effects:", "- ", p.SideEffects)
	printSection(w, "Undo:", "", p.Undo)
	if p.Blocked != "" {
		printSection(w, "Blocked, --apply refuses until then:", "", []string{p.Blocked})
	}
}

// printSection prints a titled, indented list, or nothing when the list is empty.
func printSection[T any](w io.Writer, title, bullet string, items []T) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintln(w, "\n"+title)
	for _, it := range items {
		fmt.Fprintf(w, "  %s%v\n", bullet, it)
	}
}

// List prints the automatable findings whose action ranks at or above minSev, worst first, leaving
// out accepted ones. A group of findings one plan fixes (Remediation.Group) is one line, under the
// id of its worst member, ranked by that member.
func List(w io.Writer, all []finding.Finding, minSev finding.Severity) {
	shown, accepted, below := 0, 0, 0
	var visible []finding.Finding
	for _, f := range all {
		if f.Remediation.Action == "" {
			continue
		}
		if f.Hidden() {
			accepted++
			continue
		}
		visible = append(visible, f)
	}
	sort.SliceStable(visible, func(i, j int) bool {
		return visible[i].ActionSeverity().Rank() > visible[j].ActionSeverity().Rank()
	})
	listed := map[string]bool{} // groups already printed
	for _, f := range visible {
		key := ""
		if g := f.Remediation.Group; g != "" {
			key = strings.Join([]string{f.Connector, f.Instance, f.Remediation.Action, g}, "\x00")
			if listed[key] {
				continue
			}
			listed[key] = true
		}
		sev := f.ActionSeverity()
		if sev.Rank() < minSev.Rank() {
			below++
			continue
		}
		shown++
		title := f.DisplayTitle()
		if key != "" {
			if n := len(Members(visible, f)); n > 1 {
				title = fmt.Sprintf("%d findings of %s (first: %s)", n, f.Remediation.Group, title)
			}
		}
		fmt.Fprintf(w, "%s  [%-8s] %-32s %-16s %s\n", f.ID, sev, f.Remediation.Action, f.Selector(), title)
	}
	fmt.Fprintf(w, "\n%d automatable findings or groups. Show a plan with: segurata remediate <id>\n", shown)
	if below > 0 {
		fmt.Fprintf(w, "%d more below %s (show them with --all).\n", below, minSev)
	}
	if note := finding.HiddenNote(accepted); note != "" {
		fmt.Fprintln(w, note)
	}
}
