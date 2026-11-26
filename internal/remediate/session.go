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
	"github.com/segurata/segurata/internal/textfmt"
)

// CredentialsFunc builds the credentials of the connector instance that produced a finding.
type CredentialsFunc func(f finding.Finding) (connector.Credentials, error)

// For returns what can remediate f: the core for generic file actions, otherwise its connector. An
// external connector must declare the action in describe's "remediates".
func For(f finding.Finding, conns []connector.Connector, creds CredentialsFunc) (connector.Remediator, error) {
	action := f.Remediation.Action
	if action == "" {
		return nil, fmt.Errorf("finding %s has no automatable remediation: %s", f.ID, f.Remediation.Summary)
	}
	if action == connector.ActionChmod600 {
		return files{}, nil
	}
	credentials := func() (connector.Credentials, error) {
		if creds == nil {
			return connector.Credentials{}, errors.New("no credentials for the connector's instance")
		}
		return creds(f)
	}
	for _, c := range conns {
		if c.Describe().Name != f.Connector {
			continue
		}
		switch c := c.(type) {
		case connector.CredentialedRemediator:
			cs, err := credentials()
			if err != nil {
				return nil, err
			}
			return c.WithCredentials(cs), nil
		case connector.Remediator:
			return c, nil
		case *connector.External:
			if !slices.Contains(c.Describe().Remediates, action) {
				return nil, fmt.Errorf("external connector %s does not declare the remediation %s in describe (\"remediates\")", f.Connector, action)
			}
			cs, err := credentials()
			if err != nil {
				return nil, err
			}
			return external{conn: c, req: cs.Request}, nil
		}
		return nil, fmt.Errorf("connector %s cannot remediate", f.Connector)
	}
	return nil, fmt.Errorf("connector %s is not installed", f.Connector)
}

// Options are the command-line choices of one remediate run.
type Options struct {
	Apply bool // without it the run is a dry run
	Yes   bool // skip the confirmation prompt
	TTY   bool // stdin is a terminal
	IO    connector.IO
	// Group is every finding one plan fixes with the target, the target included (see Members).
	// Empty means the target alone.
	Group []finding.Finding
}

var (
	errStillPresent  = errors.New("the finding is still reported after applying the remediation")
	errUnverified    = errors.New("could not verify the fix")
	errNeedsTerminal = errors.New("this plan runs an interactive command (a browser sign-in or a prompt) and stdin is not a terminal: run it from a terminal")
)

// Members is the group of findings one plan fixes with target: every finding of the same connector
// instance with the same action and Remediation.Group, target first, accepted ones left out.
func Members(all []finding.Finding, target finding.Finding) []finding.Finding {
	out := []finding.Finding{target}
	if target.Remediation.Group == "" {
		return out
	}
	for _, f := range all {
		if f.ID != target.ID && !f.Hidden() && groupKey(f) == groupKey(target) {
			out = append(out, f)
		}
	}
	return out
}

func groupKey(f finding.Finding) string {
	return strings.Join([]string{f.Connector, f.Instance, f.Remediation.Action, f.Remediation.Group}, "\x00")
}

// planner adapts a Remediator to a group: only a GroupRemediator plans more than one finding.
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

// apply plans again from the current state and refuses when that differs from the confirmed plan,
// so no remediator needs a stale-plan guard of its own.
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

// A fix can take a moment to settle, so the check waits and needs several clean inventories.
// Verified 2026-11-23: an AirPlay Receiver change looked fixed on an immediate check while
// ControlCenter restarted, and the ports were back seconds later.
var sleep = time.Sleep

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
	printPlan(opt.IO.Out, f, p)
	printSection(opt.IO.Out, fmt.Sprintf("Fixes these %d findings:", len(group)), "", groupLines(group))
	if !opt.Apply {
		fmt.Fprintln(opt.IO.Out, "\nDry run: nothing was changed. Run again with --apply to apply this plan.")
		return nil
	}
	if p.Blocked != "" {
		return fmt.Errorf("cannot apply yet: %s", p.Blocked)
	}
	if p.NeedsTerminal() && !opt.TTY {
		return errNeedsTerminal
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
	fmt.Fprintf(opt.IO.Out, "Applied %s. Checking %d times with a fresh %s inventory, %s apart...\n",
		p.Action, settleChecks, f.Selector(), settleWait)
	for range settleChecks {
		sleep(settleWait)
		results, err := reinventory(ctx)
		if err != nil {
			return fmt.Errorf("applied, but the check could not run: %w", err)
		}
		present, err := stillPresent(results, group...)
		if errors.Is(err, errUnverified) {
			return fmt.Errorf("applied, but %w", err)
		}
		if err != nil {
			return fmt.Errorf("applied, but the check failed: %w", err)
		}
		if present {
			return errStillPresent
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

// stillPresent reports whether a fresh run still offers any target's action under the target's id.
// The same finding without that action (a grant with fewer scopes) is fixed as far as this action
// goes. A run that could not start is an error, not a pass: its silence proves nothing. One that did
// not inspect a target's scope is errUnverified.
func stillPresent(results []*run.Result, targets ...finding.Finding) (bool, error) {
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
				return false, fmt.Errorf("%w: %s", errUnverified, why)
			}
		}
	}
	return false, nil
}

func printPlan(w io.Writer, f finding.Finding, p connector.Plan) {
	textfmt.Line(w, "Finding  %s [%s] %s · %s · %s", f.ID, f.Severity, f.Selector(), f.Account, f.Title)
	textfmt.Line(w, "Action   %s", p.Action)
	textfmt.Line(w, "Plan     %s", p.Summary)
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

func printSection[T any](w io.Writer, title, bullet string, items []T) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintln(w, "\n"+title)
	for _, it := range items {
		textfmt.Line(w, "  %s%v", bullet, it)
	}
}

// List prints the automatable findings whose action ranks at or above minSev, worst first, leaving
// out accepted ones. A group (Remediation.Group) is one line under its worst member.
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
	listed := map[string]bool{}
	for _, f := range visible {
		grouped := f.Remediation.Group != ""
		if grouped {
			if listed[groupKey(f)] {
				continue
			}
			listed[groupKey(f)] = true
		}
		sev := f.ActionSeverity()
		if sev.Rank() < minSev.Rank() {
			below++
			continue
		}
		shown++
		title := f.DisplayTitle()
		if n := len(Members(visible, f)); grouped && n > 1 {
			title = fmt.Sprintf("%d findings of %s (first: %s)", n, f.Remediation.Group, title)
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
