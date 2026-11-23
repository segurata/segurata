package remediate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
)

// ErrNotTTY is returned when confirmation would be needed but nobody can answer it.
var ErrNotTTY = errors.New("stdin is not a terminal, so nobody can confirm: refusing to apply (pass --yes to apply without asking)")

// ErrStillPresent means the remediation ran but the connector still reports the finding.
var ErrStillPresent = errors.New("the finding is still reported after applying the remediation")

// Selector is the connector instance that produced f, spelled as on the command line.
func Selector(f finding.Finding) string {
	if f.Instance == "" {
		return f.Connector
	}
	return f.Connector + ":" + f.Instance
}

// For returns what can remediate f: the core for generic file actions, otherwise its connector.
func For(f finding.Finding, conns []connector.Connector) (connector.Remediator, error) {
	if f.Remediation.Action == "" {
		return nil, fmt.Errorf("finding %s has no automatable remediation: %s", f.ID, f.Remediation.Summary)
	}
	if (Files{}).Handles(f.Remediation.Action) {
		return Files{}, nil
	}
	for _, c := range conns {
		if c.Describe().Name != f.Connector {
			continue
		}
		if r, ok := c.(connector.Remediator); ok {
			return r, nil
		}
		return nil, fmt.Errorf("connector %s cannot remediate (external connectors cannot yet)", f.Connector)
	}
	return nil, fmt.Errorf("connector %s is not installed", f.Connector)
}

// Options are the command-line choices of one remediate run.
type Options struct {
	Apply bool // without it the run is a dry run
	Yes   bool // skip the confirmation prompt
	TTY   bool // stdin is a terminal
	IO    connector.IO
}

// Reinventory runs the finding's connector again, read-only, to check the result.
type Reinventory func(ctx context.Context) ([]*run.Result, error)

// Execute shows the plan for f and, only with --apply and a confirmation, applies it and checks
// that the finding is gone.
func Execute(ctx context.Context, f finding.Finding, r connector.Remediator, opt Options, reinventory Reinventory) error {
	p, err := r.Plan(ctx, f)
	if err != nil {
		return err
	}
	Print(opt.IO.Out, f, p)
	if !opt.Apply {
		fmt.Fprintln(opt.IO.Out, "\nDry run: nothing was changed. Run again with --apply to apply this plan.")
		return nil
	}
	ok, err := confirm(opt)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(opt.IO.Out, "Not applied.")
		return nil
	}
	if err := r.Apply(ctx, f, p, opt.IO); err != nil {
		return fmt.Errorf("apply %s: %w", p.Action, err)
	}
	fmt.Fprintf(opt.IO.Out, "Applied %s. Checking with a fresh %s inventory...\n", p.Action, Selector(f))
	results, err := reinventory(ctx)
	if err != nil {
		return fmt.Errorf("applied, but the check could not run: %w", err)
	}
	present, err := StillPresent(results, f.ID)
	if err != nil {
		return fmt.Errorf("applied, but the check failed: %w", err)
	}
	if present {
		return ErrStillPresent
	}
	fmt.Fprintf(opt.IO.Out, "Fixed: %s no longer reports finding %s.\n", Selector(f), f.ID)
	return nil
}

func confirm(opt Options) (bool, error) {
	if opt.Yes {
		return true, nil
	}
	if !opt.TTY {
		return false, ErrNotTTY
	}
	fmt.Fprint(opt.IO.Out, "\nApply? [y/N] ")
	line, err := bufio.NewReader(opt.IO.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// StillPresent reports whether a fresh run still emits the finding. A run that could not start is
// an error, not a pass.
func StillPresent(results []*run.Result, id string) (bool, error) {
	if len(results) == 0 {
		return false, errors.New("no connector ran")
	}
	for _, r := range results {
		if r.Err != nil {
			return false, fmt.Errorf("%s: %w", r.Name, r.Err)
		}
		for _, f := range r.Findings {
			if f.ID == id {
				return true, nil
			}
		}
	}
	return false, nil
}

// Print shows the exact scope of a plan.
func Print(w io.Writer, f finding.Finding, p connector.Plan) {
	fmt.Fprintf(w, "Finding  %s [%s] %s · %s · %s\n", f.ID, f.Severity, Selector(f), f.Account, f.Title)
	fmt.Fprintf(w, "Action   %s\n", p.Action)
	fmt.Fprintf(w, "Plan     %s\n", p.Summary)
	runs := "Runs, as you:"
	if p.NeedsSudo() {
		runs = "Runs (sudo asks for your password on this terminal; securizame never sees it):"
	}
	printSection(w, runs, "", p.Commands)
	printSection(w, "Changes:", "", p.Files)
	printSection(w, "Side effects:", "- ", p.SideEffects)
	printSection(w, "Undo:", "", p.Undo)
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

// List prints the automatable findings of a run, one per line.
func List(w io.Writer, all []finding.Finding) {
	auto := Automatable(all)
	for _, f := range auto {
		fmt.Fprintf(w, "%s  [%-8s] %-32s %-16s %s\n", f.ID, f.Severity, f.Remediation.Action, Selector(f), f.Title)
	}
	fmt.Fprintf(w, "\n%d automatable findings. Show a plan with: securizame remediate <id>\n", len(auto))
}
