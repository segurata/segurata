package schedule

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

var confirmFunc = remediate.Confirm

// DefaultConnectors are the connectors a scheduled run selects when none are named: all of them
// except those that drive the browser over CDP, since the browser is rarely running with its
// debugging port open when the agent fires.
func (e Env) DefaultConnectors() []string {
	var out []string
	for _, c := range e.Connectors {
		if d := c.Describe(); !d.NeedsCDP() {
			out = append(out, d.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Run is one scheduled run, what the agent executes: `segurata inventory` over the selected
// connectors, a notification for high and critical findings that were not in the previous run,
// then `segurata report --format md`. Both commands are this same binary, run as separate
// processes so a scheduled run does exactly what the owner would type.
//
// The run ends before the next one is due, and the inventory early enough to leave time for the
// report: launchd starts no run while one is still going, so one that hung would stop scheduled
// scanning without a word.
func (e Env) Run(ctx context.Context, o Options) error {
	every, err := o.every()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, every*9/10)
	defer cancel()
	invCtx, cancelInv := context.WithTimeout(ctx, every*8/10)
	defer cancelInv()
	p := e.Paths()
	if err := os.MkdirAll(p.Out, 0o700); err != nil {
		return err
	}
	connectors := o.Connectors
	if len(connectors) == 0 {
		connectors = e.DefaultConnectors()
	}
	// The snapshot before is only what notifications compare with: a run file it cannot read must
	// not stop the inventory that writes the file replacing it.
	before, err := e.serious(p.Out)
	if err != nil {
		fmt.Fprintf(e.IO.Err, "previous findings unreadable, every high or critical finding counts as new: %v\n", err)
		before = map[string]finding.Finding{}
	}
	stamp := func(msg string) { fmt.Fprintf(e.IO.Out, "%s %s\n", e.Now().Format("2006-01-02 15:04:05"), msg) }
	stamp("inventory " + strings.Join(connectors, " "))
	inv := append([]string{"inventory", "--out", p.Out}, connectors...)
	if err := e.Runner.Run(invCtx, e.Exe, inv, e.IO.Out, e.IO.Err); err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	after, err := e.serious(p.Out)
	if err != nil {
		return err
	}
	var fresh []finding.Finding
	for id, f := range after {
		if _, seen := before[id]; !seen {
			fresh = append(fresh, f)
		}
	}
	sort.Slice(fresh, func(i, j int) bool {
		if a, b := fresh[i].Severity.Rank(), fresh[j].Severity.Rank(); a != b {
			return a > b
		}
		return fresh[i].ID < fresh[j].ID
	})
	if len(fresh) > 0 {
		stamp(fmt.Sprintf("%d new high or critical findings", len(fresh)))
		for _, f := range fresh {
			fmt.Fprintf(e.IO.Out, "  [%s] %s %s\n", f.Severity, remediate.Selector(f), f.Title)
		}
		if e.GOOS == "darwin" {
			if err := e.Runner.Run(ctx, osascript, []string{"-e", notification(fresh)}, e.IO.Out, e.IO.Err); err != nil {
				fmt.Fprintf(e.IO.Err, "notification failed: %v\n", err)
			}
		}
	}
	stamp("report " + p.Report)
	rep := []string{"report", "--format", "md", "--out", p.Report, "--dir", p.Out}
	if err := e.Runner.Run(ctx, e.Exe, rep, e.IO.Out, e.IO.Err); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	e.prune(p.Out)
	return nil
}

// prune removes run files older than Keep that no latest run needs (remediate.Prune). A failure is
// logged: the scan itself succeeded.
func (e Env) prune(outDir string) {
	if e.Keep <= 0 {
		return
	}
	removed, err := remediate.Prune(outDir, e.Now().Add(-e.Keep))
	if len(removed) > 0 {
		fmt.Fprintf(e.IO.Out, "%s pruned %d run files older than %s\n", e.Now().Format("2006-01-02 15:04:05"), len(removed), e.Keep)
	}
	if err != nil {
		fmt.Fprintf(e.IO.Err, "pruning %s: %v\n", outDir, err)
	}
}

// serious returns the high and critical findings of the latest run of each connector, leaving out
// accepted ones. No run yet means none.
func (e Env) serious(outDir string) (map[string]finding.Finding, error) {
	files, err := remediate.LatestFiles(outDir)
	if err != nil {
		return map[string]finding.Finding{}, nil // nothing inventoried yet
	}
	all, err := remediate.Load(files)
	if err != nil {
		return nil, err
	}
	out := map[string]finding.Finding{}
	for _, f := range all {
		if f.Severity.Rank() >= finding.SevHigh.Rank() && !f.Hidden() {
			out[f.ID] = f
		}
	}
	return out, nil
}

const maxNotified = 3

// notification is the AppleScript that posts one notification naming the new findings by title.
// Titles never hold secrets (docs/connectors.md); evidence is never shown.
func notification(fresh []finding.Finding) string {
	var titles []string
	for i, f := range fresh {
		if i == maxNotified {
			titles = append(titles, fmt.Sprintf("and %d more", len(fresh)-maxNotified))
			break
		}
		titles = append(titles, f.Title)
	}
	head := fmt.Sprintf("%d new high or critical findings", len(fresh))
	if len(fresh) == 1 {
		head = "1 new " + string(fresh[0].Severity) + " finding"
	}
	return fmt.Sprintf("display notification %s with title %s subtitle %s",
		appleString(strings.Join(titles, "; ")), appleString("segurata"), appleString(head))
}

// appleString quotes s as an AppleScript string literal.
func appleString(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
