// Package rotation is `segurata rotations`: the guided flow over the tracker's rotate items, one
// per secret fingerprint (list, next, show, replace). sync, done, snooze, ignore and reopen are
// track's own verbs, run on secrets only (tracker.CLI.Rotations). The items, their risk model and
// the reopen rules live in internal/tracker. See docs/architecture.md, "Rotation ledger".
package rotation

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

// CLI is the `segurata rotations` command family.
type CLI struct {
	Out, Err io.Writer
	In       io.Reader     // confirmations, and the new value with replace --stdin
	TTY      bool          // In is a terminal
	Paths    tracker.Paths // zero means tracker.DefaultPaths
	Config   string        // config file whose expected rules sync applies; "" means none
	KeyPath  string        // fingerprint key; "" means fingerprint.DefaultPath
	Home     func() (string, error)
	User     string // Keychain account for replace --to-keychain
	Exec     Runner // pbpaste, pbcopy, security
	Now      func() time.Time
}

const usage = `usage: segurata rotations <command>
  sync    [--from <run-file>] [--out out] [--include-noise]
  list    [--all] [--priority P0,P1] [--service stripe,aws] [--owner mine,not-mine,unknown]
  next    [--priority P0] [--service stripe] [--log]   the most urgent item, with what to do (--log records it was shown)
  show    <id>   with whose it is (owner, confidence, the reasons and claims behind it)
  replace <id> [--stdin] [--to-keychain <service>] [--apply [--yes] [--backup]]
          replace the old value in eligible working files (see: segurata rotations replace --help)
  done    <id> [--note text]
  snooze  <id> --until YYYY-MM-DD [--note text]
  ignore  <id> --reason text
  reopen  <id> [--note text]
  done, snooze, ignore and reopen take --path <prefix> instead of an id: every item (open, or
  closed for reopen) whose locations all lie under that path, e.g. a test log full of fixtures.
  sync, done, snooze, ignore and reopen are segurata track's, on secrets only.`

// Run executes one subcommand and returns the exit code.
func (c CLI) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	if slices.Contains(tracker.RotationVerbs, cmd) {
		return tracker.CLI{Out: c.Out, Err: c.Err, Paths: c.Paths, Config: c.Config, Now: c.Now}.Rotations(args, usage)
	}
	switch cmd {
	case "list", "next", "show", "replace":
	default:
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	// Commands that save hold the tracker lock from load to save. replace does not: it holds the
	// tracker across the clipboard, a confirmation and file writes, and records each outcome with
	// tracker.Update instead.
	now := c.Now()
	t, path, unlock, err := tracker.LoadFor(c.Paths, now, cmd == "next")
	defer unlock()
	if err != nil {
		return c.fail(err)
	}
	switch cmd {
	case "list":
		return c.list(t, rest, now)
	case "next":
		return c.next(t, path, rest, now)
	case "show":
		return c.show(t, rest)
	default: // replace
		return c.replace(t, path, rest, now)
	}
}

func (c CLI) fail(err error) int {
	fmt.Fprintln(c.Err, "rotations:", textfmt.Terminal(err.Error()))
	return 1
}

func splitList(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			m[strings.ToLower(p)] = true
		}
	}
	return m
}

func (c CLI) list(t *tracker.Tracker, args []string, now time.Time) int {
	fs := cliflag.New("rotations list", c.Err)
	all := fs.Bool("all", false, "include rotated, snoozed and ignored items")
	prio := fs.String("priority", "", "comma-separated priorities, e.g. P0,P1")
	service := fs.String("service", "", "comma-separated services, e.g. stripe,aws")
	owner := fs.String("owner", "", "comma-separated attributions: mine, not-mine, unknown")
	if pos, err := cliflag.Parse(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	items := selectItems(t, now, *all, splitList(*prio), splitList(*service))
	if *owner != "" {
		owners, err := attribution.ParseOwners(*owner)
		if err != nil {
			return c.fail(err)
		}
		items = slices.DeleteFunc(items, func(it *tracker.Item) bool { return !slices.Contains(owners, it.Owner()) })
	}
	tw := tabwriter.NewWriter(c.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPRI\tSTATUS\tOWNER\tLIVE\tSERVICE/TYPE\tREDACTED\tEXPOSURE\tLOCS\tFIRST SEEN\tREASON")
	for _, it := range items {
		s := it.Secret
		reason := ""
		if len(s.Reasons) > 0 {
			reason = s.Reasons[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s/%s\t%s\t%s\t%d\t%s\t%s\n", s.ID, textfmt.OrDash(string(it.EffectivePriority())), it.RotationStatus(),
			textfmt.OrDash(string(it.Owner())), it.LivenessLabel(), s.Service, s.Type, textfmt.OrDash(s.Redacted), it.WorstLabel(), len(s.Locations),
			s.FirstSeen.Format(time.DateOnly), textfmt.Truncate(reason, 90))
	}
	tw.Flush()
	fmt.Fprintf(c.Out, "%d items\n", len(items))
	if line := t.LivenessLine(); line != "" {
		fmt.Fprintln(c.Out, line)
	}
	return 0
}

func (c CLI) show(t *tracker.Tracker, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(c.Err, "usage: segurata rotations show <id>")
		return 2
	}
	it, err := t.FindRotate(args[0])
	if err != nil {
		return c.fail(err)
	}
	s, w := it.Secret, c.Out
	fmt.Fprintf(w, "%s  %s  %s/%s  %s  (%s)\n", s.ID, textfmt.OrDash(string(it.EffectivePriority())), s.Service, s.Type, textfmt.OrDash(s.Redacted), it.ID)
	fmt.Fprintf(w, "status:      %s", it.RotationStatus())
	if it.SnoozedUntil != "" {
		fmt.Fprintf(w, " until %s", it.SnoozedUntil)
	}
	fmt.Fprintf(w, "\nimpact:      %s\nfingerprint: %s\nfirst seen:  %s\nlast seen:   %s\n", s.Impact, it.Fingerprint,
		s.FirstSeen.Format(time.DateOnly), s.LastSeen.Format(time.DateOnly))
	fmt.Fprintf(w, "rotate at:   %s\n", textfmt.OrDash(s.RotateURL))
	if o := it.PriorityOverride; o != nil {
		fmt.Fprintf(w, "priority:    %s set by hand (%s), computed %s\n", o.Priority, o.Reason, textfmt.OrDash(string(it.Priority)))
	}
	fmt.Fprintln(w, "\nreasons:")
	for _, r := range s.Reasons {
		fmt.Fprintf(w, "  - %s\n", r)
	}
	printAttribution(w, s.Attribution)
	printLiveness(w, s.Liveness)
	fmt.Fprintln(w, "\nput the new value in (used_in):")
	if len(s.UsedIn) == 0 {
		fmt.Fprintln(w, "  (no working file holds it: only history, transcripts or logs)")
	}
	for _, p := range s.UsedIn {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintf(w, "\nlocations (%d):\n", len(s.Locations))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, loc := range s.Locations {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tmode %s\tlast seen %s\n", loc.Where(), loc.Spot().Label, loc.Bucket, loc.Source,
			textfmt.OrDash(loc.Mode), loc.LastSeen.Format(time.DateOnly))
	}
	tw.Flush()
	fmt.Fprintln(w, "\nhistory:")
	for _, e := range it.History {
		fmt.Fprintf(w, "  %s  %s  %s\n", e.At.Format(time.RFC3339), e.Action, e.Detail)
	}
	return 0
}

// printLiveness says what the provider answered when the secret was tried.
func printLiveness(w io.Writer, l *secretrisk.Liveness) {
	if l == nil {
		fmt.Fprintln(w, "liveness:    unchecked")
		return
	}
	fmt.Fprintf(w, "liveness:    %s, checked %s: %s", l.State, l.CheckedAt.Format(time.DateOnly), l.Said())
	if l.Account != "" {
		fmt.Fprintf(w, " (signs in as %s)", l.Account)
	}
	fmt.Fprintln(w)
}

// printAttribution says whose the secret is and why.
func printAttribution(w io.Writer, a *attribution.Result) {
	if a == nil {
		fmt.Fprintln(w, "\nowner:       not attributed yet (run segurata rotations sync)")
		return
	}
	fmt.Fprintf(w, "\nowner:       %s (%s confidence)\n", a.Owner, a.Confidence)
	for _, r := range a.Reasons {
		fmt.Fprintf(w, "  - %s\n", r)
	}
	f := a.Facts
	for _, kv := range []struct {
		k string
		v []string
	}{{"AWS accounts", f.AWSAccounts}, {"GCP projects", f.GCPProjects}, {"Slack workspaces", f.SlackTeams}, {"GitHub accounts", f.GitHubLogins},
		{"commit authors", f.AuthorEmails}, {"repository owners", f.RepoOwners}} {
		if len(kv.v) > 0 {
			fmt.Fprintf(w, "  %s: %s\n", kv.k, strings.Join(kv.v, ", "))
		}
	}
}
