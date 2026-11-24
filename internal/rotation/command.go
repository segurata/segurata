// Package rotation is `segurata rotations`: the guided flow over the tracker's rotate items, one
// per secret fingerprint (list, next, show, replace, done, snooze, ignore, reopen). The items, their
// risk model and the reopen rules live in internal/tracker. See docs/architecture.md, "Rotation
// ledger".
package rotation

import (
	"fmt"
	"github.com/segurata/segurata/internal/config"
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
  sync    [--from out/<date>/local-secrets.jsonl] [--out out] [--include-noise]
  list    [--all] [--priority P0,P1] [--service stripe,aws] [--owner mine,not-mine,unknown]
  next    [--priority P0] [--service stripe] [--log]   the most urgent item, with what to do (--log records it was shown)
  show    <id>   with whose it is (owner, confidence, the reasons and claims behind it)
  replace <id> [--stdin] [--to-keychain <service>] [--apply [--yes] [--backup]]
          put the new value in every used_in file (see: segurata rotations replace --help)
  done    <id> [--note text]
  snooze  <id> --until YYYY-MM-DD [--note text]
  ignore  <id> --reason text
  reopen  <id> [--note text]
  done, snooze, ignore and reopen take --path <prefix> instead of an id: every item (open, or
  closed for reopen) whose locations all lie under that path, e.g. a test log full of fixtures.`

// Run executes one subcommand and returns the exit code.
func (c CLI) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "sync", "list", "next", "show", "replace", "done", "snooze", "ignore", "reopen":
	default:
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	// Commands that save hold the tracker lock from load to save. replace does not: it holds the
	// tracker across the clipboard, a confirmation and file writes, and records each outcome with
	// tracker.Update instead.
	now := c.Now()
	t, path, unlock, err := tracker.LoadFor(c.Paths, now, cmd != "list" && cmd != "show" && cmd != "replace")
	defer unlock()
	if err != nil {
		return c.fail(err)
	}
	switch cmd {
	case "sync":
		return c.sync(t, path, rest, now)
	case "list":
		return c.list(t, rest, now)
	case "next":
		return c.next(t, path, rest, now)
	case "show":
		return c.show(t, rest)
	case "replace":
		return c.replace(t, path, rest, now)
	default: // done, snooze, ignore, reopen
		return c.change(t, path, cmd, rest, now)
	}
}

func (c CLI) fail(err error) int {
	fmt.Fprintln(c.Err, "rotations:", err)
	return 1
}

func (c CLI) sync(t *tracker.Tracker, path string, args []string, now time.Time) int {
	fs := cliflag.New("rotations sync", c.Err)
	from := fs.String("from", "", "local-secrets JSONL to read (default: the latest under --out)")
	out := fs.String("out", config.DefaultOutDir(), "inventory output directory")
	noise := fs.Bool("include-noise", false, "also track generic matches, public, expired and encrypted values")
	if pos, err := cliflag.Parse(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	opt, err := tracker.ConfiguredSync(c.Config, tracker.SyncOptions{OutDir: *out, From: *from, IncludeNoise: *noise})
	if err != nil {
		return c.fail(err)
	}
	t, rep, err := tracker.SyncAndSave(t, path, opt, now, func(rep tracker.SyncReport) error {
		if !rep.FoldedSecrets() {
			return fmt.Errorf("no %s output under %s: run `segurata inventory %s` first", tracker.SecretsConnector, *out, tracker.SecretsConnector)
		}
		return nil
	})
	if err != nil {
		return c.fail(err)
	}
	r := rep.Secrets
	fmt.Fprintf(c.Out, "Synced: %d secrets (%d new, %d updated, %d reopened because a working file still holds the old value, %d snoozes expired); %d reclassified as noise, %d noise-only skipped.\n",
		r.Secrets, r.Created, r.Updated, r.Reopened, rep.Woken, r.Reclassified, r.Skipped)
	if r.HistoryOnly > 0 {
		fmt.Fprintf(c.Out, "%d rotated %s seen again only in history, transcripts or logs: left rotated (%s).\n",
			r.HistoryOnly, textfmt.Plural(r.HistoryOnly, "secret", "secrets"), tracker.HistoryOnly)
	}
	counts := map[secretrisk.Priority]int{}
	for _, it := range selectItems(t, now, false, nil, nil) {
		counts[it.EffectivePriority()]++
	}
	fmt.Fprintf(c.Out, "Open: P0 %d, P1 %d, P2 %d, P3 %d. Tracker: %s\n", counts[secretrisk.P0], counts[secretrisk.P1], counts[secretrisk.P2], counts[secretrisk.P3], path)
	owners := t.OwnerCounts(func(it *tracker.Item) bool { return it.Active(now) })
	fmt.Fprintf(c.Out, "Open by owner: mine %d, not-mine %d, unknown %d (segurata rotations list --owner not-mine).\n",
		owners[attribution.Mine], owners[attribution.NotMine], owners[attribution.Unknown])
	fmt.Fprint(c.Out, tracker.SyncLine(rep))
	return 0
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
	fmt.Fprintln(tw, "ID\tPRI\tSTATUS\tOWNER\tSERVICE/TYPE\tREDACTED\tEXPOSURE\tLOCS\tFIRST SEEN\tREASON")
	for _, it := range items {
		s := it.Secret
		reason := ""
		if len(s.Reasons) > 0 {
			reason = s.Reasons[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s/%s\t%s\t%s\t%d\t%s\t%s\n", s.ID, textfmt.OrDash(string(it.EffectivePriority())), stateOf(it),
			textfmt.OrDash(string(it.Owner())), s.Service, s.Type, textfmt.OrDash(s.Redacted), it.WorstLabel(), len(s.Locations),
			s.FirstSeen.Format(time.DateOnly), textfmt.Truncate(reason, 90))
	}
	tw.Flush()
	fmt.Fprintf(c.Out, "%d items\n", len(items))
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
	fmt.Fprintf(w, "status:      %s", stateOf(it))
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
	}{{"AWS accounts", f.AWSAccounts}, {"GCP projects", f.GCPProjects}, {"Slack workspaces", f.SlackTeams},
		{"commit authors", f.AuthorEmails}, {"repository owners", f.RepoOwners}} {
		if len(kv.v) > 0 {
			fmt.Fprintf(w, "  %s: %s\n", kv.k, strings.Join(kv.v, ", "))
		}
	}
}

// stateOf is an item's status in the words of this command family: a done secret is "rotated".
func stateOf(it *tracker.Item) string {
	if it.Status == tracker.Done {
		return "rotated"
	}
	return string(it.Status)
}

// itemsUnder returns the rotate items whose every location lies under prefix (a ~/ path, as findings
// report them; an absolute path inside the home directory is accepted too): active ones, or
// closed ones when closed is true.
func itemsUnder(t *tracker.Tracker, prefix string, closed bool, now time.Time) []*tracker.Item {
	var out []*tracker.Item
	for _, it := range t.Items {
		if it.Kind == tracker.KindRotate && it.Active(now) != closed && it.Under(prefix) {
			out = append(out, it)
		}
	}
	tracker.Sort(out)
	return out
}

func (c CLI) change(t *tracker.Tracker, path, cmd string, args []string, now time.Time) int {
	fs := cliflag.New("rotations "+cmd, c.Err)
	note := fs.String("note", "", "free text kept in the history")
	var until, reason *string
	switch cmd {
	case "snooze":
		until = fs.String("until", "", "date the item comes back, YYYY-MM-DD")
	case "ignore":
		reason = fs.String("reason", "", "why this is not a secret to rotate")
	}
	under := fs.String("path", "", "instead of an id: every item whose locations all lie under this path")
	pos, err := cliflag.Parse(fs, args)
	if err != nil {
		return 2
	}
	if (len(pos) == 1) == (*under != "") {
		fmt.Fprintf(c.Err, "usage: segurata rotations %s <id> | --path <prefix> (see: segurata rotations)\n", cmd)
		return 2
	}
	var items []*tracker.Item
	if *under != "" {
		items = itemsUnder(t, *under, cmd == "reopen", now)
		if len(items) == 0 {
			return c.fail(fmt.Errorf("no %s item lies entirely under %s", map[bool]string{true: "closed", false: "open"}[cmd == "reopen"], *under))
		}
	} else {
		it, err := t.FindRotate(pos[0])
		if err != nil {
			return c.fail(err)
		}
		items = []*tracker.Item{it}
	}
	for _, it := range items {
		switch cmd {
		case "done":
			it.Done(now, *note)
		case "snooze":
			err = it.Snooze(now, *until, *note)
		case "ignore":
			r := strings.TrimSpace(*reason)
			if r != "" && *note != "" {
				r += "; " + *note
			}
			err = it.Ignore(now, r)
		case "reopen":
			it.Reopen(now, *note)
		}
		if err != nil {
			return c.fail(err) // nothing saved: a bad flag fails before the first item changes
		}
	}
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	for _, it := range items {
		s := it.Secret
		fmt.Fprintf(c.Out, "%s %s/%s %s: %s\n", s.ID, s.Service, s.Type, textfmt.OrDash(s.Redacted), stateOf(it))
	}
	if len(items) > 1 {
		fmt.Fprintf(c.Out, "%d items\n", len(items))
	}
	return 0
}
