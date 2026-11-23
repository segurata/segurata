package rotation

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
)

// CLI is the `securizame rotations` command family.
type CLI struct {
	Out, Err  io.Writer
	StatePath string // "" means DefaultPath
	Now       func() time.Time
}

const usage = `usage: securizame rotations <command>
  sync   [--from out/<date>/local-secrets.jsonl] [--out out] [--include-noise]
  list   [--all] [--priority P0,P1] [--service stripe,aws]
  show   <id>
  done   <id> [--note text]
  snooze <id> --until YYYY-MM-DD [--note text]
  ignore <id> --reason text
  reopen <id> [--note text]
  done, snooze, ignore and reopen take --path <prefix> instead of an id: every item (open, or
  closed for reopen) whose locations all lie under that path, e.g. a test log full of fixtures.`

// Run executes one subcommand and returns the exit code.
func (c CLI) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	path := c.StatePath
	if path == "" {
		p, err := DefaultPath()
		if err != nil {
			return c.fail(err)
		}
		path = p
	}
	l, err := Load(path)
	if err != nil {
		return c.fail(err)
	}
	now := c.Now()
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "sync":
		return c.sync(l, path, rest, now)
	case "list":
		return c.list(l, rest, now)
	case "show":
		return c.show(l, rest)
	case "done", "snooze", "ignore", "reopen":
		return c.change(l, path, cmd, rest, now)
	}
	fmt.Fprintln(c.Err, usage)
	return 2
}

func (c CLI) fail(err error) int {
	fmt.Fprintln(c.Err, "rotations:", err)
	return 1
}

// parse parses flags wherever they appear, so `done <id> --note x` works, and returns positionals.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func newFlags(name string, errw io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("rotations "+name, flag.ContinueOnError)
	fs.SetOutput(errw)
	return fs
}

func (c CLI) sync(l *Ledger, path string, args []string, now time.Time) int {
	fs := newFlags("sync", c.Err)
	from := fs.String("from", "", "local-secrets JSONL to read (default: the latest under --out)")
	out := fs.String("out", "out", "inventory output directory")
	noise := fs.Bool("include-noise", false, "also track generic matches, public, expired and encrypted values")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	src := *from
	if src == "" {
		p, err := LatestOutput(*out)
		if err != nil {
			return c.fail(err)
		}
		src = p
	}
	rep, err := l.SyncFile(src, now, *noise)
	if err != nil {
		return c.fail(err)
	}
	if err := l.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "Synced %s: %d secrets (%d new, %d updated, %d reopened because they are still present after rotation, %d snoozes expired); %d noise-only skipped.\n",
		src, rep.Secrets, rep.Created, rep.Updated, rep.Reopened, rep.Woken, rep.Skipped)
	counts := map[secretrisk.Priority]int{}
	for _, it := range l.Items {
		if it.Active(now) {
			counts[it.Priority]++
		}
	}
	fmt.Fprintf(c.Out, "Open: P0 %d, P1 %d, P2 %d, P3 %d. Ledger: %s\n", counts[secretrisk.P0], counts[secretrisk.P1], counts[secretrisk.P2], counts[secretrisk.P3], path)
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

func (c CLI) list(l *Ledger, args []string, now time.Time) int {
	fs := newFlags("list", c.Err)
	all := fs.Bool("all", false, "include rotated, snoozed and ignored items")
	prio := fs.String("priority", "", "comma-separated priorities, e.g. P0,P1")
	service := fs.String("service", "", "comma-separated services, e.g. stripe,aws")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	prios, services := splitList(*prio), splitList(*service)
	var items []*Item
	for _, it := range l.Items {
		switch {
		case !*all && !it.Active(now):
		case len(prios) > 0 && !prios[strings.ToLower(string(it.Priority))]:
		case len(services) > 0 && !services[strings.ToLower(it.Service)]:
		default:
			items = append(items, it)
		}
	}
	Sort(items)
	tw := tabwriter.NewWriter(c.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPRI\tSTATUS\tSERVICE/TYPE\tREDACTED\tEXPOSURE\tLOCS\tFIRST SEEN\tREASON")
	for _, it := range items {
		reason := ""
		if len(it.Reasons) > 0 {
			reason = it.Reasons[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s/%s\t%s\t%s\t%d\t%s\t%s\n", it.ID, orDash(string(it.Priority)), it.Status, it.Service, it.Type,
			orDash(it.Redacted), it.WorstLabel(), len(it.Locations), it.FirstSeen.Format(time.DateOnly), truncate(reason, 90))
	}
	tw.Flush()
	fmt.Fprintf(c.Out, "%d items\n", len(items))
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func (c CLI) show(l *Ledger, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(c.Err, "usage: securizame rotations show <id>")
		return 2
	}
	it, err := l.Find(args[0])
	if err != nil {
		return c.fail(err)
	}
	w := c.Out
	fmt.Fprintf(w, "%s  %s  %s/%s  %s\n", it.ID, orDash(string(it.Priority)), it.Service, it.Type, orDash(it.Redacted))
	fmt.Fprintf(w, "status:      %s", it.Status)
	if it.SnoozedUntil != "" {
		fmt.Fprintf(w, " until %s", it.SnoozedUntil)
	}
	fmt.Fprintf(w, "\nimpact:      %s\nfingerprint: %s\nfirst seen:  %s\nlast seen:   %s\n", it.Impact, it.Fingerprint,
		it.FirstSeen.Format(time.DateOnly), it.LastSeen.Format(time.DateOnly))
	fmt.Fprintf(w, "rotate at:   %s\n", orDash(it.RotateURL))
	fmt.Fprintln(w, "\nreasons:")
	for _, r := range it.Reasons {
		fmt.Fprintf(w, "  - %s\n", r)
	}
	fmt.Fprintln(w, "\nput the new value in (used_in):")
	if len(it.UsedIn) == 0 {
		fmt.Fprintln(w, "  (no working file holds it: only history, transcripts or logs)")
	}
	for _, p := range it.UsedIn {
		fmt.Fprintf(w, "  %s\n", p)
	}
	fmt.Fprintf(w, "\nlocations (%d):\n", len(it.Locations))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, loc := range it.Locations {
		where := loc.Path
		if loc.Line > 0 {
			where = fmt.Sprintf("%s:%d", loc.Path, loc.Line)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tmode %s\tlast seen %s\n", where, loc.spot().Label, loc.Bucket, loc.Source,
			orDash(loc.Mode), loc.LastSeen.Format(time.DateOnly))
	}
	tw.Flush()
	fmt.Fprintln(w, "\nhistory:")
	for _, e := range it.History {
		fmt.Fprintf(w, "  %s  %s  %s\n", e.At.Format(time.RFC3339), e.Action, e.Note)
	}
	return 0
}

func (c CLI) change(l *Ledger, path, cmd string, args []string, now time.Time) int {
	fs := newFlags(cmd, c.Err)
	note := fs.String("note", "", "free text kept in the history")
	var until, reason *string
	switch cmd {
	case "snooze":
		until = fs.String("until", "", "date the item comes back, YYYY-MM-DD")
	case "ignore":
		reason = fs.String("reason", "", "why this is not a secret to rotate")
	}
	under := fs.String("path", "", "instead of an id: every item whose locations all lie under this path")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if (len(pos) == 1) == (*under != "") {
		fmt.Fprintf(c.Err, "usage: securizame rotations %s <id> | --path <prefix> (see: securizame rotations)\n", cmd)
		return 2
	}
	var items []*Item
	if *under != "" {
		items = l.Under(*under, cmd == "reopen", now)
		if len(items) == 0 {
			return c.fail(fmt.Errorf("no %s item lies entirely under %s", map[bool]string{true: "closed", false: "open"}[cmd == "reopen"], *under))
		}
	} else {
		it, err := l.Find(pos[0])
		if err != nil {
			return c.fail(err)
		}
		items = []*Item{it}
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
	if err := l.Save(path); err != nil {
		return c.fail(err)
	}
	for _, it := range items {
		fmt.Fprintf(c.Out, "%s %s/%s %s: %s\n", it.ID, it.Service, it.Type, orDash(it.Redacted), it.Status)
	}
	if len(items) > 1 {
		fmt.Fprintf(c.Out, "%d items\n", len(items))
	}
	return 0
}
