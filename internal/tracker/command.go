package tracker

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
	"github.com/segurata/segurata/internal/textfmt"
)

const trackUsage = `usage: securizame track <command>
  list       [--all] [--theme t] [--kind k] [--priority P0,P1] [--status s]   items (secrets: --kind rotate)
  show       <id>
  start      <id> [--note text]
  done       <id> [--note text]       a later sync verifies it, or reopens it if a run still reports it
  note       <id> <text>
  decide     <id> --answer text
  snooze     <id> --until YYYY-MM-DD [--note text]
  ignore     <id> --reason text
  reopen     <id> [--note text]
  prioritize <id> P0|P1|P2|P3|auto [--reason text]
  add        --title text [--kind fix|decide|setup|review] [--theme t] [--priority P2] [--note text]
             --kind decide --question text --option a --option b
  sync       [--out out] [--from out/<date>/local-secrets.jsonl] [--include-noise]
<id> is T-0012 (or T-12), or a secret's short id.`

const statusUsage = "usage: securizame status [--theme t] [--kind k] [--priority P0,P1] [--format text|md|html] [--write]"

// CLI is `securizame track` and `securizame status`.
type CLI struct {
	Out, Err io.Writer
	Paths    Paths // zero means DefaultPaths
	Now      func() time.Time
}

func (c CLI) fail(err error) int {
	fmt.Fprintln(c.Err, "track:", err)
	return 1
}

func (c CLI) open(now time.Time) (*Tracker, string, error) {
	p, err := c.Paths.Resolve()
	if err != nil {
		return nil, "", err
	}
	t, err := LoadOrMigrate(p, now, c.Err)
	return t, p.Tracker, err
}

func flags(name string, w io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(w)
	return fs
}

// multi is a flag given several times.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// set reads a comma-separated flag value.
func set(s string, upper bool) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if upper {
				p = strings.ToUpper(p)
			}
			m[p] = true
		}
	}
	return m
}

// Track runs one `securizame track` subcommand.
func (c CLI) Track(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.Err, trackUsage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "list", "show", "add", "sync", "start", "done", "note", "decide", "snooze", "ignore", "reopen", "prioritize":
	default:
		fmt.Fprintln(c.Err, trackUsage)
		return 2
	}
	now := c.Now()
	t, path, err := c.open(now)
	if err != nil {
		return c.fail(err)
	}
	switch cmd {
	case "list":
		return c.list(t, rest, now)
	case "show":
		return c.show(t, rest)
	case "add":
		return c.add(t, path, rest, now)
	case "sync":
		return c.sync(t, path, rest, now)
	}
	return c.change(t, path, cmd, rest, now)
}

func (c CLI) sync(t *Tracker, path string, args []string, now time.Time) int {
	fs := flags("track sync", c.Err)
	out := fs.String("out", "out", "inventory output directory")
	from := fs.String("from", "", "local-secrets JSONL to read instead of its latest run")
	noise := fs.Bool("include-noise", false, "also track noise-only secrets, without a priority")
	if pos, err := cliflag.Parse(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(c.Err, trackUsage)
		return 2
	}
	rep, err := t.Sync(SyncOptions{OutDir: *out, From: *from, IncludeNoise: *noise}, now)
	if err != nil {
		return c.fail(err)
	}
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	s := rep.Secrets
	fmt.Fprintf(c.Out, "Secrets: %d (%d new, %d reopened, %d noise-only skipped).\n", s.Secrets, s.Created, s.Reopened, s.Skipped)
	fmt.Fprint(c.Out, SyncLine(rep))
	return 0
}

func (c CLI) list(t *Tracker, args []string, now time.Time) int {
	fs := flags("track list", c.Err)
	all := fs.Bool("all", false, "include done, accepted, ignored and snoozed items")
	theme := fs.String("theme", "", "comma-separated themes")
	kind := fs.String("kind", "", "comma-separated kinds: fix, rotate, decide, setup, review")
	prio := fs.String("priority", "", "comma-separated priorities, e.g. P0,P1")
	status := fs.String("status", "", "comma-separated statuses")
	if pos, err := cliflag.Parse(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(c.Err, trackUsage)
		return 2
	}
	f := newFilter(*theme, *kind, *prio)
	statuses := set(*status, false)
	var items []*Item
	secrets := 0
	for _, it := range t.Items {
		switch {
		case !f.keep(it):
		case len(statuses) > 0 && !statuses[string(it.Status)]:
		case len(statuses) == 0 && !*all && !it.Active(now):
		case it.Kind == KindRotate && len(f.Kinds) == 0:
			secrets++
		default:
			items = append(items, it)
		}
	}
	Sort(items)
	tw := tabwriter.NewWriter(c.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPRI\tSTATUS\tKIND\tTHEME\tSEV\tFINDINGS\tTITLE")
	for _, it := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", it.ID, textfmt.OrDash(string(it.EffectivePriority())), it.Status, it.Kind, it.Theme,
			textfmt.OrDash(string(it.Severity)), len(it.Findings), textfmt.Truncate(it.Title, 100))
	}
	tw.Flush()
	fmt.Fprintf(c.Out, "%s\n", count(len(items), "item", "items"))
	if secrets > 0 {
		fmt.Fprintf(c.Out, "Plus %s to rotate: securizame rotations list (or --kind rotate).\n", count(secrets, "secret", "secrets"))
	}
	return 0
}

func (c CLI) show(t *Tracker, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(c.Err, "usage: securizame track show <id>")
		return 2
	}
	it, err := t.Find(args[0])
	if err != nil {
		return c.fail(err)
	}
	w := c.Out
	fmt.Fprintf(w, "%s  %s  %s\n", it.ID, textfmt.OrDash(string(it.EffectivePriority())), it.Title)
	fmt.Fprintf(w, "status:    %s", it.Status)
	if it.SnoozedUntil != "" {
		fmt.Fprintf(w, " until %s", it.SnoozedUntil)
	}
	if it.VerifiedAt != nil {
		fmt.Fprintf(w, " (verified %s)", it.VerifiedAt.Format(time.DateOnly))
	}
	fmt.Fprintf(w, "\nkind:      %s\ntheme:     %s\nseverity:  %s\nkey:       %s\ncreated:   %s\n", it.Kind, t.ThemeTitle(it.Theme),
		textfmt.OrDash(string(it.Severity)), it.Key, it.CreatedAt.Format(time.DateOnly))
	if o := it.PriorityOverride; o != nil {
		fmt.Fprintf(w, "priority:  %s set by hand (%s), computed %s\n", o.Priority, o.Reason, textfmt.OrDash(string(it.Priority)))
	}
	if a := it.Accepted; a != nil {
		fmt.Fprintf(w, "accepted:  %s (until %s)\n", a.Reason, textfmt.OrDash(a.Until))
	}
	if d := it.Decision; d != nil {
		fmt.Fprintf(w, "question:  %s\n", d.Question)
		for _, o := range d.Options {
			fmt.Fprintf(w, "  option:  %s\n", o)
		}
		if d.Answer != "" {
			fmt.Fprintf(w, "answer:    %s\n", d.Answer)
		}
	}
	if n := it.Next; n != nil {
		fmt.Fprintf(w, "\nnext (%s): %s\n", n.Who, n.Action)
		if n.Command != "" && n.Command != "securizame track show "+it.ID {
			fmt.Fprintf(w, "  $ %s\n", n.Command)
		}
		if n.URL != "" {
			fmt.Fprintf(w, "  %s\n", n.URL)
		}
	}
	if s := it.Secret; s != nil {
		fmt.Fprintf(w, "\nsecret %s %s/%s %s, %s; details: securizame rotations show %s\n", s.ID, s.Service, s.Type, textfmt.OrDash(s.Redacted),
			count(len(s.Locations), "location", "locations"), s.ID)
	}
	if len(it.Findings) > 0 {
		fmt.Fprintf(w, "\nfindings (%d):\n", len(it.Findings))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, r := range it.Findings {
			state := "reported"
			if r.Gone {
				state = "gone"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", r.ID, textfmt.OrDash(string(r.Severity)), state, r.Label(), r.LastSeen.Format(time.DateOnly), textfmt.Truncate(r.Title, 100))
		}
		tw.Flush()
	}
	fmt.Fprintln(w, "\nhistory:")
	for _, e := range it.History {
		fmt.Fprintf(w, "  %s  %-9s %-18s %s\n", e.At.Format(time.RFC3339), e.Event, e.Action, e.Detail)
	}
	return 0
}

func (c CLI) change(t *Tracker, path, cmd string, args []string, now time.Time) int {
	fs := flags("track "+cmd, c.Err)
	note := fs.String("note", "", "free text kept in the history")
	until := fs.String("until", "", "snooze: date the item comes back, YYYY-MM-DD")
	reason := fs.String("reason", "", "ignore, prioritize: why")
	answer := fs.String("answer", "", "decide: the answer")
	pos, err := cliflag.Parse(fs, args)
	want := 1 // note takes the id and any number of words
	if cmd == "prioritize" {
		want = 2
	}
	if err != nil || len(pos) < 1 || (cmd != "note" && len(pos) != want) {
		fmt.Fprintf(c.Err, "usage: securizame track %s <id> (see: securizame track)\n", cmd)
		return 2
	}
	it, err := t.Find(pos[0])
	if err != nil {
		return c.fail(err)
	}
	switch cmd {
	case "start":
		err = it.Start(now, *note)
	case "done":
		it.Done(now, *note)
	case "note":
		err = it.Note(now, strings.Join(pos[1:], " "))
	case "decide":
		err = it.Decide(now, *answer)
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
	case "prioritize":
		var p secretrisk.Priority
		if p, err = ParsePriority(pos[1]); err == nil {
			err = it.Prioritize(now, p, *reason)
		}
	}
	if err != nil {
		return c.fail(err)
	}
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "%s %s · %s: %s\n", it.ID, textfmt.OrDash(string(it.EffectivePriority())), it.Title, it.Status)
	return 0
}

func (c CLI) add(t *Tracker, path string, args []string, now time.Time) int {
	fs := flags("track add", c.Err)
	kind := fs.String("kind", string(KindFix), "fix, decide, setup or review")
	title := fs.String("title", "", "what to do")
	theme := fs.String("theme", "", "theme id (default: decisions for decide, else other)")
	prio := fs.String("priority", "P2", "P0, P1, P2 or P3")
	question := fs.String("question", "", "decide: the question")
	note := fs.String("note", "", "free text kept in the history")
	var options multi
	fs.Var(&options, "option", "decide: one possible answer (repeat for each)")
	if pos, err := cliflag.Parse(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(c.Err, trackUsage)
		return 2
	}
	p, err := ParsePriority(*prio)
	if err != nil || p == "" {
		return c.fail(fmt.Errorf("--priority %q: use P0, P1, P2 or P3", *prio))
	}
	k := Kind(*kind)
	var it *Item
	switch {
	case k == KindDecide:
		if strings.TrimSpace(*question) == "" {
			return c.fail(errors.New("--kind decide needs --question"))
		}
		it = t.AddDecision(fmt.Sprintf("manual:%d", t.NextID), *question, options, now)
	case k == KindRotate || !slices.Contains(kinds, k):
		return c.fail(fmt.Errorf("--kind %q: use fix, decide, setup or review (secrets come from local-secrets)", *kind))
	case strings.TrimSpace(*title) == "":
		return c.fail(errors.New("add needs --title"))
	default:
		it = t.newItem(k, fmt.Sprintf("manual:%d", t.NextID), "other", strings.TrimSpace(*title), now)
		it.Next = &Next{Who: You, Action: it.Title}
		it.Log(now, EvFound, actFound, "added by hand")
	}
	it.Priority = p
	if *theme != "" {
		it.Theme = *theme
	}
	if *note != "" {
		_ = it.Note(now, *note)
	}
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "Added %s %s · %s (%s, %s).\n", it.ID, it.Priority, it.Title, it.Kind, it.Theme)
	return 0
}

// Status prints the briefing, and with --write also writes status.md and status.html next to the
// tracker (mode 0600). An unfiltered status remembers when it ran, for "Since the last status".
func (c CLI) Status(args []string) int {
	fs := flags("status", c.Err)
	theme := fs.String("theme", "", "comma-separated themes")
	kind := fs.String("kind", "", "comma-separated kinds")
	prio := fs.String("priority", "", "comma-separated priorities, e.g. P0,P1")
	format := fs.String("format", string(doc.Text), "text, md or html")
	write := fs.Bool("write", false, "also write status.md and status.html next to the tracker (mode 0600)")
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) > 0 || !doc.Format(*format).Valid() {
		fmt.Fprintln(c.Err, statusUsage)
		return 2
	}
	now := c.Now()
	t, path, err := c.open(now)
	if err != nil {
		return c.fail(err)
	}
	f := newFilter(*theme, *kind, *prio)
	d := t.Status(path, now, f)
	if err := doc.Render(c.Out, d, doc.Format(*format)); err != nil {
		return c.fail(err)
	}
	if *write {
		for _, ff := range []doc.Format{doc.Markdown, doc.HTML} {
			var b bytes.Buffer
			if err := doc.Render(&b, d, ff); err != nil {
				return c.fail(err)
			}
			name := filepath.Join(filepath.Dir(path), "status."+map[doc.Format]string{doc.Markdown: "md", doc.HTML: "html"}[ff])
			if err := statefile.Write(name, b.Bytes()); err != nil {
				return c.fail(err)
			}
			fmt.Fprintf(c.Err, "Wrote %s (mode 0600).\n", name)
		}
	}
	if f.empty() {
		at := now.UTC()
		t.LastStatusAt = &at
		if err := t.Save(path); err != nil {
			return c.fail(err)
		}
	}
	return 0
}
