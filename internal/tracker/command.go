package tracker

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
	"github.com/segurata/segurata/internal/textfmt"
)

const trackUsage = `usage: segurata track <command>
  list       [--all] [--theme t] [--kind k] [--priority P0,P1] [--status s]   items (secrets: --kind rotate)
  show       <id>
  start      <id> [--note text]
  done       <id> [--note text]       a later sync verifies it, or reopens it if a run still reports it
  note       <id> <text>
  decide     <id> --answer text [--ignore-scope s]... [--accept-scope s]... [--owner not-mine] [--dry-run]
             s: path:~/src/old, repo:owner/name, account:<glob>, gcp-project:<id>; --owner narrows the
             scopes' rules to secrets attributed to those owners (mine, not-mine, unknown); --dry-run
             prints what answering would close and keep open, and changes nothing
  snooze     <id> --until YYYY-MM-DD [--note text]
  ignore     <id> --reason text
  expect     <setup-id> --reason text [--detail text] [--dry-run]   write a config rule that expects its status, close it
  reopen     <id> [--note text]
  prioritize <id> P0|P1|P2|P3|auto [--reason text]
  add        --title text [--kind fix|decide|setup|review] [--theme t] [--priority P2] [--note text]
             --kind decide --question text --option a --option "b=ignore:path:~/src/old"   (an option's effect applies when it is the answer;
             "b=ignore@not-mine:path:~/src/old" closes only secrets attributed not-mine)
  sync       [--out out] [--from out/<date>/local-secrets.jsonl] [--include-noise]
<id> is T-0012 (or T-12), or a secret's short id.`

const statusUsage = "usage: segurata status [--theme t] [--kind k] [--priority P0,P1] [--format text|md|html] [--explain] [--write] [--mark-seen]"

// CLI is `segurata track` and `segurata status`.
type CLI struct {
	Out, Err io.Writer
	Paths    Paths  // zero means DefaultPaths
	Config   string // config file with the expected rules; "" means none (and no track expect)
	Now      func() time.Time
	// Instances lists the configured connector instances, for status's coverage line; nil lists
	// only the ones that ran.
	Instances func() []string
	// Browser names the connectors that drive the browser (status's segurata signin line); nil
	// for none.
	Browser func(connector string) bool
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

// Track runs one `segurata track` subcommand.
func (c CLI) Track(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.Err, trackUsage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "list", "show", "add", "sync", "start", "done", "note", "decide", "snooze", "ignore", "reopen", "prioritize", "expect":
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
		return c.show(t, rest, now)
	case "add":
		return c.add(t, path, rest, now)
	case "sync":
		return c.sync(t, path, rest, now)
	case "expect":
		return c.expect(t, path, rest, now)
	}
	return c.change(t, path, cmd, rest, now)
}

func (c CLI) sync(t *Tracker, path string, args []string, now time.Time) int {
	fs := flags("track sync", c.Err)
	out := fs.String("out", config.DefaultOutDir(), "inventory output directory")
	from := fs.String("from", "", "local-secrets JSONL to read instead of its latest run")
	noise := fs.Bool("include-noise", false, "also track noise-only secrets, without a priority")
	if pos, err := cliflag.Parse(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(c.Err, trackUsage)
		return 2
	}
	opt, err := ConfiguredSync(c.Config, SyncOptions{OutDir: *out, From: *from, IncludeNoise: *noise})
	if err != nil {
		return c.fail(err)
	}
	rep, err := t.Sync(opt, now)
	if err != nil {
		return c.fail(err)
	}
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	s := rep.Secrets
	fmt.Fprintf(c.Out, "Secrets: %d (%d new, %d reopened, %d reclassified as noise, %d noise-only skipped).\n", s.Secrets, s.Created, s.Reopened, s.Reclassified, s.Skipped)
	fmt.Fprint(c.Out, SyncLine(rep))
	return 0
}

// expect writes the config rule that expects a setup item's status and closes the item as
// expected; --dry-run prints the rule and changes nothing.
func (c CLI) expect(t *Tracker, path string, args []string, now time.Time) int {
	fs := flags("track expect", c.Err)
	reason := fs.String("reason", "", "why this status is expected")
	detail := fs.String("detail", "", "only statuses whose detail contains this text (or matches /regexp/)")
	dry := fs.Bool("dry-run", false, "print the rule and change nothing")
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprintln(c.Err, "usage: segurata track expect <setup-item-id> --reason text [--detail text] [--dry-run]")
		return 2
	}
	it, err := t.Find(pos[0])
	if err != nil {
		return c.fail(err)
	}
	key, rule, err := it.ExpectRule(*reason, *detail)
	if err != nil {
		return c.fail(err)
	}
	if c.Config == "" {
		return c.fail(errors.New("no config file to write the rule to"))
	}
	raw, _ := json.MarshalIndent(rule, "  ", "  ")
	if *dry {
		fmt.Fprintf(c.Out, "Would add to connectors.%q.expected in %s:\n  %s\nand close %s (%s) as expected. Nothing written (--dry-run).\n",
			key, c.Config, raw, it.ID, it.Title)
		return 0
	}
	changed, backup, err := config.AddExpected(c.Config, key, rule, now)
	if err != nil {
		return c.fail(err)
	}
	if changed {
		fmt.Fprintf(c.Out, "Added to connectors.%q.expected in %s:\n  %s\n", key, c.Config, raw)
		if backup != "" {
			fmt.Fprintf(c.Out, "The previous config is kept as %s.\n", backup)
		}
	} else {
		fmt.Fprintf(c.Out, "connectors.%q.expected in %s already has this rule.\n", key, c.Config)
	}
	it.Expect(now, rule, c.Config)
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "%s · %s: %s\n", it.ID, it.Title, it.Status)
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
	fmt.Fprintf(c.Out, "%s\n", textfmt.Count(len(items), "item", "items"))
	if secrets > 0 {
		fmt.Fprintf(c.Out, "Plus %s to rotate: segurata rotations list (or --kind rotate).\n", textfmt.Count(secrets, "secret", "secrets"))
	}
	return 0
}

func (c CLI) show(t *Tracker, args []string, now time.Time) int {
	if len(args) != 1 {
		fmt.Fprintln(c.Err, "usage: segurata track show <id>")
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
	if it.MergedInto != "" {
		fmt.Fprintf(w, " into %s", it.MergedInto)
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
		if it.Active(now) {
			for _, l := range t.Leverage(it, now) {
				fmt.Fprintf(w, "  if:      %s\n", l)
			}
		}
		for _, r := range t.Rules {
			if r.Decision == it.ID {
				fmt.Fprintf(w, "rule:      %s at every sync (since %s)\n", r.Spec(), r.At.Format(time.DateOnly))
			}
		}
	}
	if n := it.Next; n != nil {
		fmt.Fprintf(w, "\nnext (%s): %s\n", n.Who, n.Action)
		if n.Command != "" && n.Command != "segurata track show "+it.ID {
			fmt.Fprintf(w, "  $ %s\n", n.Command)
		}
		if n.URL != "" {
			fmt.Fprintf(w, "  %s\n", n.URL)
		}
	}
	if s := it.Secret; s != nil {
		fmt.Fprintf(w, "\nsecret %s %s/%s %s, %s, owner %s; details: segurata rotations show %s\n", s.ID, s.Service, s.Type, textfmt.OrDash(s.Redacted),
			textfmt.Count(len(s.Locations), "location", "locations"), textfmt.OrDash(string(it.Owner())), s.ID)
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
	var ignoreScopes, acceptScopes multi
	fs.Var(&ignoreScopes, "ignore-scope", "decide: ignore every item in this scope, now and at every sync (repeat for each)")
	fs.Var(&acceptScopes, "accept-scope", "decide: accept every item in this scope, now and at every sync (repeat for each)")
	owner := fs.String("owner", "", "decide: the scopes' rules close only secrets attributed to these owners: mine, not-mine, unknown (comma-separated)")
	dry := fs.Bool("dry-run", false, "decide: print what answering would close and keep open, change nothing")
	pos, err := cliflag.Parse(fs, args)
	want := 1 // note takes the id and any number of words
	if cmd == "prioritize" {
		want = 2
	}
	if err != nil || len(pos) < 1 || (cmd != "note" && len(pos) != want) {
		fmt.Fprintf(c.Err, "usage: segurata track %s <id> (see: segurata track)\n", cmd)
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
		var owners []attribution.Owner
		if *owner != "" {
			if owners, err = attribution.ParseOwners(*owner); err != nil {
				return c.fail(err)
			}
		}
		if *dry {
			lines, err := t.PreviewDecision(it, now, *answer, ignoreScopes, acceptScopes, owners)
			if err != nil {
				return c.fail(err)
			}
			for _, l := range lines {
				fmt.Fprintf(c.Out, "Answering %s\n", l)
			}
			if len(lines) == 0 {
				fmt.Fprintln(c.Out, "This answer adds no rule.")
			}
			fmt.Fprintln(c.Out, "Nothing written (--dry-run).")
			return 0
		}
		var added []Rule
		var closed int
		if added, closed, err = t.DecideWithEffects(it, now, *answer, ignoreScopes, acceptScopes, owners); err == nil && len(added) > 0 {
			for _, r := range added {
				fmt.Fprintf(c.Out, "Rule: %s, at every sync.\n", r.Spec())
			}
			fmt.Fprintf(c.Out, "%s closed now by this decision.\n", textfmt.Count(closed, "item", "items"))
		}
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
		if n := t.DropRules(it.ID); n > 0 {
			fmt.Fprintf(c.Out, "%s of this decision removed; the items they closed stay as they are.\n", textfmt.Count(n, "rule", "rules"))
		}
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
	fs.Var(&options, "option", `decide: one possible answer, optionally with its effect: "yes=ignore:path:~/src/old" (repeat for each)`)
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
		var labels []string
		var effects []OptionEffect
		for _, o := range options {
			label, eff, err := ParseOption(o)
			if err != nil {
				return c.fail(err)
			}
			labels = append(labels, label)
			if eff != nil {
				effects = append(effects, *eff)
			}
		}
		it = t.AddDecision(fmt.Sprintf("manual:%d", t.NextID), *question, labels, now)
		it.Decision.Effects = effects
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
// tracker (mode 0600). It is read-only unless asked: an unfiltered status with --mark-seen (or
// --write, which implies it) remembers when it ran, for "Since the last status".
func (c CLI) Status(args []string) int {
	fs := flags("status", c.Err)
	theme := fs.String("theme", "", "comma-separated themes")
	kind := fs.String("kind", "", "comma-separated kinds")
	prio := fs.String("priority", "", "comma-separated priorities, e.g. P0,P1")
	format := fs.String("format", string(doc.Text), "text, md or html")
	write := fs.Bool("write", false, "also write status.md and status.html next to the tracker (mode 0600); implies --mark-seen")
	markSeen := fs.Bool("mark-seen", false, "remember this status as the start of the next \"Since the last status\" (unfiltered only)")
	explain := fs.Bool("explain", false, "show the score of each \"Do next\" entry and the factors it is made of")
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
	v := View{Filter: f, Explain: *explain, Browser: c.Browser}
	if c.Instances != nil {
		v.Instances = c.Instances()
	}
	d := t.Status(path, now, v)
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
	if (*markSeen || *write) && f.empty() {
		at := now.UTC()
		t.LastStatusAt = &at
		if err := t.Save(path); err != nil {
			return c.fail(err)
		}
	}
	return 0
}
