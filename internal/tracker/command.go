package tracker

import (
	"bytes"
	"encoding/json"
	"errors"
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
             prints what answering would close and keep open, and changes nothing; answering again
             replaces the previous answer and its rules
  snooze     <id> --until YYYY-MM-DD [--note text]
  ignore     <id> --reason text
  expect     <setup-id> --reason text [--detail text] [--dry-run]   write a config rule that expects its status, close it
  reopen     <id> [--note text]
  prioritize <id> P0|P1|P2|P3|auto [--reason text]
  add        --title text [--kind fix|decide|setup|review] [--theme t] [--priority P2] [--note text]
             --kind decide --question text --option a --option "b=ignore:path:~/src/old"   (an option's effect applies when it is the answer;
             "b=ignore@not-mine:path:~/src/old" closes only secrets attributed not-mine)
  sync       [--out out] [--from <run-file>] [--include-noise]
<id> is T-0012 (or T-12), or a secret's short id. done, snooze, ignore and reopen take --path <prefix>
instead of an id: every item (open, or closed for reopen) whose locations all lie under that path,
e.g. a test log full of fixtures.`

const statusUsage = "usage: segurata status [--theme t] [--kind k] [--priority P0,P1] [--format text|md|html] [--explain] [--write] [--mark-seen]"

// CLI is `segurata track` and `segurata status`.
type CLI struct {
	Out, Err io.Writer
	Paths    Paths  // zero means DefaultPaths
	Config   string // config file with the expected rules; "" for none
	Now      func() time.Time
	// Instances lists the configured connector instances for status's coverage line.
	Instances func() []string
	// Browser names the connectors that drive the browser.
	Browser func(connector string) bool

	rotations string // `segurata rotations` usage when it runs the verb; "" for track
}

var (
	trackVerbs = []string{"list", "show", "add", "sync", "start", "done", "note", "decide", "snooze", "ignore", "reopen", "prioritize", "expect"}
	// RotationVerbs are the track verbs `segurata rotations` runs as its own.
	RotationVerbs = []string{"sync", "done", "snooze", "ignore", "reopen", "owner"}
	pathVerbs     = []string{"done", "snooze", "ignore", "reopen"}
)

// Rotations runs one of RotationVerbs as `segurata rotations`: ids and --path name secrets only,
// and sync refuses to save without a local-secrets run.
func (c CLI) Rotations(args []string, usage string) int {
	c.rotations = usage
	return c.Track(args)
}

func (c CLI) name() string {
	if c.rotations != "" {
		return "rotations"
	}
	return "track"
}

func (c CLI) usage() string {
	if c.rotations != "" {
		return c.rotations
	}
	return trackUsage
}

func (c CLI) find(t *Tracker, ref string) (*Item, error) {
	if c.rotations != "" {
		return t.FindRotate(ref)
	}
	return t.find(ref)
}

func (c CLI) fail(err error) int { return textfmt.Fail(c.Err, c.name(), err) }

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

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
	verbs := trackVerbs
	if c.rotations != "" {
		verbs = RotationVerbs
	}
	if len(args) == 0 || !slices.Contains(verbs, args[0]) {
		fmt.Fprintln(c.Err, c.usage())
		return 2
	}
	cmd, rest := args[0], args[1:]
	now := c.Now()
	t, path, unlock, err := LoadFor(c.Paths, now, cmd != "list" && cmd != "show")
	defer unlock()
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
	fs := cliflag.New(c.name()+" sync", c.Err)
	out := fs.String("out", config.DefaultOutDir(), "inventory output directory")
	from := fs.String("from", "", "local-secrets JSONL to read instead of its latest run")
	noise := fs.Bool("include-noise", false, "also track noise-only secrets, without a priority")
	if pos, err := cliflag.Parse(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(c.Err, c.usage())
		return 2
	}
	opt, err := ConfiguredSync(c.Config, SyncOptions{OutDir: *out, From: *from, IncludeNoise: *noise})
	if err != nil {
		return c.fail(err)
	}
	var require func(SyncReport) error
	if c.rotations != "" {
		require = func(rep SyncReport) error {
			if !rep.foldedSecrets() {
				return fmt.Errorf("no %s output under %s: run `segurata inventory %s` first", secretrisk.ConnectorName, *out, secretrisk.ConnectorName)
			}
			return nil
		}
	}
	t, rep, err := syncAndSave(t, path, opt, now, require)
	if err != nil {
		return c.fail(err)
	}
	if rep.foldedSecrets() {
		t.secretsSynced(c.Out, rep, path, now)
	}
	fmt.Fprint(c.Out, syncLine(rep))
	return 0
}

func (t *Tracker) secretsSynced(w io.Writer, rep SyncReport, path string, now time.Time) {
	r := rep.Secrets
	fmt.Fprintf(w, "Synced: %d secrets (%d new, %d updated, %d reopened because a working file still holds the old value, %d snoozes expired); %d reclassified as noise, %d noise-only skipped, %d AWS key ids folded into their secret key.\n",
		r.Secrets, r.Created, r.Updated, r.Reopened, rep.Woken, r.Reclassified, r.Skipped, r.Paired)
	if r.HistoryOnly > 0 {
		fmt.Fprintf(w, "%d rotated %s seen again only in history, transcripts or logs: left rotated (%s).\n",
			r.HistoryOnly, textfmt.Plural(r.HistoryOnly, "secret", "secrets"), historyOnly)
	}
	counts := map[secretrisk.Priority]int{}
	for _, it := range t.Items {
		if it.Kind == KindRotate && it.Active(now) {
			counts[it.EffectivePriority()]++
		}
	}
	fmt.Fprintf(w, "Open: P0 %d, P1 %d, P2 %d, P3 %d. Tracker: %s\n", counts[secretrisk.P0], counts[secretrisk.P1], counts[secretrisk.P2], counts[secretrisk.P3], path)
	owners := t.ownerCounts(func(it *Item) bool { return it.Active(now) })
	fmt.Fprintf(w, "Open by owner: mine %d, not-mine %d, unknown %d (segurata rotations list --owner not-mine).\n",
		owners[attribution.Mine], owners[attribution.NotMine], owners[attribution.Unknown])
}

// syncAndSave folds the runs into t and saves it, unless require rejects the report. When
// tracker.json changed without the lock (an edit, an older binary), it folds the same runs once
// more into that version rather than fail a scheduled sync or drop the change.
func syncAndSave(t *Tracker, path string, opt SyncOptions, now time.Time, require func(SyncReport) error) (*Tracker, SyncReport, error) {
	for again := false; ; again = true {
		rep, err := t.Sync(opt, now)
		if err == nil && require != nil {
			err = require(rep)
		}
		if err != nil {
			return t, rep, err
		}
		if err = t.Save(path); again || !errors.Is(err, errChanged) {
			return t, rep, err
		}
		if t, err = Load(path); err != nil {
			return t, rep, err
		}
	}
}

// expect writes the config rule that expects a setup item's status and closes the item.
func (c CLI) expect(t *Tracker, path string, args []string, now time.Time) int {
	fs := cliflag.New("track expect", c.Err)
	reason := fs.String("reason", "", "why this status is expected")
	detail := fs.String("detail", "", "only statuses whose detail contains this text (or matches /regexp/)")
	dry := fs.Bool("dry-run", false, "print the rule and change nothing")
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprintln(c.Err, "usage: segurata track expect <setup-item-id> --reason text [--detail text] [--dry-run]")
		return 2
	}
	it, err := t.find(pos[0])
	if err != nil {
		return c.fail(err)
	}
	key, rule, err := it.expectRule(*reason, *detail)
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
	it.expect(now, rule, c.Config)
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "%s · %s: %s\n", it.ID, it.Title, it.Status)
	return 0
}

func (c CLI) list(t *Tracker, args []string, now time.Time) int {
	fs := cliflag.New("track list", c.Err)
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
	it, err := t.find(args[0])
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
	fmt.Fprintf(w, "\nkind:      %s\ntheme:     %s\nseverity:  %s\nkey:       %s\ncreated:   %s\n", it.Kind, t.themeTitle(it.Theme),
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
			for _, l := range t.optionLeverage(it, now) {
				fmt.Fprintf(w, "  if:      %s\n", l)
			}
		}
		for _, r := range t.Rules {
			if r.Decision == it.ID {
				fmt.Fprintf(w, "rule:      %s at every sync (since %s)\n", r.spec(), r.At.Format(time.DateOnly))
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
		textfmt.Line(w, "  %s  %-9s %-18s %s", e.At.Format(time.RFC3339), e.Event, e.Action, e.Detail)
	}
	return 0
}

func (c CLI) change(t *Tracker, path, cmd string, args []string, now time.Time) int {
	fs := cliflag.New(c.name()+" "+cmd, c.Err)
	note := fs.String("note", "", "free text kept in the history")
	until := fs.String("until", "", "snooze: date the item comes back, YYYY-MM-DD")
	reason := fs.String("reason", "", "ignore, prioritize, owner: why")
	answer := fs.String("answer", "", "decide: the answer")
	var ignoreScopes, acceptScopes multi
	fs.Var(&ignoreScopes, "ignore-scope", "decide: ignore every item in this scope, now and at every sync (repeat for each)")
	fs.Var(&acceptScopes, "accept-scope", "decide: accept every item in this scope, now and at every sync (repeat for each)")
	owner := fs.String("owner", "", "decide: the scopes' rules close only secrets attributed to these owners: mine, not-mine, unknown (comma-separated)")
	dry := fs.Bool("dry-run", false, "decide: print what answering would close and keep open, change nothing")
	under := new(string)
	byPath := slices.Contains(pathVerbs, cmd)
	if byPath {
		under = fs.String("path", "", "instead of an id: every item whose locations all lie under this path")
	}
	pos, err := cliflag.Parse(fs, args)
	want := 1 // note takes the id and any number of words
	switch {
	case cmd == "prioritize" || cmd == "owner":
		want = 2
	case *under != "":
		want = 0
	}
	if err != nil || (cmd == "note" && len(pos) < 1) || (cmd != "note" && len(pos) != want) {
		form := "<id>"
		if byPath {
			form += " | --path <prefix>"
		}
		fmt.Fprintf(c.Err, "usage: segurata %s %s %s (see: segurata %s)\n", c.name(), cmd, form, c.name())
		return 2
	}
	var items []*Item
	if *under != "" {
		if items = c.itemsUnder(t, *under, cmd == "reopen", now); len(items) == 0 {
			return c.fail(fmt.Errorf("no %s item lies entirely under %s", map[bool]string{true: "closed", false: "open"}[cmd == "reopen"], *under))
		}
	} else {
		it, err := c.find(t, pos[0])
		if err != nil {
			return c.fail(err)
		}
		items = []*Item{it}
	}
	for _, it := range items {
		switch cmd {
		case "start":
			err = it.start(now, *note)
		case "done":
			it.Done(now, *note)
		case "note":
			err = it.Note(now, strings.Join(pos[1:], " "))
		case "decide":
			if *dry {
				return c.previewDecision(t, it, now, *answer, ignoreScopes, acceptScopes, *owner)
			}
			err = c.decide(t, it, now, *answer, ignoreScopes, acceptScopes, *owner)
		case "snooze":
			err = it.snooze(now, *until, *note)
		case "ignore":
			r := strings.TrimSpace(*reason)
			if r != "" && *note != "" {
				r += "; " + *note
			}
			err = it.ignore(now, r)
		case "reopen":
			it.reopen(now, *note)
			if n := t.dropRules(it.ID); n > 0 {
				fmt.Fprintf(c.Out, "%s of this decision removed; the items they closed stay as they are.\n", textfmt.Count(n, "rule", "rules"))
			}
		case "prioritize":
			var p secretrisk.Priority
			if p, err = parsePriority(pos[1]); err == nil {
				err = it.prioritize(now, p, *reason)
			}
		case "owner":
			err = c.setOwner(t, it, now, pos[1], *reason)
		}
		if err != nil {
			return c.fail(err) // nothing saved: a bad flag fails before the first item changes
		}
	}
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	for _, it := range items {
		if s := it.Secret; s != nil {
			status := it.RotationStatus()
			if cmd == "owner" {
				status = fmt.Sprintf("owner %s, %s", it.Owner(), status)
			}
			fmt.Fprintf(c.Out, "%s %s/%s %s: %s\n", s.ID, s.Service, s.Type, textfmt.OrDash(s.Redacted), status)
		} else {
			fmt.Fprintf(c.Out, "%s %s · %s: %s\n", it.ID, textfmt.OrDash(string(it.EffectivePriority())), it.Title, it.Status)
		}
	}
	if len(items) > 1 {
		fmt.Fprintf(c.Out, "%d items\n", len(items))
	}
	return 0
}

// setOwner sets the owner's verdict on one secret, then applies the decisions' rules as a sync
// would, so a rule narrowed to owners closes or reopens it now.
func (c CLI) setOwner(t *Tracker, it *Item, now time.Time, owner, reason string) error {
	o := attribution.Owner(strings.ToLower(strings.TrimSpace(owner)))
	opt, err := ConfiguredSync(c.Config, SyncOptions{})
	if err != nil {
		return err
	}
	if err := t.setOwner(it, now, o, reason, opt.Owned); err != nil {
		return err
	}
	t.applyRules(now)
	return nil
}

// itemsUnder returns the active (or, with closed, the closed) items that lie entirely under prefix;
// secrets only for rotations.
func (c CLI) itemsUnder(t *Tracker, prefix string, closed bool, now time.Time) []*Item {
	var out []*Item
	for _, it := range t.Items {
		if (c.rotations == "" || it.Kind == KindRotate) && it.Active(now) != closed && it.liesUnder(prefix) {
			out = append(out, it)
		}
	}
	Sort(out)
	return out
}

func parseOwners(s string) ([]attribution.Owner, error) {
	if s == "" {
		return nil, nil
	}
	return attribution.ParseOwners(s)
}

func (c CLI) previewDecision(t *Tracker, it *Item, now time.Time, answer string, ignore, accept []string, owner string) int {
	owners, err := parseOwners(owner)
	if err != nil {
		return c.fail(err)
	}
	lines, err := t.previewDecision(it, now, answer, ignore, accept, owners)
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

func (c CLI) decide(t *Tracker, it *Item, now time.Time, answer string, ignore, accept []string, owner string) error {
	owners, err := parseOwners(owner)
	if err != nil {
		return err
	}
	again := it.Decision != nil && it.Decision.Answer != ""
	added, closed, err := t.decideWithEffects(it, now, answer, ignore, accept, owners)
	if err != nil {
		return err
	}
	if again {
		fmt.Fprintf(c.Out, "This answer %s.\n", it.lastDetail(actReanswer))
	}
	if len(added) > 0 {
		for _, r := range added {
			fmt.Fprintf(c.Out, "Rule: %s, at every sync.\n", r.spec())
		}
		fmt.Fprintf(c.Out, "%s closed now by this decision.\n", textfmt.Count(closed, "item", "items"))
	}
	return nil
}

func (c CLI) add(t *Tracker, path string, args []string, now time.Time) int {
	fs := cliflag.New("track add", c.Err)
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
	p, err := parsePriority(*prio)
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
			label, eff, err := parseOption(o)
			if err != nil {
				return c.fail(err)
			}
			labels = append(labels, label)
			if eff != nil {
				effects = append(effects, *eff)
			}
		}
		it = t.addDecision(fmt.Sprintf("manual:%d", t.NextID), *question, labels, now)
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

// Status prints the briefing, with --write also as status.md and status.html next to the tracker.
// It is read-only except that an unfiltered --mark-seen or --write records when it ran.
func (c CLI) Status(args []string) int {
	fs := cliflag.New("status", c.Err)
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
	t, path, _, err := LoadFor(c.Paths, now, false)
	if err != nil {
		return c.fail(err)
	}
	f := newFilter(*theme, *kind, *prio)
	v := View{Filter: f, Explain: *explain, Browser: c.Browser}
	if c.Instances != nil {
		v.Instances = c.Instances()
	}
	d := t.status(path, now, v)
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
		if err := Update(path, now, func(t *Tracker) error { t.LastStatusAt = &at; return nil }); err != nil {
			return c.fail(err)
		}
	}
	return 0
}
