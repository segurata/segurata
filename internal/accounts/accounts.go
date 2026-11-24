// Package accounts is `segurata accounts`: which accounts each connector saw and whether the
// config watches them (list), adding or removing one from connectors.<x>.config.accounts (watch,
// unwatch), and the owner's accounts attribution compares secrets with (owned). See README,
// "Accounts", and docs/architecture.md, "Attribution".
package accounts

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/tracker"
)

// Watchable are the connectors whose config takes an accounts list; an account the list leaves
// out is declared a skipped scope (docs/connectors.md, "Coverage").
var Watchable = []string{"gcp", "google-personal"}

const usage = `usage: segurata accounts <command>
  list    [connector[:label]] [--out out]   accounts each connector saw, watched or not, and when (default: gcp, google-personal)
  watch   <connector[:label]> <account> [--out out]   add it to connectors.<x>.config.accounts, reopen its setup items
  unwatch <connector[:label]> <account> [--out out]   take it out (writing the list from the accounts seen when there is none), close its setup items
  owned   [--out out]   the owner's accounts attribution compares secrets with, and where each comes from
watch and unwatch rewrite the config atomically (mode 0600) and keep the previous file as config.json.segurata-bak-<time>.`

// CLI is the `segurata accounts` command family.
type CLI struct {
	Out, Err io.Writer
	Config   string        // config file
	Paths    tracker.Paths // zero means tracker.DefaultPaths
	Now      func() time.Time
	// Email is the owner's commit email by default (attribution.GitEmail); nil for none.
	Email func() string
}

func (c CLI) fail(err error) int {
	fmt.Fprintln(c.Err, "accounts:", err)
	return 1
}

// Run executes one subcommand and returns the exit code.
func (c CLI) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet("accounts "+cmd, flag.ContinueOnError)
	fs.SetOutput(c.Err)
	out := fs.String("out", "out", "inventory output directory")
	pos, err := cliflag.Parse(fs, rest)
	if err != nil {
		return 2
	}
	switch {
	case cmd == "list" && len(pos) <= 1:
		return c.list(*out, pos)
	case (cmd == "watch" || cmd == "unwatch") && len(pos) == 2:
		return c.watch(*out, pos[0], pos[1], cmd == "watch")
	case cmd == "owned" && len(pos) == 0:
		return c.owned(*out)
	}
	fmt.Fprintln(c.Err, usage)
	return 2
}

// Seen is one account a connector instance reported.
type Seen struct {
	Account  string
	State    string // the state of its latest status, or "skipped: <reason>" when declared skipped
	LastSeen time.Time
	// Skipped is true when the latest run that names it declared it skipped (not watched).
	Skipped bool
}

// SeenAccounts reads every run of the connector instance lbl under out: the accounts its statuses
// name and those its run_end declares skipped because the config's accounts list leaves them out,
// each with what the latest run naming it said.
func SeenAccounts(out, lbl string) ([]Seen, error) {
	history, err := remediate.History(out)
	if err != nil {
		return nil, err
	}
	by := map[string]*Seen{}
	for _, file := range history[strings.ReplaceAll(lbl, ":", "-")+".jsonl"] {
		rf, err := remediate.ReadRun(file)
		if err != nil {
			return nil, err
		}
		at := runTime(file, rf)
		note := func(account, state string, skipped bool) {
			if account == "" || account == finding.ScopeAll {
				return
			}
			key := strings.ToLower(account)
			if s, ok := by[key]; ok && s.LastSeen.After(at) {
				return
			}
			by[key] = &Seen{Account: account, State: state, LastSeen: at, Skipped: skipped}
		}
		for _, st := range rf.Statuses {
			if st.Scope == "" { // a status for one project or service says nothing about the account
				note(st.Account, string(st.State), false)
			}
		}
		if rf.End != nil {
			for _, sk := range rf.End.Scopes.Skipped {
				if strings.Contains(sk.Reason, "config.accounts") {
					note(sk.Scope, "skipped: "+sk.Reason, true)
				}
			}
		}
	}
	list := make([]Seen, 0, len(by))
	for _, s := range by {
		list = append(list, *s)
	}
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Account) < strings.ToLower(list[j].Account) })
	return list, nil
}

// runTime is when a run ended, or the file's modification time for a run without run_end.
func runTime(file string, rf remediate.RunFile) time.Time {
	if rf.End != nil && !rf.End.EndedAt.IsZero() {
		return rf.End.EndedAt
	}
	if st, err := os.Stat(file); err == nil {
		return st.ModTime().UTC()
	}
	return time.Time{}
}

func (c CLI) loadConfig() (config.Config, error) {
	if c.Config == "" {
		return config.Config{}, errors.New("no config file")
	}
	return config.Load(c.Config)
}

// labels are the instances to list: the one named, or every configured (or default) instance of
// the watchable connectors.
func labels(cfg config.Config, named []string) []string {
	if len(named) == 1 {
		return named
	}
	var out []string
	for _, name := range Watchable {
		for _, in := range cfg.Instances(name) {
			lbl := name
			if in.Label != "" {
				lbl += ":" + in.Label
			}
			out = append(out, lbl)
		}
	}
	return out
}

func (c CLI) list(out string, named []string) int {
	cfg, err := c.loadConfig()
	if err != nil {
		return c.fail(err)
	}
	for i, lbl := range labels(cfg, named) {
		seen, err := SeenAccounts(out, lbl)
		if err != nil {
			return c.fail(err)
		}
		if i > 0 {
			fmt.Fprintln(c.Out)
		}
		list, set := cfg.Accounts(lbl)
		switch {
		case !watchable(lbl):
			fmt.Fprintf(c.Out, "%s (no accounts list in its config: every account it reaches is inspected)\n", lbl)
		case set:
			fmt.Fprintf(c.Out, "%s (connectors.%q.config.accounts: %d watched)\n", lbl, lbl, len(list))
		default:
			fmt.Fprintf(c.Out, "%s (no accounts list: every account is watched)\n", lbl)
		}
		tw := tabwriter.NewWriter(c.Out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ACCOUNT\tWATCHED\tLAST STATE\tLAST SEEN")
		listed := map[string]bool{}
		for _, s := range seen {
			listed[strings.ToLower(s.Account)] = true
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Account, yesNo(!set || containsFold(list, s.Account)), s.State, s.LastSeen.Local().Format("2006-01-02 15:04"))
		}
		for _, a := range list {
			if !listed[strings.ToLower(a)] {
				fmt.Fprintf(tw, "%s\tyes\tnever seen\t-\n", a)
			}
		}
		tw.Flush()
	}
	return 0
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func containsFold(list []string, v string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, v) })
}

func watchable(lbl string) bool {
	name, _, _ := strings.Cut(lbl, ":")
	return slices.Contains(Watchable, name)
}

// unwatchedReason is the reason unwatch closes an account's setup items with; watch reopens the
// items closed with it.
func unwatchedReason(lbl string) string {
	return fmt.Sprintf("not watched: taken out of connectors.%q.config.accounts by segurata accounts unwatch", lbl)
}

// watch adds an account to the instance's accounts list or takes it out, and moves its setup items.
func (c CLI) watch(out, lbl, account string, on bool) int {
	if !watchable(lbl) {
		return c.fail(fmt.Errorf("%s has no accounts list in its config (watchable: %s)", lbl, strings.Join(Watchable, ", ")))
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return c.fail(err)
	}
	list, set := cfg.Accounts(lbl)
	var next []string
	switch {
	case on && !set:
		fmt.Fprintf(c.Out, "%s: already watched (no accounts list: every account is).\n", account)
		return c.moveSetup(lbl, account, on)
	case on && containsFold(list, account):
		fmt.Fprintf(c.Out, "%s: already in connectors.%q.config.accounts.\n", account, lbl)
		return c.moveSetup(lbl, account, on)
	case on:
		next = append(slices.Clone(list), account)
	case set && !containsFold(list, account):
		fmt.Fprintf(c.Out, "%s: not in connectors.%q.config.accounts, so not watched already.\n", account, lbl)
		return c.moveSetup(lbl, account, on)
	case set:
		next = slices.DeleteFunc(slices.Clone(list), func(x string) bool { return strings.EqualFold(x, account) })
	default:
		// No list yet: every account seen is watched; the list is all of them but this one.
		seen, err := SeenAccounts(out, lbl)
		if err != nil {
			return c.fail(fmt.Errorf("no list to take %s out of, and no run to write one from: %w", account, err))
		}
		for _, s := range seen {
			// People's accounts only: not "authuser 1" placeholders, not service accounts.
			if !s.Skipped && !strings.EqualFold(s.Account, account) && strings.Contains(s.Account, "@") && !strings.HasSuffix(s.Account, ".iam.gserviceaccount.com") {
				next = append(next, s.Account)
			}
		}
	}
	if len(next) == 0 {
		return c.fail(fmt.Errorf("%s would leave connectors.%q.config.accounts empty; take the connector out of your runs instead", account, lbl))
	}
	changed, backup, err := config.SetAccounts(c.Config, lbl, next, c.Now())
	if err != nil {
		return c.fail(err)
	}
	if changed {
		fmt.Fprintf(c.Out, "connectors.%q.config.accounts in %s is now: %s\n", lbl, c.Config, strings.Join(next, ", "))
		if backup != "" {
			fmt.Fprintf(c.Out, "The previous config is kept as %s.\n", backup)
		}
	}
	return c.moveSetup(lbl, account, on)
}

// moveSetup reopens (watch) or closes (unwatch) the account's setup items in the tracker.
func (c CLI) moveSetup(lbl, account string, on bool) int {
	p, err := c.Paths.Resolve()
	if err != nil {
		return c.fail(err)
	}
	now := c.Now()
	t, err := tracker.LoadOrMigrate(p, now, c.Err)
	if err != nil {
		return c.fail(err)
	}
	var moved []*tracker.Item
	if on {
		moved = t.ReopenSetup(lbl, account, unwatchedReason(lbl), "watched again (segurata accounts watch)", now)
	} else {
		moved = t.CloseSetup(lbl, account, unwatchedReason(lbl), now)
	}
	if len(moved) == 0 {
		return 0
	}
	if err := t.Save(p.Tracker); err != nil {
		return c.fail(err)
	}
	for _, it := range moved {
		fmt.Fprintf(c.Out, "%s · %s: %s\n", it.ID, it.Title, it.Status)
	}
	if !on {
		fmt.Fprintf(c.Out, "The next %s run declares %s a skipped scope: its findings stay as they are, never taken as resolved.\n", lbl, account)
	}
	return 0
}

// owned prints the owner's accounts by kind, each with where it comes from: config `owned`, the
// tracker (discovered by earlier syncs), the latest runs, git.
func (c CLI) owned(out string) int {
	cfg, err := c.loadConfig()
	if err != nil {
		return c.fail(err)
	}
	p, err := c.Paths.Resolve()
	if err != nil {
		return c.fail(err)
	}
	t, err := tracker.LoadOrMigrate(p, c.Now(), c.Err)
	if err != nil {
		return c.fail(err)
	}
	type source struct {
		name  string
		owned attribution.Owned
	}
	sources := []source{{"config", cfg.Owned}}
	if t.Owned != nil {
		sources = append(sources, source{"tracker", *t.Owned})
	}
	if runs, err := latestOwned(out); err == nil {
		sources = append(sources, source{"runs in " + out, runs})
	} else {
		fmt.Fprintf(c.Err, "accounts: latest runs not read: %v\n", err)
	}
	if c.Email != nil {
		if e := c.Email(); e != "" {
			sources = append(sources, source{"git config user.email", attribution.Owned{Emails: []string{e}}})
		}
	}
	kinds := []struct {
		key string
		get func(attribution.Owned) []string
	}{
		{"aws_accounts", func(o attribution.Owned) []string { return o.AWSAccounts }},
		{"gcp_projects", func(o attribution.Owned) []string { return o.GCPProjects }},
		{"slack_teams", func(o attribution.Owned) []string { return o.SlackTeams }},
		{"github", func(o attribution.Owned) []string { return o.GitHub }},
		{"emails", func(o attribution.Owned) []string { return o.Emails }},
	}
	for _, k := range kinds {
		from := map[string][]string{}
		var order []string
		for _, s := range sources {
			for _, v := range k.get(s.owned) {
				key := strings.ToLower(v)
				if _, ok := from[key]; !ok {
					order = append(order, v)
				}
				from[key] = append(from[key], s.name)
			}
		}
		sort.Slice(order, func(i, j int) bool { return strings.ToLower(order[i]) < strings.ToLower(order[j]) })
		fmt.Fprintf(c.Out, "%s (%d):\n", k.key, len(order))
		if len(order) == 0 {
			fmt.Fprintf(c.Out, "  none known: set owned.%s in %s\n", k.key, c.Config)
		}
		for _, v := range order {
			fmt.Fprintf(c.Out, "  %s  (%s)\n", v, strings.Join(from[strings.ToLower(v)], ", "))
		}
	}
	return 0
}

// latestOwned is what attribution.Discover reads in the latest run of every connector instance
// that reports accounts (local-secrets reports none, and its runs are large).
func latestOwned(out string) (attribution.Owned, error) {
	files, err := remediate.LatestFiles(out)
	if err != nil {
		return attribution.Owned{}, err
	}
	var fs []finding.Finding
	var sts []finding.Status
	for _, f := range files {
		if strings.HasPrefix(filepath.Base(f), tracker.SecretsConnector) {
			continue
		}
		rf, err := remediate.ReadRun(f)
		if err != nil {
			return attribution.Owned{}, err
		}
		fs, sts = append(fs, rf.Findings...), append(sts, rf.Statuses...)
	}
	return attribution.Discover(fs, sts), nil
}
