// segurata inventories a personal digital footprint; docs/architecture.md, "Verbs", says what each
// command changes.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/version"

	_ "github.com/segurata/segurata/connectors" // registers built-in connectors
)

// commands is the only list of verbs: dispatch, usage and the docs test read it.
type command struct {
	name, args, summary string
	run                 func(args []string) int
}

var commands = []command{
	{"connectors", "", "list built-in and external connectors", connectorsCmd},
	{"inventory", "[name|name:label ...] [--min-severity=low] [--out=out] [--verbose]", "run connectors (all when none given)", inventory},
	{"status", "[--theme t] [--kind k] [--priority P0,P1] [--format text|md|html] [--write]", "the briefing",
		func(args []string) int { return trackerCLI().Status(args) }},
	{"track", "list|show|start|done|note|decide|snooze|ignore|reopen|prioritize|expect|add|sync", "tracker items",
		func(args []string) int { return trackerCLI().Track(args) }},
	{"report", "[--format text|md|html] [--out file]", "latest runs, changes, secrets, accepted risks", reportCmd},
	{"remediate", "--list | <finding-id> [--apply] [--yes]", "automatable findings of the latest run; the plan, applied with --apply", remediateCmd},
	{"rotations", "list|next|show|replace|sync|done|snooze|ignore|reopen", "ledger of secrets to rotate; sync, done, snooze, ignore and reopen are track's, on secrets", rotationsCmd},
	{"accounts", "list|watch|unwatch|owned", "accounts each connector saw and watches; the owner's accounts", accountsCmd},
	{"signin", "[name|name:label ...] [--all] [--list] [--timeout 10m]", "open the pages where you sign in again, wait, rerun", signinCmd},
	{"redact", "--trails|--path p|--item id [--apply [--yes]]", "replace secrets in trail files", redactCmd},
	{"accept", "<finding-id> --reason text [--until YYYY-MM-DD] | --list", "keep a risk on purpose",
		func(args []string) int { return acceptCLI().Accept(args) }},
	{"unaccept", "<finding-id>", "stop keeping it", func(args []string) int { return acceptCLI().Unaccept(args) }},
	{"schedule", "install|uninstall|status [--every 24h] [--connectors a,b] [--apply]", "scheduled runs", scheduleCmd},
	{"doctor", "[--connector name] [--out out]", "check prerequisites, read-only", doctorCmd},
	{"version", "", "version, commit and build date", versionCmd},
}

func main() {
	if len(os.Args) >= 2 {
		for _, c := range commands {
			if c.name == os.Args[1] {
				os.Exit(c.run(os.Args[2:]))
			}
		}
	}
	usage()
	os.Exit(2)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %s\n      %s\n", strings.TrimSpace("segurata "+c.name+" "+c.args), c.summary)
	}
}

func versionCmd([]string) int {
	fmt.Println(version.Get())
	return 0
}

func connectorsCmd([]string) int {
	for _, c := range all() {
		d := c.Describe()
		kind := "built-in"
		if e, ok := c.(*connector.External); ok {
			kind = e.Path
		}
		remediates := ""
		if len(d.Remediates) > 0 {
			remediates = " [remediates: " + strings.Join(d.Remediates, ", ") + "]"
		}
		fmt.Printf("%-16s %-8s %s  [needs: %s]%s (%s)\n", d.Name, d.Version, d.Summary, strings.Join(d.Needs, ", "), remediates, kind)
	}
	return 0
}

// all is every connector, discovered once per process: discovery runs each plugin's describe.
var all = sync.OnceValue(discover)

func discover() []connector.Connector {
	conns := connector.Builtins()
	for _, e := range connector.Discover() {
		conns = append(conns, e)
	}
	return conns
}

func inventory(args []string) int {
	fs := cliflag.New("inventory", os.Stderr)
	minSev := fs.String("min-severity", "low", "hide findings below this severity in the summary")
	out := fs.String("out", config.DefaultOutDir(), "output directory")
	verbose := fs.Bool("verbose", false, "show connector logs")
	selectors, err := cliflag.Parse(fs, args)
	if err != nil {
		return 2
	}

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	targets, err := run.Targets(cfg, all(), selectors)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	l, err := lent(cfg.Owned)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tracker:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var logw io.Writer
	if *verbose {
		logw = os.Stderr
	}
	results, err := run.Inventory(ctx, cfg, targets, *out, logw, l)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	run.Summary(os.Stdout, results, finding.Severity(*minSev))
	fmt.Println()
	return trackerCLI().Track([]string{"sync", "--out", *out})
}
