// segurata inventories a personal digital footprint. See docs/architecture.md.
//
//	segurata connectors                     list built-in and external connectors
//	segurata inventory [name|name:label ...] run connectors (all when none given)
//	    --min-severity=low  --out=out  --verbose
//	segurata status [--theme t] [--kind k] [--priority P0,P1] [--format text|md|html] [--write]   the briefing
//	segurata track list|show|start|done|note|decide|snooze|ignore|reopen|prioritize|add|sync   tracker items
//	segurata report [--format text|md|html] [--out file]   latest runs, changes, secrets, accepted risks
//	segurata remediate --list               automatable findings of the latest run
//	segurata remediate <finding-id>         show the plan; --apply [--yes] to apply it
//	segurata rotations sync|list|next|show|replace|done|snooze|ignore|reopen   ledger of secrets to rotate
//	segurata redact --trails|--path p|--item id   replace secrets in trail files; --apply [--yes] to rewrite
//	segurata accept <finding-id> --reason text [--until YYYY-MM-DD]   keep a risk on purpose
//	segurata accept --list | segurata unaccept <finding-id>
//	segurata schedule install|uninstall|status [--every 24h] [--connectors a,b] [--apply]   scheduled runs
//	segurata doctor [--connector name]      check prerequisites, read-only
//	segurata keychain-migrate [--apply]     move Keychain items to their segurata-* names (internal/legacy)
//	segurata version                        version, commit and build date
//
// Every command except version first moves a machine set up under the former name to the current layout (see
// internal/legacy).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/version"

	_ "github.com/segurata/segurata/connectors" // registers built-in connectors
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if os.Args[1] == "version" {
		fmt.Println(version.Get())
		return
	}
	migrateLegacy()
	switch os.Args[1] {
	case "connectors":
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
	case "inventory":
		os.Exit(inventory(os.Args[2:]))
	case "status":
		os.Exit(trackerCLI().Status(os.Args[2:]))
	case "track":
		os.Exit(trackerCLI().Track(os.Args[2:]))
	case "report":
		os.Exit(reportCmd(os.Args[2:]))
	case "remediate":
		os.Exit(remediateCmd(os.Args[2:]))
	case "rotations":
		os.Exit(rotationsCmd(os.Args[2:]))
	case "redact":
		os.Exit(redactCmd(os.Args[2:]))
	case "accept":
		os.Exit(acceptCLI().Accept(os.Args[2:]))
	case "unaccept":
		os.Exit(acceptCLI().Unaccept(os.Args[2:]))
	case "schedule":
		os.Exit(scheduleCmd(os.Args[2:]))
	case "doctor":
		os.Exit(doctorCmd(os.Args[2:]))
	case "keychain-migrate":
		os.Exit(keychainMigrateCmd(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: segurata connectors | segurata inventory [--min-severity=low] [--out=out] [--verbose] [name ...] | segurata status [--theme t] [--kind k] [--priority P0,P1] [--format text|md|html] [--write] | segurata track <list|show|start|done|note|decide|snooze|ignore|reopen|prioritize|add|sync> | segurata report [--format text|md|html] [--out file] | segurata remediate --list | <finding-id> [--apply] [--yes] | segurata rotations <sync|list|next|show|replace|done|snooze|ignore|reopen> | segurata accept <finding-id> --reason text [--until YYYY-MM-DD] | --list | segurata unaccept <finding-id> | segurata schedule install|uninstall|status [--every 24h] [--connectors a,b] [--apply] | segurata redact [--trails] [--path prefix] [--item id] [--apply] | segurata doctor [--connector name] | segurata keychain-migrate [--apply [--yes]] | segurata version")
}

func all() []connector.Connector {
	conns := connector.Builtins()
	for _, e := range connector.Discover() {
		conns = append(conns, e)
	}
	return conns
}

func inventory(args []string) int {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	minSev := fs.String("min-severity", "low", "hide findings below this severity in the summary")
	out := fs.String("out", "out", "output directory")
	verbose := fs.Bool("verbose", false, "show connector logs")
	_ = fs.Parse(args)

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	targets, err := run.Targets(cfg, all(), fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	annotate, err := acceptedAnnotator()
	if err != nil {
		fmt.Fprintln(os.Stderr, "accepted risks:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var logw io.Writer
	if *verbose {
		logw = os.Stderr
	}
	results, err := run.Inventory(ctx, cfg, targets, *out, logw, annotate)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	run.Summary(os.Stdout, results, finding.Severity(*minSev))
	fmt.Println()
	return trackerCLI().Track([]string{"sync", "--out", *out})
}
