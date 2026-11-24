// securizame inventories a personal digital footprint. See docs/arquitectura.md.
//
//	securizame connectors                     list built-in and external connectors
//	securizame inventory [name|name:label ...] run connectors (all when none given)
//	    --min-severity=low  --out=out  --verbose
//	securizame remediate --list               automatable findings of the latest run
//	securizame remediate <finding-id>         show the plan; --apply [--yes] to apply it
//	securizame rotations sync|list|next|show|replace|done|snooze|ignore|reopen   ledger of secrets to rotate
//	securizame accept <finding-id> --reason text [--until YYYY-MM-DD]   keep a risk on purpose
//	securizame accept --list | securizame unaccept <finding-id>
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

	_ "github.com/segurata/segurata/connectors" // registers built-in connectors
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "connectors":
		for _, c := range all() {
			d := c.Describe()
			kind := "built-in"
			if e, ok := c.(*connector.External); ok {
				kind = e.Path
			}
			fmt.Printf("%-16s %-8s %s  [needs: %s] (%s)\n", d.Name, d.Version, d.Summary, strings.Join(d.Needs, ", "), kind)
		}
	case "inventory":
		os.Exit(inventory(os.Args[2:]))
	case "remediate":
		os.Exit(remediateCmd(os.Args[2:]))
	case "rotations":
		os.Exit(rotationsCmd(os.Args[2:]))
	case "accept":
		os.Exit(acceptCLI().Accept(os.Args[2:]))
	case "unaccept":
		os.Exit(acceptCLI().Unaccept(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: securizame connectors | securizame inventory [--min-severity=low] [--out=out] [--verbose] [name ...] | securizame remediate --list | <finding-id> [--apply] [--yes] | securizame rotations <sync|list|next|show|replace|done|snooze|ignore|reopen> | securizame accept <finding-id> --reason text [--until YYYY-MM-DD] | --list | securizame unaccept <finding-id>")
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
	return 0
}
