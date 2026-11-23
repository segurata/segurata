package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/run"
)

// remediateCmd is `securizame remediate --list | <finding-id> [--apply] [--yes]`. Without --apply
// it only prints the plan.
func remediateCmd(args []string) int {
	fs := flag.NewFlagSet("remediate", flag.ExitOnError)
	list := fs.Bool("list", false, "list the automatable findings of the latest run")
	apply := fs.Bool("apply", false, "apply the plan after confirmation (default: dry run)")
	yes := fs.Bool("yes", false, "with --apply, do not ask for confirmation")
	out := fs.String("out", "out", "output directory")
	_ = fs.Parse(args)
	id := ""
	if fs.NArg() > 0 { // flags may also follow the id
		id = fs.Arg(0)
		_ = fs.Parse(fs.Args()[1:])
	}
	if fs.NArg() > 0 || (id == "") == !*list {
		fmt.Fprintln(os.Stderr, "usage: securizame remediate --list | securizame remediate <finding-id> [--apply] [--yes]")
		return 2
	}

	dir, err := remediate.LatestDir(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	findings, err := remediate.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *list {
		fmt.Printf("Latest run: %s\n\n", dir)
		remediate.List(os.Stdout, findings)
		return 0
	}
	f, err := remediate.Find(findings, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	conns := all()
	r, err := remediate.For(f, conns)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	reinventory := func(ctx context.Context) ([]*run.Result, error) {
		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return nil, err
		}
		targets, err := run.Targets(cfg, conns, []string{remediate.Selector(f)})
		if err != nil {
			return nil, err
		}
		return run.Inventory(ctx, cfg, targets, *out, nil)
	}
	opt := remediate.Options{Apply: *apply, Yes: *yes, TTY: remediate.IsTerminal(os.Stdin),
		IO: connector.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}}
	if err := remediate.Execute(ctx, f, r, opt, reinventory); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
