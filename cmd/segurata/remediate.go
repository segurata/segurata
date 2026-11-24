package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/run"
)

// remediateCmd is `segurata remediate --list | <finding-id> [--apply] [--yes]`. Without --apply
// it only prints the plan.
func remediateCmd(args []string) int {
	fs := flag.NewFlagSet("remediate", flag.ExitOnError)
	list := fs.Bool("list", false, "list the automatable findings of the latest run")
	showAll := fs.Bool("all", false, "with --list, include info findings")
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
		fmt.Fprintln(os.Stderr, "usage: segurata remediate --list | segurata remediate <finding-id> [--apply] [--yes]")
		return 2
	}

	files, err := remediate.LatestFiles(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	findings, err := remediate.Load(files)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	annotate, err := acceptedAnnotator()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for i := range findings {
		annotate(&findings[i])
	}
	if *list {
		fmt.Printf("Latest run of each connector:\n  %s\n\n", strings.Join(files, "\n  "))
		minSev := finding.SevLow
		if *showAll {
			minSev = finding.SevInfo
		}
		remediate.List(os.Stdout, findings, minSev)
		return 0
	}
	f, err := remediate.Find(findings, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	conns := all()
	request := func(f finding.Finding) (connector.Request, error) {
		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return connector.Request{}, err
		}
		req, errs := run.InstanceRequest(cfg, f.Connector, f.Instance)
		if len(errs) > 0 {
			return connector.Request{}, fmt.Errorf("%s: %w", remediate.Selector(f), errors.Join(errs...))
		}
		return req, nil
	}
	r, err := remediate.For(f, conns, request)
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
		return run.Inventory(ctx, cfg, targets, *out, nil, annotate)
	}
	opt := remediate.Options{Apply: *apply, Yes: *yes, TTY: remediate.IsTerminal(os.Stdin),
		IO: connector.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}}
	if err := remediate.Execute(ctx, f, r, opt, reinventory); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
