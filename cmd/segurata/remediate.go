package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/run"
)

// remediateCmd is `segurata remediate --list | <finding-id> [--apply] [--yes]`. Without --apply
// it only prints the plan.
func remediateCmd(args []string) int {
	fs := cliflag.New("remediate", os.Stderr)
	list := fs.Bool("list", false, "list the automatable findings of the latest run")
	showAll := fs.Bool("all", false, "with --list, include info findings")
	apply := fs.Bool("apply", false, "apply the plan after confirmation (default: dry run)")
	yes := fs.Bool("yes", false, "with --apply, do not ask for confirmation")
	out := fs.String("out", config.DefaultOutDir(), "output directory")
	pos, err := cliflag.Parse(fs, args)
	id := ""
	if len(pos) > 0 {
		id = pos[0]
	}
	if err != nil || len(pos) > 1 || (id == "") == !*list {
		fmt.Fprintln(os.Stderr, "usage: segurata remediate --list | segurata remediate <finding-id> [--apply] [--yes]")
		return 2
	}

	files, err := run.LatestFiles(*out, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	findings, err := run.Load(files)
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
	f, err := run.Find(findings, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	conns := all()
	creds := func(f finding.Finding) (connector.Credentials, error) {
		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return connector.Credentials{}, err
		}
		cs, errs := run.InstanceCredentials(ctx, cfg, f.Connector, f.Instance)
		if len(errs) > 0 {
			return connector.Credentials{}, fmt.Errorf("%s: %w", f.Selector(), errors.Join(errs...))
		}
		return cs, nil
	}
	r, err := remediate.For(f, conns, creds)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	reinventory := func(ctx context.Context) ([]*run.Result, error) {
		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return nil, err
		}
		targets, err := run.Targets(cfg, conns, []string{f.Selector()})
		if err != nil {
			return nil, err
		}
		return run.Inventory(ctx, cfg, targets, *out, nil, annotate)
	}
	opt := remediate.Options{Apply: *apply, Yes: *yes, TTY: prompt.IsTerminal(os.Stdin),
		IO: connector.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}, Group: remediate.Members(findings, f)}
	if err := remediate.Execute(ctx, f, r, opt, reinventory); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
