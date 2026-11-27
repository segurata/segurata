package main

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/signin"
)

func signinCmd(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return signin.CLI{
		Out: os.Stdout, Err: os.Stderr, In: os.Stdin, TTY: prompt.IsTerminal(os.Stdin),
		Config: config.DefaultPath(), Now: time.Now, Connectors: all(),
		Connect: func(ctx context.Context, cdpURL string) (signin.Browser, func(), error) {
			c, err := cdp.Connect(ctx, cdpURL)
			if err != nil {
				return nil, nil, err
			}
			return signin.CDP{Client: c}, func() { c.Close() }, nil
		},
		Inventory: func(ctx context.Context, cfg config.Config, targets []run.Target, out string) ([]*run.Result, error) {
			l, err := lent(cfg)
			if err != nil {
				return nil, err
			}
			return run.Inventory(ctx, cfg, targets, out, nil, l)
		},
		Sync: func(out string) int { return trackerCLI().Track([]string{"sync", "--out", out}) },
	}.Run(ctx, args)
}
