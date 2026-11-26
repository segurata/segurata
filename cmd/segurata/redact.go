package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/segurata/segurata/connectors/localsecrets"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/redact"
	"github.com/segurata/segurata/internal/secretrisk"
)

// redactCmd is `segurata redact`: replace the secrets local-secrets finds in trail files.
func redactCmd(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return redact.CLI{Out: os.Stdout, Err: os.Stderr, In: os.Stdin, TTY: prompt.IsTerminal(os.Stdin),
		Trails: func(ctx context.Context) (*localsecrets.Trails, error) {
			cfg, err := config.Load(config.DefaultPath())
			if err != nil {
				return nil, fmt.Errorf("config: %w", err)
			}
			return localsecrets.New().Trails(ctx, cfg.Connectors[secretrisk.ConnectorName].Config)
		},
		OpenFiles: redact.DefaultOpenFiles, Now: time.Now}.Run(ctx, args)
}
