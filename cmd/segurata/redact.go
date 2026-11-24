package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/segurata/segurata/connectors/localsecrets"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/redact"
	"github.com/segurata/segurata/internal/remediate"
)

// redactCmd is `segurata redact`: replace the secrets local-secrets finds in trail files.
func redactCmd(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return redact.CLI{Out: os.Stdout, Err: os.Stderr, In: os.Stdin, TTY: remediate.IsTerminal(os.Stdin),
		Trails: func(ctx context.Context) (*localsecrets.Trails, error) {
			cfg, err := config.Load(config.DefaultPath())
			if err != nil {
				return nil, fmt.Errorf("config: %w", err)
			}
			return localsecrets.New().Trails(ctx, cfg.Connectors["local-secrets"].Config)
		},
		Lsof: lsof, Now: time.Now}.Run(ctx, args)
}

// lsof runs lsof read-only and returns its stdout; the error keeps the exit status.
func lsof(ctx context.Context, _ string, args ...string) ([]byte, error) {
	path, err := exec.LookPath("lsof")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return exec.CommandContext(ctx, path, args...).Output()
}
