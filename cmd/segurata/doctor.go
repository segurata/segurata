package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/doctor"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/tracker"
)

const doctorUsage = "usage: segurata doctor [--connector name|name:label] [--out out]"

// doctorCmd is `segurata doctor`: read-only prerequisite checks.
func doctorCmd(args []string) int {
	fs := cliflag.New("doctor", os.Stderr)
	only := fs.String("connector", "", "check one connector (or one instance, name:label)")
	out := fs.String("out", config.DefaultOutDir(), "inventory output directory whose mode is checked")
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) != 0 {
		fmt.Fprintln(os.Stderr, doctorUsage)
		return 2
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	paths, err := tracker.DefaultPaths()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var selectors []string
	if *only != "" {
		selectors = []string{*only}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return doctor.Env{
		Out: os.Stdout, ConfigPath: config.DefaultPath(), KeyPath: fingerprint.DefaultPath(home), Tracker: paths,
		OutDir: *out, GOOS: runtime.GOOS, Connectors: all(),
		Request: run.NewRequest, CDPVersion: cdp.ReadVersion, LookPath: exec.LookPath,
	}.Run(ctx, selectors)
}
