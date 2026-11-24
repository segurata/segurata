package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"

	"github.com/segurata/segurata/internal/accept"
	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/doctor"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/rotation"
	"github.com/segurata/segurata/internal/run"
)

const doctorUsage = "usage: securizame doctor [--connector name|name:label] [--out out]"

// doctorCmd is `securizame doctor`: read-only prerequisite checks.
func doctorCmd(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	only := fs.String("connector", "", "check one connector (or one instance, name:label)")
	out := fs.String("out", "out", "inventory output directory whose mode is checked")
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
	ledger, err := rotation.DefaultPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	accepted, err := accept.DefaultPath()
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
		Out: os.Stdout, ConfigPath: config.DefaultPath(), KeyPath: fingerprint.DefaultPath(home), LedgerPath: ledger,
		AcceptedPath: accepted, OutDir: *out, GOOS: runtime.GOOS, Connectors: all(),
		Request: run.NewRequest, CDPVersion: cdp.ReadVersion, LookPath: exec.LookPath,
	}.Run(ctx, selectors)
}
