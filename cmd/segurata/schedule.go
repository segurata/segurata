package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/schedule"
	"github.com/segurata/segurata/internal/searchpath"
)

const scheduleUsage = "usage: segurata schedule install|uninstall|status|run [--every 24h] [--connectors a,b] [--apply] [--yes]"

// scheduleCmd is `segurata schedule`. install and uninstall are dry runs unless --apply; run is
// what the installed agent executes.
func scheduleCmd(args []string) int {
	fs := cliflag.New("schedule", os.Stderr)
	every := fs.Duration("every", schedule.DefaultEvery, "interval between runs")
	conns := fs.String("connectors", "", "comma-separated connectors (default: all that do not need the browser)")
	apply := fs.Bool("apply", false, "write and load the agent after confirmation (default: dry run)")
	yes := fs.Bool("yes", false, "with --apply, do not ask for confirmation")
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprintln(os.Stderr, scheduleUsage)
		return 2
	}
	env, err := scheduleEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var selected []string
	for _, c := range strings.Split(*conns, ",") {
		if c = strings.TrimSpace(c); c != "" {
			selected = append(selected, c)
		}
	}
	opt := schedule.Options{Every: *every, Connectors: selected, Apply: *apply, Yes: *yes}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch pos[0] {
	case "install":
		err = env.Install(ctx, opt)
	case "uninstall":
		err = env.Uninstall(ctx, opt)
	case "status":
		err = env.Status(ctx)
	case "run":
		err = env.Run(ctx, selected)
	default:
		fmt.Fprintln(os.Stderr, scheduleUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func scheduleEnv() (schedule.Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return schedule.Env{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return schedule.Env{}, err
	}
	return schedule.Env{
		GOOS: runtime.GOOS, Home: home, UID: os.Getuid(), Exe: exe, Path: searchpath.Clean(os.Getenv("PATH")), TmpDir: os.TempDir(),
		Runner: schedule.System{}, IO: connector.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr},
		TTY: remediate.IsTerminal(os.Stdin), Now: time.Now, Connectors: all(),
	}, nil
}
