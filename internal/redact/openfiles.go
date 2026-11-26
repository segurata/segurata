package redact

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Runner runs a program and returns its stdout.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Lsof lists, through run, the files running claude and codex processes have open, whatever paths
// asks about. lsof exits 1 when a name matches no process; any other failure refuses, or an active
// session could be rewritten.
func Lsof(run Runner) func(ctx context.Context, paths []string) (map[string]bool, error) {
	return func(ctx context.Context, _ []string) (map[string]bool, error) {
		out, err := run(ctx, "lsof", "-Fn", "-c", "claude", "-c", "codex")
		var exit interface{ ExitCode() int }
		if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1) {
			return nil, fmt.Errorf("cannot list the files agents have open (lsof): %w", err)
		}
		open := map[string]bool{}
		for _, l := range strings.Split(string(out), "\n") {
			if path, ok := strings.CutPrefix(l, "n"); ok && filepath.IsAbs(path) {
				open[filepath.Clean(path)] = true
			}
		}
		return open, nil
	}
}
