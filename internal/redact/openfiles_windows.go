//go:build windows

package redact

import (
	"context"
	"fmt"

	"github.com/segurata/segurata/internal/winsys"
)

// Windows has no lsof, and ReplaceFileW fails on a file another process holds anyway, so any
// holder leaves the file alone, not only an agent.
const skipOpen = "open by a running process"

// rmBatch bounds how many files one Restart Manager session registers.
const rmBatch = 256

// DefaultOpenFiles asks the Restart Manager which of paths any process holds open. It answers for
// a set of files, so a batch with a holder is split until each held file is found.
func DefaultOpenFiles(ctx context.Context, paths []string) (map[string]bool, error) {
	open := map[string]bool{}
	var check func(batch []string) error
	check = func(batch []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		holders, err := winsys.FileHolders(batch)
		if err != nil {
			return fmt.Errorf("cannot list the processes holding trail files open (Restart Manager): %w", err)
		}
		switch {
		case len(holders) == 0:
			return nil
		case len(batch) == 1:
			open[batch[0]] = true
			return nil
		}
		mid := len(batch) / 2
		if err := check(batch[:mid]); err != nil {
			return err
		}
		return check(batch[mid:])
	}
	for i := 0; i < len(paths); i += rmBatch {
		if err := check(paths[i:min(i+rmBatch, len(paths))]); err != nil {
			return nil, err
		}
	}
	return open, nil
}
