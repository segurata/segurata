//go:build unix

package redact

import (
	"context"
	"os/exec"
	"time"
)

const skipOpen = "open by a running claude or codex process"

// DefaultOpenFiles asks lsof which files the claude and codex agents have open.
var DefaultOpenFiles = Lsof(runLsof)

// runLsof runs lsof read-only and returns its stdout; the error keeps the exit status.
func runLsof(ctx context.Context, _ string, args ...string) ([]byte, error) {
	path, err := exec.LookPath("lsof")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return exec.CommandContext(ctx, path, args...).Output()
}
