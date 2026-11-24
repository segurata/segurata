package localsecrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// A run that could not read part of the machine says so, so the findings it missed there are not
// taken as resolved.

// writeExe writes an executable shell script named name into a fresh directory and returns its path.
func writeExe(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFailedRipgrepLeavesTheFilesUninspected(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		timeout      time.Duration
		skipped      bool
	}{
		{"regex error", `echo "rg: regex parse error" >&2; exit 2`, time.Minute, true},
		{"partial output, then an error", `printf '%s\0001:x\n' "$HOME/.zshrc"; echo "rg: something broke" >&2; exit 2`, time.Minute, true},
		{"killed", `kill -9 $$`, time.Minute, true},
		{"timed out", `exec sleep 5`, 100 * time.Millisecond, true},
		{"unreadable files only", `exit 2`, time.Minute, false},
		{"no match", `exit 1`, time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			c := fx.connector(t, "[]")
			c.RG = cli.Exec{Path: writeExe(t, "rg", tc.script), Timeout: tc.timeout}
			rec := &recorder{}
			if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
				t.Fatal(err)
			}
			var files []string
			for _, s := range rec.skipped {
				if strings.HasPrefix(s, filesScope+": ") {
					files = append(files, s)
				}
			}
			if got := len(files) > 0; got != tc.skipped {
				t.Errorf("files scope skipped = %v, want %v (skipped: %q)", got, tc.skipped, rec.skipped)
			}
			for _, s := range files {
				if !strings.Contains(s, "rg") {
					t.Errorf("reason does not name ripgrep: %q", s)
				}
			}
		})
	}
}

func TestFailedLsFilesIsAScopedErrorNotAnEmptyRepository(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, "[]")
	var lsCalls int
	git := c.Git
	c.Git = cli.RunnerFunc(func(ctx context.Context, args ...string) ([]byte, error) {
		for _, a := range args {
			if a == "ls-files" {
				lsCalls++
				return nil, errors.New("index file corrupt")
			}
		}
		return git.Run(ctx, args...)
	})
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
		t.Fatal(err)
	}
	var failed int
	for _, s := range rec.statuses {
		if s.State == finding.StateError && s.Scope == filesScope && s.Account == "~/src/shop" && strings.Contains(s.Detail, "git ls-files") {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("want one error status for ~/src/shop scoped to %q, got %d: %+v", filesScope, failed, rec.statuses)
	}
	if lsCalls != 1 {
		t.Errorf("ls-files ran %d times for one repository in one run", lsCalls)
	}
}
