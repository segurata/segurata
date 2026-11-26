//go:build unix

package schedule

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// A scheduled inventory stays in the agent's process group, which launchd ends when it unloads
// the agent or the user logs out: in a group of its own it would outlive the agent.
func TestSystemKeepsTheRunInTheAgentsProcessGroup(t *testing.T) {
	var out bytes.Buffer
	if err := (System{}).Run(context.Background(), "/bin/sh", []string{"-c", "ps -o pgid= -p $$"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	pgid, err := strconv.Atoi(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatalf("%q: %v", out.String(), err)
	}
	if pgid != syscall.Getpgrp() {
		t.Fatalf("the run leads process group %d, not the agent's %d", pgid, syscall.Getpgrp())
	}
}
