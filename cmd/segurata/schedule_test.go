package main

import (
	"os"
	"slices"
	"syscall"
	"testing"
)

// launchd stops an agent with SIGTERM and a logout hangs up: both must reach the run's context,
// which interrupts the inventory and waits for it, rather than kill the agent alone.
func TestScheduleStopsGracefullyOnTermAndHangUp(t *testing.T) {
	for _, s := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
		if !slices.Contains(scheduleSignals, s) {
			t.Errorf("%v does not stop a schedule command gracefully", s)
		}
	}
}
