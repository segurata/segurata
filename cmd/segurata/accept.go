package main

import (
	"os"
	"time"

	"github.com/segurata/segurata/internal/accept"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/tracker"
)

func acceptCLI() accept.CLI { return accept.CLI{Out: os.Stdout, Err: os.Stderr, Now: time.Now} }

func trackerCLI() tracker.CLI {
	return tracker.CLI{Out: os.Stdout, Err: os.Stderr, Config: config.DefaultPath(), Now: time.Now}
}

// acceptedAnnotator loads the tracker's acceptances for an inventory or remediate run.
func acceptedAnnotator() (func(*finding.Finding), error) {
	t, err := tracker.LoadOrMigrate(tracker.Paths{}, time.Now(), os.Stderr)
	if err != nil {
		return nil, err
	}
	return t.Annotator(time.Now), nil
}
