package main

import (
	"os"
	"time"

	"github.com/segurata/segurata/internal/accept"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/tracker"
)

func acceptCLI() accept.CLI { return accept.CLI{Out: os.Stdout, Err: os.Stderr, Now: time.Now} }

func trackerCLI() tracker.CLI {
	return tracker.CLI{Out: os.Stdout, Err: os.Stderr, Config: config.DefaultPath(), Now: time.Now, Instances: instances, Browser: browserConnector}
}

// instances are the connector instances an unfiltered inventory runs, by label; none when the
// config does not load (status then lists only what ran).
func instances() []string {
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return nil
	}
	targets, err := run.Targets(cfg, all(), nil)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.Label())
	}
	return out
}

// browserConnector reports whether the connector called name drives the browser over CDP.
func browserConnector(name string) bool {
	for _, c := range all() {
		if d := c.Describe(); d.Name == name {
			return d.NeedsCDP()
		}
	}
	return false
}

// acceptedAnnotator loads the tracker's acceptances for an inventory or remediate run.
func acceptedAnnotator() (func(*finding.Finding), error) {
	t, err := tracker.LoadOrNew(tracker.Paths{}, time.Now())
	if err != nil {
		return nil, err
	}
	return t.Annotator(time.Now), nil
}
