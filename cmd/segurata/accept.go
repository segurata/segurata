package main

import (
	"os"
	"time"

	"github.com/segurata/segurata/internal/accept"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/config"
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

// lent loads what the tracker lends an inventory or remediate run: its acceptances, and whose each
// secret is, against the tracker's accounts plus owned (config owned).
func lent(owned attribution.Owned) (run.Lent, error) {
	t, err := tracker.LoadOrNew(tracker.Paths{}, time.Now())
	if err != nil {
		return run.Lent{}, err
	}
	return run.Lent{Annotate: t.Annotator(time.Now), Known: t.Known(owned)}, nil
}
