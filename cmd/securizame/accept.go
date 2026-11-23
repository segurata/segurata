package main

import (
	"os"
	"time"

	"github.com/segurata/segurata/internal/accept"
	"github.com/segurata/segurata/internal/finding"
)

func acceptCLI() accept.CLI { return accept.CLI{Out: os.Stdout, Err: os.Stderr, Now: time.Now} }

// acceptedAnnotator loads the accepted-risks file for an inventory or remediate run.
func acceptedAnnotator() (func(*finding.Finding), error) {
	path, err := accept.DefaultPath()
	if err != nil {
		return nil, err
	}
	s, err := accept.Load(path)
	if err != nil {
		return nil, err
	}
	return s.Annotator(time.Now), nil
}
