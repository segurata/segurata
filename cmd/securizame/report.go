package main

import (
	"os"
	"time"

	"github.com/segurata/segurata/internal/report"
)

func reportCmd(args []string) int {
	return report.CLI{Out: os.Stdout, Err: os.Stderr, Now: time.Now}.Run(args)
}
