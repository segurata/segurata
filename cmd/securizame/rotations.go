package main

import (
	"os"
	"time"

	"github.com/segurata/segurata/internal/rotation"
)

func rotationsCmd(args []string) int {
	return rotation.CLI{Out: os.Stdout, Err: os.Stderr, Now: time.Now}.Run(args)
}
