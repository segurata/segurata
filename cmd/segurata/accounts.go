package main

import (
	"os"
	"time"

	"github.com/segurata/segurata/internal/accounts"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/config"
)

func accountsCmd(args []string) int {
	return accounts.CLI{Out: os.Stdout, Err: os.Stderr, Config: config.DefaultPath(), Now: time.Now, Email: attribution.GitEmail}.Run(args)
}
