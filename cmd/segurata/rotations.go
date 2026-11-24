package main

import (
	"os"
	"os/user"
	"time"

	"github.com/segurata/segurata/internal/keychain"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/rotation"
)

func rotationsCmd(args []string) int {
	account := os.Getenv("USER")
	if u, err := user.Current(); err == nil {
		account = u.Username
	}
	return rotation.CLI{Out: os.Stdout, Err: os.Stderr, In: os.Stdin, TTY: remediate.IsTerminal(os.Stdin),
		Home: os.UserHomeDir, User: account, Exec: keychain.Exec, Now: time.Now}.Run(args)
}
