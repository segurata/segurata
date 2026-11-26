package main

import (
	"os"
	"os/user"
	"time"

	"github.com/segurata/segurata/internal/clipboard"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/keychain"
	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/rotation"
)

func rotationsCmd(args []string) int {
	account := os.Getenv("USER")
	if u, err := user.Current(); err == nil {
		account = u.Username
	}
	return rotation.CLI{Out: os.Stdout, Err: os.Stderr, Config: config.DefaultPath(), In: os.Stdin, TTY: prompt.IsTerminal(os.Stdin),
		Home: os.UserHomeDir, User: account, Keychain: keychain.Default, Clipboard: clipboard.Default(), Now: time.Now}.Run(args)
}
