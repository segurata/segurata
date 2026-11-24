package main

import (
	"context"
	"fmt"
	"os"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/keychain"
	"github.com/segurata/segurata/internal/legacy"
	"github.com/segurata/segurata/internal/remediate"
)

// migrateLegacy moves the former name's directories once, before any config or state is read. A
// failure is reported and the command goes on with whatever is in place.
func migrateLegacy() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	env := legacy.Env{Home: home, UID: os.Getuid(), Keychain: keychain.Keychain{Run: keychain.Exec}, Out: os.Stderr}
	if err := legacy.Migrate(context.Background(), env); err != nil {
		fmt.Fprintln(os.Stderr, "segurata:", err)
	}
}

func keychainMigrateCmd(args []string) int {
	return legacy.KeychainCLI{Config: config.DefaultPath(), Exec: keychain.Exec, In: os.Stdin, Out: os.Stdout, Err: os.Stderr,
		TTY: remediate.IsTerminal(os.Stdin)}.Run(args)
}
