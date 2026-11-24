package legacy

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/segurata/segurata/internal/keychain"
	"github.com/segurata/segurata/internal/remediate"
)

const keychainUsage = "usage: segurata keychain-migrate [--apply [--yes]]"

// KeychainCLI is `segurata keychain-migrate`: for each keychain:securizame-* reference in the
// config, copy the item to its segurata-* name, check the copy, point the reference at it and only
// then delete the old item. Values stay in memory: they travel on the stdout of security
// find-generic-password -w and the stdin of security -i, never in an argument, and are never printed.
type KeychainCLI struct {
	Config   string // config.json
	Exec     keychain.Runner
	In       io.Reader
	Out, Err io.Writer
	TTY      bool
}

func (c KeychainCLI) fail(err error) int {
	fmt.Fprintln(c.Err, "keychain-migrate:", err)
	return 1
}

// Run is the command; it returns the exit code.
func (c KeychainCLI) Run(args []string) int {
	fs := flag.NewFlagSet("keychain-migrate", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	apply := fs.Bool("apply", false, "move the items after confirmation (default: dry run)")
	yes := fs.Bool("yes", false, "with --apply, do not ask for confirmation")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(c.Err, keychainUsage)
		return 2
	}
	raw, err := os.ReadFile(c.Config)
	if err != nil {
		return c.fail(err)
	}
	olds := oldServices(raw)
	if len(olds) == 0 {
		fmt.Fprintf(c.Out, "%s references no Keychain item under the old name: nothing to do.\n", c.Config)
		return 0
	}
	ctx := context.Background()
	anyAccount := keychain.Keychain{Run: c.Exec}
	accounts := map[string]string{}
	fmt.Fprintf(c.Out, "Keychain items referenced by %s:\n", c.Config)
	for _, old := range olds {
		account, err := anyAccount.Find(ctx, old)
		switch {
		case err != nil:
			fmt.Fprintf(c.Out, "  %-36s missing from the Keychain: skipped (fix the reference by hand)\n", old)
			continue
		case hasItem(ctx, anyAccount, newService(old)):
			fmt.Fprintf(c.Out, "  %-36s -> %s (exists: kept if it holds the same value)\n", old, newService(old))
		default:
			fmt.Fprintf(c.Out, "  %-36s -> %s (account %q)\n", old, newService(old), account)
		}
		accounts[old] = account
	}
	fmt.Fprintln(c.Out, "\nEach item: read the value, store it under the new name with security -i (value on stdin), read it back and compare, point the config at it, then delete the old item.")
	if len(accounts) == 0 {
		return 1
	}
	if !*apply {
		fmt.Fprintln(c.Out, "\nDry run: nothing was changed. Run again with --apply to move these items.")
		return 0
	}
	ok, err := remediate.Confirm(c.In, c.Out, *yes, c.TTY)
	if err != nil {
		return c.fail(err)
	}
	if !ok {
		fmt.Fprintln(c.Out, "Nothing was changed.")
		return 1
	}
	var errs []error
	for _, old := range olds {
		account, found := accounts[old]
		if !found {
			continue
		}
		if err := c.moveItem(ctx, old, account); err != nil {
			errs = append(errs, err)
			fmt.Fprintf(c.Err, "keychain-migrate: %s: %v\n", old, err)
			continue
		}
		fmt.Fprintf(c.Out, "moved %s to %s\n", old, newService(old))
	}
	if len(errs) > 0 {
		return 1
	}
	return 0
}

func hasItem(ctx context.Context, k keychain.Keychain, service string) bool {
	_, err := k.Find(ctx, service)
	return err == nil
}

// moveItem copies old to its new name under the same account, checks the copy, rewrites the
// reference and deletes old. Any failure before the rewrite leaves the config and the old item as
// they were.
func (c KeychainCLI) moveItem(ctx context.Context, old, account string) error {
	k := keychain.Keychain{Run: c.Exec, Account: account}
	to := newService(old)
	value, err := k.Read(ctx, old)
	if err != nil {
		return err
	}
	if value == "" {
		return errors.New("the item holds no value; move it by hand")
	}
	if anyAccount := (keychain.Keychain{Run: c.Exec}); hasItem(ctx, anyAccount, to) {
		got, err := anyAccount.Read(ctx, to)
		if err != nil {
			return err
		}
		if got != value {
			return fmt.Errorf("%s already exists with a different value; decide which one is current and move it by hand", to)
		}
	} else {
		if err := k.Store(ctx, to, value); err != nil {
			return err
		}
		got, err := k.Read(ctx, to)
		if err != nil {
			return err
		}
		if got != value {
			return fmt.Errorf("%s does not hold the value after storing it; the config and %s are unchanged", to, old)
		}
	}
	if err := rewriteReference(c.Config, old); err != nil {
		return err
	}
	return k.Delete(ctx, old)
}
