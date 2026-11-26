package macos

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	lsBin    = "/bin/ls"
	chmodBin = "/bin/chmod"
)

// homeDir is the only source of the home path for the check, its plan and its allowlist.
func (c *Connector) homeDir() (string, error) {
	home, err := c.Home()
	if err != nil {
		return "", err
	}
	if home == "" || !strings.HasPrefix(home, "/") {
		return "", fmt.Errorf("home folder %q is not an absolute path", home)
	}
	return home, nil
}

func (c *Connector) homeACL(ctx context.Context, home string) []string {
	out, err := c.homeGuard(c.Run).Run(ctx, lsBin, "-led", home)
	if err != nil {
		return nil
	}
	var acl []string
	for _, l := range strings.Split(string(out), "\n")[1:] {
		if l = strings.TrimSpace(l); l != "" {
			acl = append(acl, l)
		}
	}
	return acl
}

// homeReadable ignores execute: 711 lets others reach known paths but not list, as CIS accepts.
func homeReadable(mode fs.FileMode) bool { return mode.Perm()&0o066 != 0 }

// homeCheck: every macOS user is in staff, so group read is as open as world read.
func (c *Connector) homeCheck(ctx context.Context) check {
	ch := check{id: "home-private", sev: finding.SevMedium,
		title: "Your home folder can be read by other accounts on this Mac",
		rem: finding.Remediation{Action: actionHomePrivate,
			Summary: "Make it private with `segurata remediate <id> --apply` (chmod 700, no sudo), or in Finder > Get Info > Sharing & Permissions."}}
	home, err := c.homeDir()
	if err != nil {
		ch.skip = err.Error()
		return ch
	}
	fi, err := os.Stat(home)
	if err != nil {
		ch.skip = err.Error()
		return ch
	}
	mode := fi.Mode().Perm()
	acl := c.homeACL(ctx, home)
	ch.evidence = map[string]any{"path": home, "mode": fmt.Sprintf("%o", mode), "acl": len(acl) > 0, "acl_entries": acl}
	switch {
	case homeReadable(mode):
		ch.detail = fmt.Sprintf("%s is mode %o: other accounts (a guest, a repair technician's account) can list it and read whatever inside is not private", home, mode)
	case mode&0o011 != 0:
		ch.ok, ch.detail = true, fmt.Sprintf("%s is mode %o: others can pass through it to paths they know, but cannot list or read it (CIS accepts 711)", home, mode)
	default:
		ch.ok, ch.detail = true, fmt.Sprintf("%s is mode %o", home, mode)
	}
	return ch
}

// homePlan: chmod with an octal mode leaves the ACL entries untouched.
func (c *Connector) homePlan() (connector.Plan, error) {
	home, err := c.homeDir()
	if err != nil {
		return connector.Plan{}, err
	}
	fi, err := os.Stat(home)
	if err != nil {
		return connector.Plan{}, err
	}
	was := fi.Mode().Perm()
	if !homeReadable(was) {
		return connector.Plan{}, fmt.Errorf("%s is already mode %o: other accounts cannot read it", home, was)
	}
	return connector.Plan{
		Action:   actionHomePrivate,
		Summary:  fmt.Sprintf("Make your home folder %s private (mode %o to 700). Its ACL entries are left as they are.", home, was),
		Commands: []connector.Step{{Argv: []string{chmodBin, "700", home}}},
		Undo:     []connector.Step{{Argv: []string{chmodBin, fmt.Sprintf("%o", was), home}}},
		SideEffects: []string{
			"Other accounts on this Mac can no longer open anything under your home folder, including ~/Public and ~/Sites; share files with them through /Users/Shared instead.",
			"Services running as another user that read files in your home folder (a web server serving ~/Sites) stop being able to.",
		},
	}, nil
}

func (c *Connector) homeAllowlist() (connector.Allowlist, error) {
	home, err := c.homeDir()
	if err != nil {
		return nil, err
	}
	return connector.Allowlist{actionHomePrivate: {{Argv: []string{chmodBin, "700", home}}}}, nil
}

func (c *Connector) homeGuard(r cli.Runner) cli.Runner {
	home, err := c.homeDir()
	if err != nil {
		return guard(r)
	}
	return guard(r, []string{lsBin, "-led", home})
}
