package macos

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

// launchDirs are where third parties install launchd jobs; /Library ones run for every user.
var launchDirs = []struct {
	dir        string
	privileged bool
}{
	{"/Library/LaunchDaemons", true},
	{"/Library/LaunchAgents", true},
	{"~/Library/LaunchAgents", false},
}

// helperTools is where SMJobBless installs an app's privileged helper: one without its app is a
// leftover.
const helperTools = "/Library/PrivilegedHelperTools"

type launchJob struct {
	label      string
	plist      string // as shown
	program    string // Program, else ProgramArguments[0]; "" unless absolute
	onDisk     string // under Root for system paths
	privileged bool
}

// readPlist converts a binary plist with plutil, allowed for that exact file only.
func (c *Connector) readPlist(ctx context.Context, path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(raw, []byte("bplist")) {
		argv := []string{plutilBin, "-convert", "xml1", "-o", "-", path}
		if raw, err = guard(c.Run, argv).Run(ctx, argv...); err != nil {
			return nil, err
		}
	}
	return plistDict(raw)
}

// launchJobs leaves out files it cannot read or parse.
func (c *Connector) launchJobs(ctx context.Context) []launchJob {
	home, _ := c.Home()
	var out []launchJob
	for _, d := range launchDirs {
		dir := c.path(d.dir)
		if rest, ok := strings.CutPrefix(d.dir, "~/"); ok {
			if home == "" {
				continue
			}
			dir = filepath.Join(home, rest)
		}
		for _, p := range plists(dir) {
			m, err := c.readPlist(ctx, p)
			if err != nil {
				continue
			}
			j := launchJob{plist: c.shown(p), privileged: d.privileged}
			j.label, _ = m["Label"].(string)
			if j.label == "" {
				j.label = strings.TrimSuffix(filepath.Base(p), ".plist")
			}
			j.program, _ = m["Program"].(string)
			if args, ok := m["ProgramArguments"].([]any); j.program == "" && ok && len(args) > 0 {
				j.program, _ = args[0].(string)
			}
			switch {
			case !filepath.IsAbs(j.program):
				j.program = ""
			case home != "" && strings.HasPrefix(j.program, home+"/"):
				j.onDisk = j.program
			default:
				j.onDisk = c.path(j.program)
			}
			out = append(out, j)
		}
	}
	return out
}

func plists(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "*.plist"))
	return m
}

// installedBundleIDs reads /Applications, one folder down (suites like Adobe's) and ~/Applications.
func (c *Connector) installedBundleIDs(ctx context.Context) []string {
	home, _ := c.Home()
	patterns := []string{c.path("/Applications/*.app"), c.path("/Applications/*/*.app")}
	if home != "" {
		patterns = append(patterns, filepath.Join(home, "Applications", "*.app"))
	}
	var ids []string
	for _, pat := range patterns {
		apps, _ := filepath.Glob(pat)
		for _, app := range apps {
			m, err := c.readPlist(ctx, filepath.Join(app, "Contents", "Info.plist"))
			if err != nil {
				continue
			}
			if id, _ := m["CFBundleIdentifier"].(string); id != "" {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// vendorDomain is com.tunnelbear for com.tunnelbear.mac.tbeard: a helper and its app share it.
func vendorDomain(id string) string {
	parts := strings.SplitN(id, ".", 3)
	if len(parts) < 2 {
		return id
	}
	return parts[0] + "." + parts[1]
}

// leftoverCheck flags a job whose program is gone, or a privileged helper whose app is not
// installed: both outlive an app dragged to the Trash.
func leftoverCheck(j launchJob, bundleIDs func() []string) (check, bool) {
	if j.program == "" {
		return check{}, false
	}
	kind := "launch agent"
	if j.privileged {
		kind = "privileged helper"
	}
	ch := check{id: "leftover:" + j.label, resource: "background_item", name: j.label, sev: finding.SevLow,
		evidence: map[string]any{"label": j.label, "plist": j.plist, "program": j.program, "privileged": j.privileged}}
	unload := fmt.Sprintf("`launchctl bootout gui/$(id -u) %s`", j.plist)
	if j.privileged {
		unload = fmt.Sprintf("`sudo launchctl bootout system %s`", j.plist)
	}
	switch {
	case !pathExists(j.onDisk):
		ch.title = fmt.Sprintf("Leftover %s %s: its program is missing", kind, j.label)
		ch.detail = fmt.Sprintf("%s starts %s, which does not exist", j.plist, j.program)
		ch.evidence["program_exists"] = false
	case j.privileged && strings.HasPrefix(j.program, helperTools+"/") &&
		!slices.ContainsFunc(bundleIDs(), func(id string) bool { return vendorDomain(id) == vendorDomain(j.label) }):
		ch.title = fmt.Sprintf("Leftover privileged helper %s: no app from %s is installed", j.label, vendorDomain(j.label))
		ch.detail = fmt.Sprintf("%s starts %s as root, and no installed app's bundle id starts with %s", j.plist, j.program, vendorDomain(j.label))
		ch.evidence["program_exists"] = true
	default:
		return check{}, false
	}
	ch.rem = manual(fmt.Sprintf("If you no longer use the app that installed it, unload it with %s and delete %s and %s.", unload, j.plist, j.program))
	return ch, true
}

func bundleOf(p string) string {
	if i := strings.Index(p, ".app/"); i >= 0 {
		return p[:i+len(".app")]
	}
	return p
}

// bgItems holds background item checks so listening ports can join the item that runs them.
type bgItems struct {
	checks []check
	owners map[string]int // executable path or .app bundle → index in checks
}

func (b *bgItems) add(ch check, paths ...string) {
	if b.owners == nil {
		b.owners = map[string]int{}
	}
	for _, p := range paths {
		if p != "" {
			b.owners[bundleOf(p)] = len(b.checks)
		}
	}
	b.checks = append(b.checks, ch)
}

func (b *bgItems) absorb(l listener) bool {
	i, ok := b.owners[bundleOf(l.path)]
	if !ok || l.path == "" {
		return false
	}
	ch := &b.checks[i]
	if ch.evidence == nil {
		ch.evidence = map[string]any{}
	}
	ports, _ := ch.evidence["listening_ports"].([]string)
	ch.evidence["listening_ports"] = append(ports, l.port)
	ch.detail += fmt.Sprintf("; %s listens on TCP %s from the network", l.proc, l.port)
	return true
}
