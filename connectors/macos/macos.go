// Package macos checks the security posture of this Mac and of the Brave browser on it: disk
// encryption, SIP, Gatekeeper, firewall, updates, screen lock, login options, local accounts and
// what deleted ones left behind, Time Machine backups, endpoint agents, ports reachable from the
// network, SMB share points, the home folder mode, login and background items and Brave's remote
// debugging port. Browser extensions are the browser-extensions connector.
// Inventory is read-only and never uses sudo. A few findings can be fixed with
// `segurata remediate` (remediate.go).
package macos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/proc"
)

// Absolute paths, so nothing earlier in PATH can stand in for a system tool.
const (
	socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	defaultsBin    = "/usr/bin/defaults"
	softwareUpdate = "/usr/sbin/softwareupdate"
	netstatBin     = "/usr/sbin/netstat"
	psBin          = "/bin/ps"
	sfltoolBin     = "/usr/bin/sfltool"
	plutilBin      = "/usr/bin/plutil"
)

// Preference files read by the checks.
const (
	softwareUpdatePrefs = "/Library/Preferences/com.apple.SoftwareUpdate"
	commercePrefs       = "/Library/Preferences/com.apple.commerce"
	loginWindowPrefs    = "/Library/Preferences/com.apple.loginwindow"
)

var updateKeys = []string{"AutomaticCheckEnabled", "AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall", "AutomaticallyInstallMacOSUpdates"}

// readOnly is every command line inventory may run, exactly. None of them changes anything; a
// command not listed here is refused before it starts.
var readOnly = func() map[string]bool {
	cmds := [][]string{
		{"/usr/sbin/scutil", "--get", "ComputerName"},
		{"/usr/bin/fdesetup", "status"},
		{"/usr/bin/csrutil", "status"},
		{"/usr/sbin/spctl", "--status"},
		{socketfilterfw, "--getglobalstate"},
		{socketfilterfw, "--getstealthmode"},
		{defaultsBin, "read", commercePrefs, "AutoUpdate"},
		{softwareUpdate, "-l"},
		{"/usr/bin/sw_vers", "-productVersion"},
		{"/usr/sbin/sysadminctl", "-screenLock", "status"},
		{defaultsBin, "-currentHost", "read", "com.apple.screensaver", "idleTime"},
		{defaultsBin, "read", "com.apple.screensaver", "idleTime"},
		{"/usr/bin/pmset", "-g"},
		{defaultsBin, "read", loginWindowPrefs, "autoLoginUser"},
		{defaultsBin, "read", loginWindowPrefs, "GuestEnabled"},
		{"/usr/sbin/systemsetup", "-getremotelogin"},
		{netstatBin, "-anv", "-p", "tcp"},
		{psBin, "-axo", "pid=,comm="},
		{psBin, "-axo", "command="},
		listShares,
		{sfltoolBin, "dumpbtm"},
		{"/bin/launchctl", "list"},
		listUIDs,
		listHomes,
		tmDestinations,
		tmLatest,
		tmPrefs,
	}
	for _, k := range updateKeys {
		cmds = append(cmds, []string{defaultsBin, "read", softwareUpdatePrefs, k})
	}
	m := map[string]bool{}
	for _, c := range cmds {
		m[argvKey(c)] = true
	}
	return m
}()

// argvKey joins a command line with NUL, which no argument can contain, so distinct argvs never
// share a key.
func argvKey(argv []string) string { return strings.Join(argv, "\x00") }

// guard refuses any command line that is not exactly one of readOnly.
func guard(r cli.Runner) cli.Runner { return guardWith(r) }

// guardWith also lets through the exact command lines in extra, which name live objects (the home
// folder, an account) that a fixed list cannot. Callers build extra from a fresh read, never from
// a finding.
func guardWith(r cli.Runner, extra ...[]string) cli.Runner {
	allowed := map[string]bool{}
	for _, e := range extra {
		allowed[argvKey(e)] = true
	}
	return cli.RunnerFunc(func(ctx context.Context, args ...string) ([]byte, error) {
		if k := argvKey(args); !readOnly[k] && !allowed[k] {
			return nil, fmt.Errorf("%w: %s", cli.ErrRefused, strings.Join(args, " "))
		}
		return r.Run(ctx, args...)
	})
}

type Connector struct {
	// Run executes read-only commands after the guard. Tests replace it with canned output.
	Run cli.Runner
	// Exec runs remediation commands after the per-action allowlist. Tests replace it.
	Exec connector.Executor
	// Home is the user's home directory, where Brave keeps its profiles.
	Home func() (string, error)
	OS   string
	// Root prefixes the system folders the file checks read (accounts' homes, /Library, /Users/Shared,
	// /Applications); "" is the real root. Tests point it at a temporary tree.
	Root string
	// UID is the user running segurata, whose account is not reported as an extra one.
	UID func() int
	Now func() time.Time
}

func New() *Connector {
	return &Connector{Run: system{}, Exec: connector.System{}, Home: os.UserHomeDir, OS: runtime.GOOS, UID: os.Getuid, Now: time.Now}
}

// path is a system path under Root; shown is its inverse, for evidence and titles.
func (c *Connector) path(p string) string { return filepath.Join(c.Root, p) }
func (c *Connector) shown(p string) string {
	if c.Root == "" {
		return p
	}
	return strings.TrimPrefix(p, filepath.Clean(c.Root))
}

func init() { connector.Register(New()) }

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     "macos",
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "FileVault, SIP, Gatekeeper, firewall, updates, screen lock, local accounts, Time Machine, endpoint agents, network ports, login items, home folder, SMB shares, Brave debugging port",
		Needs:    []string{"os:darwin"},
		Theme:    finding.ThemeMac,
	}
}

// Track makes one item of each finding: each is its own setting to fix.
func (c *Connector) Track(finding.Finding) *finding.Track {
	return &finding.Track{Group: finding.GroupFinding}
}

// slowTimeout is how long the tools that can take minutes get: softwareupdate asks Apple's
// servers, and sfltool dumpbtm walks every background item record and slows down a lot when the
// Mac is busy.
const slowTimeout = 2 * time.Minute

// system runs the macOS tools. It returns stdout, or stderr when stdout is empty, because several
// of them (sysadminctl, defaults on a missing key) answer only on stderr. softwareupdate and
// sfltool get slowTimeout; everything else thirty seconds.
type system struct{}

func (system) Run(ctx context.Context, args ...string) ([]byte, error) {
	timeout := 30 * time.Second
	if args[0] == softwareUpdate || args[0] == sfltoolBin {
		timeout = slowTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := proc.Command(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	out := stdout.Bytes()
	if len(bytes.TrimSpace(out)) == 0 {
		out = stderr.Bytes()
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("%s did not answer within %s: %w", filepath.Base(args[0]), timeout, context.DeadlineExceeded)
	}
	if err != nil {
		return out, &cli.Error{Cmd: filepath.Base(args[0]), Stderr: stderr.String(), Err: err}
	}
	return out, nil
}

// text runs a read-only command and returns its trimmed output, and whether it exited cleanly.
// A failed command still returns what it printed, like `cmd 2>&1` would.
func (c *Connector) text(ctx context.Context, args ...string) (string, bool) {
	out, err := guard(c.Run).Run(ctx, args...)
	s := strings.TrimSpace(string(out))
	if err != nil && s == "" {
		s = err.Error()
	}
	return s, err == nil
}

// pref reads one defaults key, or "" when it is not set.
func (c *Connector) pref(ctx context.Context, args ...string) string {
	if s, ok := c.text(ctx, args...); ok {
		return s
	}
	return ""
}

func (c *Connector) Inventory(ctx context.Context, _ connector.Request, emit connector.Emitter) error {
	if c.OS != "darwin" {
		emit.Status(finding.Status{Account: "this machine", State: finding.StateUnsupported, Detail: "the macos connector only runs on macOS"})
		return nil
	}
	host, _ := c.text(ctx, "/usr/sbin/scutil", "--get", "ComputerName")
	if host == "" {
		host, _ = os.Hostname()
	}
	r := &reporter{host: host, emit: emit}

	// softwareupdate -l can take a minute or two: start it first and report it last.
	pending := make(chan check, 1)
	go func() { pending <- c.pendingUpdates(ctx) }()

	r.reportAll(c.systemChecks(ctx))
	r.report(c.homeCheck(ctx))
	if users, err := c.localUsers(ctx); err != nil {
		r.report(check{id: "local-accounts", skip: "dscl could not list local users: " + err.Error()})
	} else {
		r.reportAll(inArea("local-accounts", c.accountChecks(ctx, users)))
		r.reportAll(inArea("local-accounts", c.orphanedFiles(users)))
		r.reportAll(inArea("local-accounts", c.endpointAgents(ctx, users)))
	}
	r.reportAll(c.backupChecks(ctx))
	items := c.backgroundItems(ctx, r)
	c.listeningPorts(ctx, r, items)
	r.reportAll(items.checks)
	r.report(c.braveDebugging(ctx))
	r.report(<-pending)

	// A check that could not run leaves only its own area uninspected: the machine was.
	emit.Status(finding.Status{Account: host, State: finding.StateOK})
	for _, ch := range r.skipped {
		state := ch.skipState
		if state == "" {
			state = finding.StateUnsupported
		}
		emit.Status(finding.Status{Account: host, Scope: ch.scope(), State: state, Detail: ch.id + ": " + ch.skip})
	}
	return nil
}

// check is one posture check's outcome. A passing check is logged, not emitted: a finding is
// something to act on, and its disappearance is how remediate confirms a fix.
type check struct {
	id       string
	area     string // the checks a skip of this id stands for, when several; defaults to id
	resource string // resource type; "macos_setting" when empty
	name     string
	ok       bool
	skip     string // why the check could not run
	// skipState is the status a skipped check reports: unsupported (the default) when this Mac
	// cannot answer it, error when the tool failed or timed out.
	skipState finding.State
	sev       finding.Severity
	blast     finding.Blast // what it puts at stake beyond its severity
	title     string
	detail    string
	evidence  map[string]any
	rem       finding.Remediation
}

type reporter struct {
	host    string
	emit    connector.Emitter
	skipped []check
}

// scope is a check's coverage scope: findings carry it, and a check that cannot run leaves it
// uninspected. Checks that one failure skips together (every share point, every background item,
// everything read from the local users) share an area.
func (ch check) scope() string {
	if ch.area != "" {
		return "check:" + ch.area
	}
	return "check:" + ch.id
}

func inArea(area string, chs []check) []check {
	for i := range chs {
		chs[i].area = area
	}
	return chs
}

func (r *reporter) reportAll(chs []check) {
	for _, ch := range chs {
		r.report(ch)
	}
}

func (r *reporter) report(ch check) {
	switch {
	case ch.skip != "":
		r.skipped = append(r.skipped, ch)
		return
	case ch.ok:
		r.emit.Log(fmt.Sprintf("OK %s: %s", ch.id, ch.detail))
		return
	}
	ev := map[string]any{"check": ch.id, "detail": ch.detail}
	maps.Copy(ev, ch.evidence)
	typ, name := ch.resource, ch.name
	if typ == "" {
		typ = "macos_setting"
	}
	if name == "" {
		name = ch.id
	}
	r.emit.Finding(finding.Finding{
		Account:     r.host,
		Scope:       ch.scope(),
		Resource:    finding.Resource{Type: typ, ID: ch.id, Name: name},
		Kind:        finding.KindSetting,
		Severity:    ch.sev,
		Blast:       ch.blast,
		Title:       ch.title,
		Evidence:    ev,
		Remediation: ch.rem,
	})
}
