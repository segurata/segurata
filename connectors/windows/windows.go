// Package windows checks the security posture of this Windows PC. Inventory is read-only and runs
// as the user who starts it: a check that needs an administrator says so with the command to run
// from an elevated PowerShell, never reporting what it could not read as clean. One finding, the
// screen lock, can be fixed with `segurata remediate`; machine-wide fixes are left to the owner.
package windows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/posture"
	"github.com/segurata/segurata/internal/cfgkey"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/proc"
)

const name = "windows"

type (
	check    = posture.Check
	reporter = posture.Reporter
)

type Connector struct {
	Run      cli.Runner         // behind guard
	Exec     connector.Executor // behind the screen lock allowlist
	Reg      Registry
	OS       string
	System32 func() (string, error)
	Host     func() (string, error)
	Now      func() time.Time
	Exists   func(path string) bool
	// DesktopKey is the HKCU key of the screen saver settings; tests point it at a key of their own.
	DesktopKey string
}

func New() *Connector {
	return &Connector{Run: system{}, Exec: connector.System{}, Reg: sysRegistry{}, OS: runtime.GOOS, System32: system32,
		Host: os.Hostname, Now: time.Now, Exists: fileExists, DesktopKey: desktopKey}
}

func init() { connector.Register(New()) }

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     name,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "BitLocker, Defender Firewall, antivirus, Windows Update, screen lock, local administrators, Guest, auto-logon, UAC, Remote Desktop, SMBv1, shared folders, network ports, Secure Boot, browser debugging ports",
		Needs:    []string{"os:windows"},
		Theme:    finding.ThemeWindows,
	}
}

func (c *Connector) Track(finding.Finding) *finding.Track {
	return &finding.Track{Group: finding.GroupFinding}
}

// powershell is Windows PowerShell from System32, never one earlier in PATH.
func (c *Connector) powershell() (string, error) {
	sys, err := c.System32()
	if err != nil {
		return "", err
	}
	return filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe"), nil
}

// probeArgv is the one command line inventory runs.
func (c *Connector) probeArgv() ([]string, error) {
	ps, err := c.powershell()
	if err != nil {
		return nil, err
	}
	return []string{ps, "-NoProfile", "-NonInteractive", "-Command", probeScript}, nil
}

// guard refuses any command line but the probe's.
func (c *Connector) guard() cli.Runner {
	return cli.RunnerFunc(func(ctx context.Context, args ...string) ([]byte, error) {
		want, err := c.probeArgv()
		if err != nil {
			return nil, err
		}
		if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
			return nil, fmt.Errorf("%w: %s", cli.ErrRefused, filepath.Base(args[0]))
		}
		return c.Run.Run(ctx, args...)
	})
}

// probeTimeout: Win32_OptionalFeature asks the servicing stack, which takes seconds on a busy PC.
const probeTimeout = 2 * time.Minute

type system struct{}

func (system) Run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	cmd := proc.Command(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("powershell did not answer within %s: %w", probeTimeout, context.DeadlineExceeded)
	}
	if err != nil {
		return stdout.Bytes(), &cli.Error{Cmd: "powershell", Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

// readProbe runs the probe; when it fails as a whole, every section it reads failed with it.
func (c *Connector) readProbe(ctx context.Context) probe {
	argv, err := c.probeArgv()
	var out []byte
	if err == nil {
		out, err = c.guard().Run(ctx, argv...)
	}
	if err != nil {
		return probe{recs: map[string][]record{}, failed: map[string]record{}, whole: "Windows PowerShell failed: " + err.Error()}
	}
	return parseProbe(string(out))
}

// lockLimitKey is the longest idle time, in seconds, the screen may stay unlocked, and what the
// remediation sets.
const (
	lockLimitKey     = "screen_lock_seconds"
	defaultLockLimit = 10 * 60
)

func lockLimit(cfg map[string]any) (int, error) {
	return cfgkey.PositiveInt(cfg, name, lockLimitKey, defaultLockLimit)
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	if c.OS != "windows" {
		emit.Status(finding.Status{Account: "this machine", State: finding.StateUnsupported, Detail: "the windows connector only runs on Windows"})
		return nil
	}
	limit, err := lockLimit(req.Config)
	if err != nil {
		return err
	}
	host, err := c.Host()
	if err != nil || host == "" {
		host = "this PC"
	}
	r := &reporter{Host: host, Emit: emit, Setting: "windows_setting"}
	p := c.readProbe(ctx)
	r.ReportAll(diskChecks(p))
	r.ReportAll(firewallChecks(p))
	r.ReportAll(antivirusChecks(p))
	r.ReportAll(c.updateChecks(p))
	r.Report(c.screenLockCheck(limit))
	r.ReportAll(c.accountChecks(p))
	r.ReportAll(c.systemChecks())
	r.ReportAll(c.remoteChecks(p))
	r.ReportAll(listenerChecks(p))
	r.ReportAll(browserChecks(p))
	// A check that could not run leaves only its own area uninspected.
	r.Finish()
	return nil
}
