// Package schedule is `segurata schedule`: it installs a per-user agent that runs an inventory
// and writes a report on a fixed interval, and notifies about new high or critical findings. On
// macOS the agent is a launchd user agent; on Linux the equivalent systemd user timer is printed
// only. Install and uninstall are dry runs unless --apply. See docs/architecture.md, "Scheduled runs".
package schedule

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/tracker"
)

const (
	// Label names the launchd agent and its plist.
	Label = "com.segurata.inventory"
	// Unit names the systemd user service and timer.
	Unit = "segurata-inventory"

	DefaultEvery = 24 * time.Hour
	MinEvery     = time.Hour

	launchctl = "/bin/launchctl"
	osascript = "/usr/bin/osascript"
)

// Runner runs one external command. Tests inject a fake; System is the real one.
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error
}

// System runs commands as real processes.
type System struct{}

// stopGrace is how long a command whose context ended has to stop after its interrupt before it is
// killed: enough for an inventory to write run_end and sync the tracker.
var stopGrace = 2 * time.Minute

// Run runs the command. When ctx ends, the command gets an interrupt, the signal segurata
// commands stop cleanly on, then a kill after stopGrace.
func (System) Run(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = stopGrace
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// Env is the machine the schedule is installed on. Everything that touches the system is here so
// tests can use a temp home and a fake runner.
type Env struct {
	GOOS   string
	Home   string
	UID    int
	Exe    string // absolute path of the segurata binary the agent runs
	Path   string // PATH the agent runs with, so connectors find their CLIs and external connectors
	TmpDir string // a binary under it was built by `go run` and will not survive
	Runner Runner
	IO     connector.IO
	TTY    bool
	Now    func() time.Time
	// Connectors are the installed connectors: the default selection, and which drive the browser.
	Connectors []connector.Connector
	// Config is the owner's config: cdp_url, keep_runs_days and browser_stale_days.
	Config config.Config
	// Browser checks that Brave answers at a CDP address (cdp.Brave). It never starts a browser.
	Browser func(ctx context.Context, cdpURL string) (cdp.Version, error)
	// Tracker is the tracker the inventory's sync writes, whose new items a run notifies; zero
	// means tracker.DefaultPaths.
	Tracker tracker.Paths
}

// Paths are the files the schedule uses, all under the owner's home.
type Paths struct {
	Plist  string // ~/Library/LaunchAgents/com.segurata.inventory.plist
	Logs   string // ~/Library/Logs/segurata
	State  string // ~/.segurata, the agent's working directory
	Out    string // inventory output of scheduled runs, under State
	Report string // the last report, under State
	// BrowserState is what runs remember about the browser connectors, under State.
	BrowserState string
	SystemdTo    string // ~/.config/systemd/user
}

func (e Env) Paths() Paths {
	state := filepath.Join(e.Home, ".segurata")
	return Paths{
		Plist:        filepath.Join(e.Home, "Library", "LaunchAgents", Label+".plist"),
		Logs:         filepath.Join(e.Home, "Library", "Logs", "segurata"),
		State:        state,
		Out:          filepath.Join(state, "out"),
		Report:       filepath.Join(state, "last-report.md"),
		BrowserState: filepath.Join(state, "schedule-browser.json"),
		SystemdTo:    filepath.Join(e.Home, ".config", "systemd", "user"),
	}
}

// Options are the command-line choices of install and uninstall.
type Options struct {
	Every      time.Duration
	Connectors []string // empty: every installed connector
	Apply      bool
	Yes        bool
}

func (o Options) every() (time.Duration, error) {
	if o.Every == 0 {
		return DefaultEvery, nil
	}
	if o.Every < MinEvery || o.Every%time.Second != 0 {
		return 0, fmt.Errorf("--every must be whole seconds and at least %s", MinEvery)
	}
	return o.Every, nil
}

// runArgs is the command line the agent runs. It names an interval other than the default, which
// bounds how long a run may take.
func (e Env) runArgs(o Options) []string {
	args := []string{e.Exe, "schedule", "run"}
	if o.Every != 0 && o.Every != DefaultEvery {
		args = append(args, "--every", o.Every.String())
	}
	if len(o.Connectors) > 0 {
		args = append(args, "--connectors", strings.Join(o.Connectors, ","))
	}
	return args
}

func (e Env) domain() string  { return "gui/" + strconv.Itoa(e.UID) }
func (e Env) service() string { return e.domain() + "/" + Label }

// Plist is the launchd agent: run `segurata schedule run` every interval, from the state
// directory, with logs in ~/Library/Logs/segurata. It does not run at load, so installing it
// starts nothing until the first interval passes.
func (e Env) Plist(o Options) (string, error) {
	every, err := o.every()
	if err != nil {
		return "", err
	}
	p := e.Paths()
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`)
	key := func(k string) { fmt.Fprintf(&b, "\t<key>%s</key>\n", xmlText(k)) }
	str := func(indent, v string) { fmt.Fprintf(&b, "%s<string>%s</string>\n", indent, xmlText(v)) }
	key("Label")
	str("\t", Label)
	key("ProgramArguments")
	b.WriteString("\t<array>\n")
	for _, a := range e.runArgs(o) {
		str("\t\t", a)
	}
	b.WriteString("\t</array>\n")
	key("StartInterval")
	fmt.Fprintf(&b, "\t<integer>%d</integer>\n", int64(every/time.Second))
	key("RunAtLoad")
	b.WriteString("\t<false/>\n")
	key("WorkingDirectory")
	str("\t", p.State)
	key("EnvironmentVariables")
	b.WriteString("\t<dict>\n\t\t<key>PATH</key>\n")
	str("\t\t", e.Path)
	b.WriteString("\t</dict>\n")
	key("StandardOutPath")
	str("\t", filepath.Join(p.Logs, "inventory.log"))
	key("StandardErrorPath")
	str("\t", filepath.Join(p.Logs, "inventory.err.log"))
	key("ProcessType")
	str("\t", "Background")
	b.WriteString("</dict>\n</plist>\n")
	return b.String(), nil
}

func xmlText(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// SystemdUnits are the Linux equivalent: a oneshot service and a timer that starts it every
// interval (and 15 minutes after boot).
func (e Env) SystemdUnits(o Options) (service, timer string, err error) {
	every, err := o.every()
	if err != nil {
		return "", "", err
	}
	quoted := make([]string, 0, 4)
	for _, a := range e.runArgs(o) {
		quoted = append(quoted, systemdQuote(a))
	}
	service = fmt.Sprintf(`[Unit]
Description=segurata scheduled inventory and report

[Service]
Type=oneshot
WorkingDirectory=%s
Environment=%s
ExecStart=%s
`, e.Paths().State, systemdQuote("PATH="+e.Path), strings.Join(quoted, " "))
	timer = fmt.Sprintf(`[Unit]
Description=Run segurata inventory every %s

[Timer]
OnBootSec=15min
OnUnitActiveSec=%ds

[Install]
WantedBy=timers.target
`, every, int64(every/time.Second))
	return service, timer, nil
}

func systemdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\%$") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$")
	return `"` + r.Replace(s) + `"`
}

// ErrDarwinOnly refuses --apply where only a printed equivalent exists.
var ErrDarwinOnly = errors.New("--apply works on macOS only; on this system, install the printed units by hand")

func (e Env) checkExe() error {
	if !filepath.IsAbs(e.Exe) {
		return fmt.Errorf("cannot tell where the segurata binary lives (%q)", e.Exe)
	}
	if e.TmpDir != "" && strings.HasPrefix(e.Exe, filepath.Clean(e.TmpDir)+string(filepath.Separator)) {
		return fmt.Errorf("%s is in a temporary directory (go run?): build segurata and run it from where it will stay", e.Exe)
	}
	return nil
}

// Install prints the agent and how it is loaded and, with --apply and a confirmation, writes and
// loads it.
func (e Env) Install(ctx context.Context, o Options) error {
	if err := e.checkExe(); err != nil {
		return err
	}
	out := e.IO.Out
	if e.GOOS != "darwin" {
		return e.printSystemd(o)
	}
	plist, err := e.Plist(o)
	if err != nil {
		return err
	}
	p := e.Paths()
	fmt.Fprintf(out, "Agent    %s\nRuns     %s\nEvery    %s\nReport   %s\nLogs     %s\n",
		p.Plist, strings.Join(e.runArgs(o), " "), orDefault(o.Every), p.Report, p.Logs)
	fmt.Fprintf(out, "\n%s\n", plist)
	loaded := e.loaded(ctx)
	fmt.Fprintln(out, "Commands:")
	if loaded {
		fmt.Fprintf(out, "  %s bootout %s   (the agent is loaded now; it is replaced)\n", launchctl, e.service())
	}
	fmt.Fprintf(out, "  write %s (mode 644)\n  %s bootstrap %s %s\n", p.Plist, launchctl, e.domain(), p.Plist)
	fmt.Fprintf(out, "\nUndo: segurata schedule uninstall --apply\n")
	if !o.Apply {
		fmt.Fprintln(out, "\nDry run: nothing was changed. Run again with --apply to install this agent.")
		return nil
	}
	ok, err := e.confirm(o)
	if err != nil || !ok {
		return err
	}
	for _, dir := range []string{filepath.Dir(p.Plist), p.Logs, p.State} {
		mode := os.FileMode(0o700)
		if dir == filepath.Dir(p.Plist) {
			mode = 0o755
		}
		if err := os.MkdirAll(dir, mode); err != nil {
			return err
		}
	}
	if loaded {
		if err := e.launchctl(ctx, "bootout", e.service()); err != nil {
			return err
		}
	}
	if err := os.WriteFile(p.Plist, []byte(plist), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(p.Plist, 0o644); err != nil { // WriteFile keeps an existing file's mode
		return err
	}
	if err := e.launchctl(ctx, "bootstrap", e.domain(), p.Plist); err != nil {
		return err
	}
	fmt.Fprintf(out, "Installed. The first run starts in %s; logs in %s.\n", orDefault(o.Every), p.Logs)
	return nil
}

// Uninstall unloads the agent and removes its plist. Reports, logs and inventories stay.
func (e Env) Uninstall(ctx context.Context, o Options) error {
	out := e.IO.Out
	if e.GOOS != "darwin" {
		p := e.Paths()
		fmt.Fprintf(out, "Commands:\n  systemctl --user disable --now %s.timer\n  rm %s %s\n  systemctl --user daemon-reload\n",
			Unit, filepath.Join(p.SystemdTo, Unit+".service"), filepath.Join(p.SystemdTo, Unit+".timer"))
		if o.Apply {
			return ErrDarwinOnly
		}
		return nil
	}
	p := e.Paths()
	_, statErr := os.Stat(p.Plist)
	exists := statErr == nil
	loaded := e.loaded(ctx)
	if !exists && !loaded {
		fmt.Fprintln(out, "No segurata agent is installed.")
		return nil
	}
	fmt.Fprintln(out, "Commands:")
	if loaded {
		fmt.Fprintf(out, "  %s bootout %s\n", launchctl, e.service())
	}
	if exists {
		fmt.Fprintf(out, "  rm %s\n", p.Plist)
	}
	fmt.Fprintf(out, "Kept: %s and %s.\n", p.State, p.Logs)
	if !o.Apply {
		fmt.Fprintln(out, "\nDry run: nothing was changed. Run again with --apply to uninstall.")
		return nil
	}
	ok, err := e.confirm(o)
	if err != nil || !ok {
		return err
	}
	if loaded {
		if err := e.launchctl(ctx, "bootout", e.service()); err != nil {
			return err
		}
	}
	if exists {
		if err := os.Remove(p.Plist); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "Uninstalled.")
	return nil
}

// Status says whether the agent is installed and loaded, and when the last report was written.
func (e Env) Status(ctx context.Context) error {
	out, p := e.IO.Out, e.Paths()
	if e.GOOS == "darwin" {
		installed := "not installed"
		if _, err := os.Stat(p.Plist); err == nil {
			installed = "installed"
		}
		loaded := "not loaded"
		if e.loaded(ctx) {
			loaded = "loaded"
		}
		fmt.Fprintf(out, "Agent    %s: %s, %s\n", p.Plist, installed, loaded)
		fmt.Fprintf(out, "Logs     %s\n", p.Logs)
	} else {
		fmt.Fprintf(out, "Timer    check with: systemctl --user list-timers %s.timer\n", Unit)
	}
	if st, err := os.Stat(p.Report); err == nil {
		fmt.Fprintf(out, "Report   %s, written %s\n", p.Report, st.ModTime().Format("2006-01-02 15:04"))
	} else {
		fmt.Fprintf(out, "Report   %s: none yet\n", p.Report)
	}
	return nil
}

func (e Env) printSystemd(o Options) error {
	svc, timer, err := e.SystemdUnits(o)
	if err != nil {
		return err
	}
	p := e.Paths()
	fmt.Fprintf(e.IO.Out, "%s:\n\n%s\n%s:\n\n%s\nCommands:\n  mkdir -p %s %s\n  systemctl --user daemon-reload\n  systemctl --user enable --now %s.timer\n",
		filepath.Join(p.SystemdTo, Unit+".service"), svc, filepath.Join(p.SystemdTo, Unit+".timer"), timer, p.SystemdTo, p.State, Unit)
	fmt.Fprintln(e.IO.Out, "\nLogs: journalctl --user -u "+Unit+". Notifications are macOS only; on Linux new findings go to the log.")
	if o.Apply {
		return ErrDarwinOnly
	}
	return nil
}

func (e Env) confirm(o Options) (bool, error) {
	ok, err := confirmFunc(e.IO.In, e.IO.Out, o.Yes, e.TTY)
	if err == nil && !ok {
		fmt.Fprintln(e.IO.Out, "Not applied.")
	}
	return ok, err
}

func (e Env) loaded(ctx context.Context) bool {
	return e.Runner.Run(ctx, launchctl, []string{"print", e.service()}, io.Discard, io.Discard) == nil
}

func (e Env) launchctl(ctx context.Context, args ...string) error {
	var stderr bytes.Buffer
	fmt.Fprintf(e.IO.Err, "$ %s %s\n", launchctl, strings.Join(args, " "))
	if err := e.Runner.Run(ctx, launchctl, args, e.IO.Out, &stderr); err != nil {
		return fmt.Errorf("launchctl %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func orDefault(d time.Duration) time.Duration {
	if d == 0 {
		return DefaultEvery
	}
	return d
}
