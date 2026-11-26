// Package schedule is `segurata schedule`: a launchd user agent on macOS, a Task Scheduler task on
// Windows (on Linux, a printed systemd timer) that runs an inventory and a report on an interval
// and notifies about new P0 and P1 items. Install and uninstall are dry runs unless --apply. See
// docs/architecture.md, "Scheduled runs".
package schedule

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/statefile"
	"github.com/segurata/segurata/internal/tracker"
)

const (
	agentLabel = "com.segurata.inventory" // the launchd agent and its plist
	unit       = "segurata-inventory"     // the systemd user service and timer

	DefaultEvery = 24 * time.Hour
	minEvery     = time.Hour

	launchctl = "/bin/launchctl"
	osascript = "/usr/bin/osascript"
)

// taskName is the Task Scheduler task; a variable so the Windows test registers its own.
var taskName = `segurata\inventory`

// Runner runs one external command; System is the real one.
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error
}

type System struct{}

// stopGrace lets an interrupted inventory write run_end and sync the tracker before it is killed.
var stopGrace = 2 * time.Minute

// Run interrupts a cancelled command and gives it stopGrace to stop.
func (System) Run(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error {
	cmd := scheduledCommand(ctx, name, args...)
	cmd.Cancel = func() error { return proc.Interrupt(cmd) }
	cmd.WaitDelay = stopGrace
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// Env is the machine the schedule is installed on, everything that touches the system included.
type Env struct {
	GOOS   string
	Home   string
	UID    int    // macOS: the launchd domain gui/<uid>
	Exe    string // absolute path of the segurata binary the agent runs
	Path   string // PATH the agent runs with, so connectors find their CLIs and external connectors
	TmpDir string // a binary under it was built by `go run` and will not survive
	// Windows (LoadTaskHost): the account the task runs as, the local application data folder that
	// holds its log, and schtasks.exe and conhost.exe by absolute path.
	UserSID      string
	LocalAppData string
	SchTasks     string
	Conhost      string
	Runner       Runner
	IO           connector.IO
	TTY          bool
	Now          func() time.Time
	// Connectors are the installed connectors: the default selection, and which drive the browser.
	Connectors []connector.Connector
	Config     config.Config
	Browser    func(ctx context.Context, cdpURL string) (cdp.Version, error) // cdp.Brave
	// Tracker is what the inventory's sync writes; zero means tracker.DefaultPaths.
	Tracker tracker.Paths
}

// Paths are the files the schedule uses, all the owner's.
type Paths struct {
	Plist        string // macOS
	Task         string // Windows: the task definition schtasks registers
	Logs         string
	State        string // the agent's working directory
	Out          string
	Report       string
	BrowserState string
	SystemdTo    string // Linux
}

func (e Env) Paths() Paths {
	state := filepath.Join(e.Home, ".segurata")
	p := Paths{
		State:        state,
		Out:          filepath.Join(state, "out"),
		Report:       filepath.Join(state, "last-report.md"),
		BrowserState: filepath.Join(state, "schedule-browser.json"),
	}
	switch e.GOOS {
	case "windows":
		p.Task = filepath.Join(state, "schedule-task.xml")
		p.Logs = filepath.Join(e.LocalAppData, "segurata", "Logs")
	case "darwin":
		p.Plist = filepath.Join(e.Home, "Library", "LaunchAgents", agentLabel+".plist")
		p.Logs = filepath.Join(e.Home, "Library", "Logs", "segurata")
	default:
		p.SystemdTo = filepath.Join(e.Home, ".config", "systemd", "user")
	}
	return p
}

// logFile is where a Windows task's run writes, Task Scheduler keeping no output.
func (p Paths) logFile() string { return filepath.Join(p.Logs, "schedule.log") }

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
	if o.Every < minEvery || o.Every%time.Second != 0 {
		return 0, fmt.Errorf("--every must be whole seconds and at least %s", minEvery)
	}
	return o.Every, nil
}

// runArgs is the command line the agent runs; the interval bounds how long a run may take.
func (e Env) runArgs(o Options) []string {
	args := []string{e.Exe, "schedule", "run"}
	if o.Every != 0 && o.Every != DefaultEvery {
		args = append(args, "--every", o.Every.String())
	}
	if len(o.Connectors) > 0 {
		args = append(args, "--connectors", strings.Join(o.Connectors, ","))
	}
	if e.GOOS == "windows" {
		args = append(args, "--log", e.Paths().logFile())
	}
	return args
}

func (e Env) domain() string  { return "gui/" + strconv.Itoa(e.UID) }
func (e Env) service() string { return e.domain() + "/" + agentLabel }

// Plist is the launchd agent. It does not run at load: installing starts nothing until the first
// interval passes.
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
	str("\t", agentLabel)
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

// SystemdUnits are a oneshot service and the timer that starts it every interval.
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

var errApplyUnsupported = errors.New("--apply works on macOS and Windows only; on this system, install the printed units by hand")

func (e Env) checkExe() error {
	if !filepath.IsAbs(e.Exe) {
		return fmt.Errorf("cannot tell where the segurata binary lives (%q)", e.Exe)
	}
	if e.TmpDir != "" && e.under(e.Exe, e.TmpDir) {
		return fmt.Errorf("%s is in a temporary directory (go run?): build segurata and run it from where it will stay", e.Exe)
	}
	return nil
}

// under reports whether path lies inside dir; Windows paths compare without case.
func (e Env) under(path, dir string) bool {
	prefix := filepath.Clean(dir) + string(filepath.Separator)
	if e.GOOS == "windows" {
		return len(path) > len(prefix) && strings.EqualFold(path[:len(prefix)], prefix)
	}
	return strings.HasPrefix(path, prefix)
}

// agent is what one OS's scheduler needs: the file that defines the job and the commands that
// load, query and unload it.
type agent struct {
	noun       string // "agent", "task"
	file       string
	definition string // printed in the dry run
	access     string // how the file is written, for the dry run
	write      func() error
	load       []string // replaces a loaded job when replaces is set
	replaces   bool
	unload     []string
	query      []string // succeeds while the job is loaded
	loadedAs   string   // "loaded", "registered"
}

func (e Env) agent(o Options) (agent, error) {
	p := e.Paths()
	if e.GOOS == "windows" {
		xml, err := e.TaskXML(o)
		if err != nil {
			return agent{}, err
		}
		return agent{
			noun: "task", file: p.Task, definition: xml, access: "private",
			write:    func() error { return statefile.Write(p.Task, utf16File(xml)) },
			load:     []string{e.SchTasks, "/Create", "/TN", taskName, "/XML", p.Task, "/F"},
			replaces: true,
			unload:   []string{e.SchTasks, "/Delete", "/TN", taskName, "/F"},
			query:    []string{e.SchTasks, "/Query", "/TN", taskName},
			loadedAs: "registered",
		}, nil
	}
	plist, err := e.Plist(o)
	if err != nil {
		return agent{}, err
	}
	return agent{
		noun: "agent", file: p.Plist, definition: plist, access: "mode 644",
		write: func() error {
			if err := os.MkdirAll(filepath.Dir(p.Plist), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p.Plist, []byte(plist), 0o644); err != nil {
				return err
			}
			return os.Chmod(p.Plist, 0o644) // WriteFile keeps an existing file's mode
		},
		load:     []string{launchctl, "bootstrap", e.domain(), p.Plist},
		unload:   []string{launchctl, "bootout", e.service()},
		query:    []string{launchctl, "print", e.service()},
		loadedAs: "loaded",
	}, nil
}

// scheduler is the OS's own scheduler; Linux prints systemd units instead.
func (e Env) scheduler() bool { return e.GOOS == "darwin" || e.GOOS == "windows" }

// Install prints the agent and how it is loaded and, with --apply and a confirmation, writes and
// loads it.
func (e Env) Install(ctx context.Context, o Options) error {
	if err := e.checkExe(); err != nil {
		return err
	}
	if !e.scheduler() {
		return e.printSystemd(o)
	}
	a, err := e.agent(o)
	if err != nil {
		return err
	}
	out := e.IO.Out
	every, _ := o.every() // agent validated it
	p := e.Paths()
	fmt.Fprintf(out, "%-8s %s\nRuns     %s\nEvery    %s\nReport   %s\nLogs     %s\n",
		title(a.noun), a.file, strings.Join(e.runArgs(o), " "), every, p.Report, p.Logs)
	fmt.Fprintf(out, "\n%s\n", a.definition)
	loaded := e.loaded(ctx, a)
	fmt.Fprintln(out, "Commands:")
	if loaded && !a.replaces {
		fmt.Fprintf(out, "  %s   (the %s is %s now; it is replaced)\n", strings.Join(a.unload, " "), a.noun, a.loadedAs)
	}
	fmt.Fprintf(out, "  write %s (%s)\n  %s", a.file, a.access, strings.Join(a.load, " "))
	if loaded && a.replaces {
		fmt.Fprintf(out, "   (the %s is %s now; it is replaced)", a.noun, a.loadedAs)
	}
	fmt.Fprintf(out, "\n\nUndo: segurata schedule uninstall --apply\n")
	if !o.Apply {
		fmt.Fprintf(out, "\nDry run: nothing was changed. Run again with --apply to install this %s.\n", a.noun)
		return nil
	}
	ok, err := e.confirm(o)
	if err != nil || !ok {
		return err
	}
	for _, dir := range []string{p.Logs, p.State} {
		if err := fileacl.MkdirPrivate(dir); err != nil {
			return err
		}
	}
	if loaded && !a.replaces {
		if err := e.command(ctx, a.unload); err != nil {
			return err
		}
	}
	if err := a.write(); err != nil {
		return err
	}
	if err := e.command(ctx, a.load); err != nil {
		return err
	}
	fmt.Fprintf(out, "Installed. The first run starts in %s; logs in %s.\n", every, p.Logs)
	return nil
}

func title(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

// Uninstall unloads the agent and removes its file. Reports, logs and inventories stay.
func (e Env) Uninstall(ctx context.Context, o Options) error {
	out, p := e.IO.Out, e.Paths()
	if !e.scheduler() {
		fmt.Fprintf(out, "Commands:\n  systemctl --user disable --now %s.timer\n  rm %s %s\n  systemctl --user daemon-reload\n",
			unit, filepath.Join(p.SystemdTo, unit+".service"), filepath.Join(p.SystemdTo, unit+".timer"))
		if o.Apply {
			return errApplyUnsupported
		}
		return nil
	}
	a, err := e.agent(Options{})
	if err != nil {
		return err
	}
	_, statErr := os.Stat(a.file)
	exists := statErr == nil
	loaded := e.loaded(ctx, a)
	if !exists && !loaded {
		fmt.Fprintf(out, "No segurata %s is installed.\n", a.noun)
		return nil
	}
	fmt.Fprintln(out, "Commands:")
	if loaded {
		fmt.Fprintf(out, "  %s\n", strings.Join(a.unload, " "))
	}
	if exists {
		fmt.Fprintf(out, "  rm %s\n", a.file)
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
		if err := e.command(ctx, a.unload); err != nil {
			return err
		}
	}
	if exists {
		if err := os.Remove(a.file); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "Uninstalled.")
	return nil
}

// Status says whether the agent is installed and loaded, and when the last report was written. On
// Windows it adds Task Scheduler's own view: the last run and its result.
func (e Env) Status(ctx context.Context) error {
	out, p := e.IO.Out, e.Paths()
	if e.scheduler() {
		a, err := e.agent(Options{})
		if err != nil {
			return err
		}
		installed := "not installed"
		if _, err := os.Stat(a.file); err == nil {
			installed = "installed"
		}
		loaded := e.loaded(ctx, a)
		state := "not " + a.loadedAs
		if loaded {
			state = a.loadedAs
		}
		fmt.Fprintf(out, "%-8s %s: %s, %s\n", title(a.noun), a.file, installed, state)
		fmt.Fprintf(out, "Logs     %s\n", p.Logs)
		if loaded && e.GOOS == "windows" {
			if err := e.Runner.Run(ctx, e.SchTasks, []string{"/Query", "/TN", taskName, "/V", "/FO", "LIST"}, out, io.Discard); err != nil {
				fmt.Fprintf(e.IO.Err, "schtasks /Query: %v\n", err)
			}
		}
	} else {
		fmt.Fprintf(out, "Timer    check with: systemctl --user list-timers %s.timer\n", unit)
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
		filepath.Join(p.SystemdTo, unit+".service"), svc, filepath.Join(p.SystemdTo, unit+".timer"), timer, p.SystemdTo, p.State, unit)
	fmt.Fprintln(e.IO.Out, "\nLogs: journalctl --user -u "+unit+". Notifications are macOS only; on Linux new findings go to the log.")
	if o.Apply {
		return errApplyUnsupported
	}
	return nil
}

func (e Env) confirm(o Options) (bool, error) {
	ok, err := prompt.Confirm(e.IO.In, e.IO.Out, o.Yes, e.TTY)
	if err == nil && !ok {
		fmt.Fprintln(e.IO.Out, "Not applied.")
	}
	return ok, err
}

func (e Env) loaded(ctx context.Context, a agent) bool {
	return e.Runner.Run(ctx, a.query[0], a.query[1:], io.Discard, io.Discard) == nil
}

// command runs argv, echoing it first, as the dry run printed it.
func (e Env) command(ctx context.Context, argv []string) error {
	var stderr bytes.Buffer
	fmt.Fprintf(e.IO.Err, "$ %s\n", strings.Join(argv, " "))
	if err := e.Runner.Run(ctx, argv[0], argv[1:], e.IO.Out, &stderr); err != nil {
		return fmt.Errorf("%s %s: %w: %s", toolName(argv[0]), argv[1], err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// toolName is the last element of a macOS or Windows path, whatever the host.
func toolName(path string) string {
	return strings.TrimSuffix(path[strings.LastIndexAny(path, `/\`)+1:], ".exe")
}
