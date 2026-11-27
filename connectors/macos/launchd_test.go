package macos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/finding"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func jobPlist(label, program string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>--flag</string></array>
</dict></plist>`, label, program)
}

func appPlist(id string) string {
	return fmt.Sprintf(`<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>%s</string></dict></plist>`, id)
}

// leftoverTree has a helper whose binary is gone, a helper whose app is gone, a helper whose app
// is installed, and an agent whose program is in place.
func leftoverTree(t *testing.T, c *Connector) {
	root := c.Root
	writeFile(t, root+"/Library/LaunchDaemons/com.ghost.Helper.plist", jobPlist("com.ghost.Helper", "/Library/PrivilegedHelperTools/com.ghost.Helper"))
	writeFile(t, root+"/Library/LaunchDaemons/com.bear.mac.helper.plist", jobPlist("com.bear.mac.helper", "/Library/PrivilegedHelperTools/com.bear.mac.helper"))
	writeFile(t, root+"/Library/PrivilegedHelperTools/com.bear.mac.helper", "bin")
	writeFile(t, root+"/Library/LaunchDaemons/us.zoom.ZoomDaemon.plist", jobPlist("us.zoom.ZoomDaemon", "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"))
	writeFile(t, root+"/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon", "bin")
	writeFile(t, root+"/Applications/zoom.us.app/Contents/Info.plist", appPlist("us.zoom.xos"))
	writeFile(t, root+"/Library/LaunchAgents/com.example.agent.plist", jobPlist("com.example.agent", "/Applications/Example.app/Contents/MacOS/agent"))
	writeFile(t, root+"/Applications/Example.app/Contents/MacOS/agent", "bin")
	writeFile(t, root+"/Applications/Example.app/Contents/Info.plist", appPlist("com.example.app"))
}

func TestLeftoverHelpersAreLowAndReplaceTheirBackgroundItem(t *testing.T) {
	r := healthy()
	r["/usr/bin/sfltool dumpbtm"] = btmSigned + ` #2:
                 Name: com.ghost.Helper
                 Type: legacy daemon (0x10010)
          Disposition: [enabled, disallowed, visible, notified] (0x9)
           Identifier: 16.com.ghost.Helper
                  URL: file:///Library/LaunchDaemons/com.ghost.Helper.plist
      Executable Path: /Library/PrivilegedHelperTools/com.ghost.Helper
      Team Identifier: JHBA9UTELB
`
	c, _, _ := newTest(t, r)
	leftoverTree(t, c)
	rec := inventory(t, c)

	ghost := rec.ByResource(t, "background_item", "leftover:com.ghost.Helper")
	if ghost.Severity != finding.SevLow || !strings.Contains(ghost.Title, "Leftover privileged helper com.ghost.Helper: its program is missing") ||
		!strings.Contains(ghost.Remediation.Summary, "sudo launchctl bootout system /Library/LaunchDaemons/com.ghost.Helper.plist") {
		t.Errorf("missing program: %s %q %q", ghost.Severity, ghost.Title, ghost.Remediation.Summary)
	}
	bear := rec.ByResource(t, "background_item", "leftover:com.bear.mac.helper")
	if bear.Severity != finding.SevLow || !strings.Contains(bear.Title, "no app from com.bear is installed") {
		t.Errorf("helper without app: %s %q", bear.Severity, bear.Title)
	}
	for _, f := range rec.Findings {
		switch f.Resource.ID {
		case "btm:16.com.ghost.Helper", "leftover:us.zoom.ZoomDaemon", "leftover:com.example.agent":
			t.Errorf("reported %s: %s", f.Resource.ID, f.Title)
		}
	}
}

func TestSfltoolTimeoutIsAnErrorAndFallsBackToDedupedLaunchItems(t *testing.T) {
	r := healthy()
	r["/bin/launchctl list"] = "PID\tStatus\tLabel\n-\t0\tcom.example.agent\n12\t0\tapplication.com.brave.Browser.1234.5678\n-\t0\tcom.apple.Finder\n-\t0\tcom.other.job\n"
	c, fr, _ := newTest(t, r)
	fr.errs = map[string]error{"/usr/bin/sfltool dumpbtm": fmt.Errorf("sfltool did not answer within 2m0s: %w", context.DeadlineExceeded)}
	leftoverTree(t, c)
	rec := inventory(t, c)

	var btm []finding.Status
	for _, s := range rec.Statuses {
		if strings.HasPrefix(s.Detail, "btm:") {
			btm = append(btm, s)
		}
	}
	if len(btm) != 1 || btm[0].State != finding.StateError || btm[0].Scope != "check:btm" || !strings.Contains(btm[0].Detail, "timed out after 2m0s") {
		t.Fatalf("btm status: %+v", btm)
	}
	if f := rec.ByResource(t, "background_item", "launch-item:com.example.agent"); f.Scope != "check:btm" {
		t.Errorf("fallback items share the btm scope the failed status leaves uninspected: %q", f.Scope)
	}
	if f := rec.ByResource(t, "background_item", "leftover:com.ghost.Helper"); f.Scope != "check:leftover:com.ghost.Helper" {
		t.Errorf("leftovers are read from the plists, not sfltool, and keep their own scope: %q", f.Scope)
	}
	ids := map[string]int{}
	for _, f := range rec.Findings {
		if f.Resource.Type == "background_item" {
			ids[f.Resource.ID]++
		}
	}
	want := map[string]int{
		"leftover:com.ghost.Helper":      1,
		"leftover:com.bear.mac.helper":   1,
		"launch-item:us.zoom.ZoomDaemon": 1,
		"launch-item:com.example.agent":  1,
		"launchctl:com.other.job":        1,
	}
	if fmt.Sprint(ids) != fmt.Sprint(want) {
		t.Fatalf("background items %v, want %v", ids, want)
	}
}

func TestSfltoolFailureIsAnError(t *testing.T) {
	c, fr, _ := newTest(t, healthy())
	fr.errs = map[string]error{"/usr/bin/sfltool dumpbtm": errors.New("exit status 64")}
	fr.replies["/usr/bin/sfltool dumpbtm"] = ""
	rec := inventory(t, c)
	for _, s := range rec.Statuses {
		if strings.HasPrefix(s.Detail, "btm:") && (s.State != finding.StateError || !strings.Contains(s.Detail, "exit status 64")) {
			t.Fatalf("status %+v", s)
		}
	}
}

func TestListeningPortFoldsIntoTheBackgroundItemThatRunsIt(t *testing.T) {
	r := healthy()
	r["/usr/bin/sfltool dumpbtm"] = btmSigned + ` #2:
                 Name: Spotify
                 Type: login item (0x4)
          Disposition: [enabled, allowed, visible, notified] (0x9)
           Identifier: com.spotify.client.startuphelper
                  URL: file:///Applications/Spotify.app/
      Executable Path: Contents/Resources/SpotifyLauncher
      Team Identifier: 2FNC3A47ZF
`
	r[netstatBin+" -anv -p tcp"] = netstatHeader + nsLine("tcp4", "*.57621", "LISTEN", "77") + nsLine("tcp4", "*.88", "LISTEN", "81")
	r[psBin+" -axo pid=,comm="] = "   77 /Applications/Spotify.app/Contents/MacOS/Spotify\n   81 /System/Library/PrivateFrameworks/Heimdal.framework/Helpers/kdc\n"
	c, _, _ := newTest(t, r)
	rec := inventory(t, c)
	sp := rec.ByResource(t, "background_item", "btm:com.spotify.client.startuphelper")
	if fmt.Sprint(sp.Evidence["listening_ports"]) != "[57621]" || !strings.Contains(fmt.Sprint(sp.Evidence["detail"]), "Spotify listens on TCP 57621") {
		t.Errorf("spotify item: %v", sp.Evidence)
	}
	rec.ByResource(t, "listening_port", "listen-88")
	for _, f := range rec.Findings {
		if f.Resource.ID == "listen-57621" {
			t.Errorf("port owned by a background item still has its own row: %s", f.Title)
		}
	}
}

func TestScreenIdleCheck(t *testing.T) {
	set := func(v string) setting { return setting{value: v, set: true} }
	cases := []struct {
		name           string
		saver, display setting
		ok             bool
		sev            finding.Severity
		skip           bool
		detail         string
	}{
		{"display within limit, saver unset", setting{}, set("10"), true, "", false, "screen saver not set (macOS default), display off after 600 s"},
		{"saver short, display long", set("300"), set("30"), true, "", false, ""},
		{"both long", set("1200"), set("30"), false, finding.SevLow, false, ""},
		{"saver never, display long", set("0"), set("20"), false, finding.SevLow, false, ""},
		{"both never", set("0"), set("0"), false, finding.SevMedium, false, ""},
		{"display unreadable, saver unset", setting{}, setting{err: "pmset: exit status 1"}, false, "", true, "unreadable (displaysleep: pmset: exit status 1)"},
		{"saver never, display unreadable", set("0"), setting{err: "boom"}, false, "", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := screenIdleCheck(tc.saver, tc.display)
			if ch.OK != tc.ok || (ch.Skip != "") != tc.skip || (!tc.ok && !tc.skip && ch.Sev != tc.sev) {
				t.Fatalf("ok=%v skip=%q sev=%s title=%q", ch.OK, ch.Skip, ch.Sev, ch.Title)
			}
			if tc.skip && ch.SkipState != finding.StateError {
				t.Errorf("a failed read is an error, not unsupported: %q", ch.SkipState)
			}
			if tc.detail != "" && !strings.Contains(ch.Detail, tc.detail) {
				t.Errorf("detail %q", ch.Detail)
			}
		})
	}
}

func TestScreensaverFallsBackFromCurrentHost(t *testing.T) {
	r := healthy()
	r["/usr/bin/pmset -g"] = "System-wide power settings:\n displaysleep         30\n"
	r["/usr/bin/defaults read com.apple.screensaver idleTime"] = "300"
	c, fr, _ := newTest(t, r)
	rec := inventory(t, c)
	for _, f := range rec.Findings {
		if f.Resource.ID == "screensaver" {
			t.Fatalf("a 5-minute screen saver from the global domain passes: %+v", f)
		}
	}
	if !strings.Contains(strings.Join(fr.calls, "\n"), "-currentHost read com.apple.screensaver idleTime") {
		t.Fatal("the per-host value is read first")
	}
}

func TestBinaryPlistIsConvertedByPlutilForThatFileOnly(t *testing.T) {
	c, fr, _ := newTest(t, healthy())
	p := filepath.Join(c.Root, "job.plist")
	writeFile(t, p, "bplist00\x00binary")
	fr.replies[strings.Join([]string{plutilBin, "-convert", "xml1", "-o", "-", p}, " ")] = jobPlist("com.example.bin", "/usr/local/bin/x")
	m, err := c.readPlist(context.Background(), p)
	if err != nil || m["Label"] != "com.example.bin" {
		t.Fatalf("m=%v err=%v", m, err)
	}
	if _, err := guard(fr).Run(context.Background(), plutilBin, "-convert", "xml1", "-o", "-", p); !errors.Is(err, cli.ErrRefused) {
		t.Fatal("plutil is not on the fixed allowlist; only readPlist may run it, for the file it read")
	}
}
