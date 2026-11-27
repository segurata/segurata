package windows

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const testSys32 = `C:\Windows\System32`

// fakeRegistry holds keys by hive and path; errs makes a key fail to open.
type fakeRegistry struct {
	keys map[string]map[string]RegValue
	errs map[string]error
	has  []string // value names Has was asked about
}

func regPath(h Hive, path string) string { return string(h) + `\` + path }

func (r *fakeRegistry) Read(h Hive, path string, names ...string) (map[string]RegValue, error) {
	if err := r.errs[regPath(h, path)]; err != nil {
		return nil, err
	}
	k, ok := r.keys[regPath(h, path)]
	if !ok {
		return nil, fs.ErrNotExist
	}
	out := map[string]RegValue{}
	for _, n := range names {
		if v, ok := k[n]; ok {
			out[n] = v
		}
	}
	return out, nil
}

func (r *fakeRegistry) Has(h Hive, path, name string) (bool, error) {
	r.has = append(r.has, name)
	if err := r.errs[regPath(h, path)]; err != nil {
		return false, err
	}
	_, ok := r.keys[regPath(h, path)][name]
	return ok, nil
}

func (r *fakeRegistry) set(h Hive, path, name string, v RegValue) {
	k := regPath(h, path)
	if r.keys[k] == nil {
		r.keys[k] = map[string]RegValue{}
	}
	r.keys[k][name] = v
}

func sz(s string) RegValue    { return RegValue{Type: regSZ, Text: s} }
func dword(s string) RegValue { return RegValue{Type: regDWORD, Text: s} }

// healthyRegistry is a PC whose registry raises nothing: values as Windows 11 sets them.
func healthyRegistry() *fakeRegistry {
	r := &fakeRegistry{keys: map[string]map[string]RegValue{}, errs: map[string]error{}}
	r.set(HKCU, desktopKey, "ScreenSaveActive", sz("1"))
	r.set(HKCU, desktopKey, "ScreenSaverIsSecure", sz("1"))
	r.set(HKCU, desktopKey, "ScreenSaveTimeOut", sz("300"))
	r.set(HKCU, desktopKey, "SCRNSAVE.EXE", sz(`%SystemRoot%\system32\scrnsave.scr`))
	r.set(HKLM, systemPolicyKey, "EnableLUA", dword("1"))
	r.set(HKLM, systemPolicyKey, "ConsentPromptBehaviorAdmin", dword("5"))
	r.set(HKLM, winlogonKey, "AutoAdminLogon", sz("0"))
	r.set(HKLM, tsKey, "fDenyTSConnections", dword("1"))
	r.set(HKLM, rdpTCPKey, "UserAuthentication", dword("1"))
	r.set(HKLM, lanmanKey, "NullSessionPipes", RegValue{Type: 7})
	r.set(HKLM, secureBootKey, "UEFISecureBootEnabled", dword("1"))
	r.set(HKLM, wuauservKey, "Start", dword("3"))
	return r
}

// fakeRunner answers the probe with a testdata file and records what it was asked to run.
type fakeRunner struct {
	out   string
	err   error
	calls [][]string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	return []byte(f.out), f.err
}

func probeFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var testNow = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

type recordingExec struct{ steps [][]string }

func (e *recordingExec) Run(_ context.Context, s connector.Step, _ connector.IO) error {
	e.steps = append(e.steps, s.Argv)
	return nil
}

func newTest(t *testing.T, probeOut string, reg *fakeRegistry) (*Connector, *fakeRunner, *recordingExec) {
	t.Helper()
	t.Setenv("SystemRoot", `C:\Windows`)
	fr := &fakeRunner{out: probeOut}
	ex := &recordingExec{}
	return &Connector{Run: fr, Exec: ex, Reg: reg, OS: "windows",
		System32: func() (string, error) { return testSys32, nil },
		Host:     func() (string, error) { return "DESKTOP-TEST", nil },
		Now:      func() time.Time { return testNow },
		Exists: func(p string) bool {
			return strings.EqualFold(p, testSys32+`\scrnsave.scr`) || p == filepath.Join(testSys32, "scrnsave.scr")
		},
		DesktopKey: desktopKey}, fr, ex
}

func inventory(t *testing.T, c *Connector, req connector.Request) *httpxtest.Recorder {
	t.Helper()
	rec := &httpxtest.Recorder{}
	if err := c.Inventory(context.Background(), req, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// severities is each finding's resource id and severity, for comparing whole runs.
func severities(rec *httpxtest.Recorder) map[string]finding.Severity {
	out := map[string]finding.Severity{}
	for _, f := range rec.Findings {
		out[f.Resource.ID] = f.Severity
	}
	return out
}

// skips is each scope a run did not inspect, with the status detail.
func skips(rec *httpxtest.Recorder) map[string]finding.Status {
	out := map[string]finding.Status{}
	for _, s := range rec.Statuses {
		if s.Scope != "" {
			out[s.Scope] = s
		}
	}
	return out
}

func TestParseProbeKeepsFieldsAndFailures(t *testing.T) {
	p := parseProbe("self\tsid=S-1-5-21-1\televated=True\r\nbrowser\tname=brave.exe\tcmd=a --x=1 b\nerr\tsec=mp\tdenied=True\tcode=AccessDenied\tmsg=no\n\n")
	if s, _ := p.one("self"); s.get("sid") != "S-1-5-21-1" || !p.elevated() {
		t.Errorf("self %+v", s)
	}
	if b, _ := p.one("browser"); b.get("cmd") != "a --x=1 b" {
		t.Errorf("a value keeps its = signs: %q", b.get("cmd"))
	}
	if f, ok := p.failure("mp"); !ok || !f.is("denied") || f.get("code") != "AccessDenied" {
		t.Errorf("failure %+v", f)
	}
	if _, ok := p.failure("self"); ok {
		t.Error("a section that answered is no failure")
	}
}

// The probe script goes to powershell.exe as one argument, which a double quote would end.
func TestProbeScriptHasNoDoubleQuote(t *testing.T) {
	if strings.Contains(probeScript, `"`) {
		t.Fatal("probe.ps1 holds a double quote")
	}
	for _, sec := range []string{"self", "vol", "bde", "fw", "mp", "av", "fwp", "wu", "reboot", "tcp", "browser", "user", "admin", "share", "feature"} {
		if !strings.Contains(probeScript, "'"+sec+"'") {
			t.Errorf("probe.ps1 has no section %s", sec)
		}
	}
	if strings.Contains(probeScript, "Get-") || strings.Contains(probeScript, "Import-Module") {
		t.Error("probe.ps1 calls a cmdlet: it must load no module")
	}
}

func TestHealthyPCRaisesNothingAboveInfo(t *testing.T) {
	c, fr, _ := newTest(t, probeFile(t, "probe-healthy.txt"), healthyRegistry())
	rec := inventory(t, c, connector.Request{})
	for _, f := range rec.Findings {
		if f.Severity != finding.SevInfo {
			t.Errorf("healthy PC reported %s %s: %s (%v)", f.Severity, f.Resource.ID, f.Title, f.Evidence["detail"])
		}
		if f.Kind != finding.KindSetting || f.Account != "DESKTOP-TEST" {
			t.Errorf("kind %s account %s", f.Kind, f.Account)
		}
	}
	if got := severities(rec); !slices.Equal(slices.Sorted(maps.Keys(got)), []string{"listen-windows-services"}) {
		t.Errorf("findings %v", got)
	}
	if s := skips(rec); len(s) != 0 {
		t.Errorf("healthy PC skipped %v", s)
	}
	want := []string{testSys32 + `/WindowsPowerShell/v1.0/powershell.exe`, "-NoProfile", "-NonInteractive", "-Command", probeScript}
	if len(fr.calls) != 1 || !slices.Equal(fr.calls[0], append([]string{filepath.Join(testSys32, "WindowsPowerShell", "v1.0", "powershell.exe")}, want[1:]...)) {
		t.Errorf("ran %d commands: %q", len(fr.calls), fr.calls)
	}
}

// exposedRegistry is a PC with every registry-read risk.
func exposedRegistry() *fakeRegistry {
	r := healthyRegistry()
	r.set(HKCU, desktopKey, "ScreenSaveActive", sz("0"))
	r.set(HKLM, systemPolicyKey, "EnableLUA", dword("0"))
	r.set(HKLM, systemPolicyKey, "ConsentPromptBehaviorAdmin", dword("0"))
	r.set(HKLM, winlogonKey, "AutoAdminLogon", sz("1"))
	r.set(HKLM, winlogonKey, "DefaultUserName", sz("José"))
	r.set(HKLM, winlogonKey, "DefaultPassword", sz("never read"))
	r.set(HKLM, tsKey, "fDenyTSConnections", dword("0"))
	r.set(HKLM, rdpTCPKey, "UserAuthentication", dword("0"))
	r.set(HKLM, secureBootKey, "UEFISecureBootEnabled", dword("0"))
	r.set(HKLM, wuauservKey, "Start", dword("4"))
	r.set(HKLM, auPolicyKey, "NoAutoUpdate", dword("1"))
	return r
}

func TestExposedPCGetsEachSeverity(t *testing.T) {
	reg := exposedRegistry()
	c, _, _ := newTest(t, probeFile(t, "probe-exposed.txt"), reg)
	rec := inventory(t, c, connector.Request{})
	want := map[string]finding.Severity{
		"bitlocker-c":                       finding.SevHigh,
		"bitlocker-d":                       finding.SevMedium,
		"firewall-domain":                   finding.SevLow,
		"firewall-private-inbound":          finding.SevMedium,
		"firewall-public":                   finding.SevHigh,
		"antivirus":                         finding.SevHigh,
		"update-service":                    finding.SevMedium,
		"update-policy":                     finding.SevMedium,
		"updates-stale":                     finding.SevMedium,
		"updates-restart":                   finding.SevMedium,
		"screen-lock":                       finding.SevMedium,
		"guest-account":                     finding.SevMedium,
		"password-not-required:tecnico":     finding.SevMedium,
		"local-admin:tecnico":               finding.SevHigh,
		`local-admin:CONTOSO\Domain Admins`: finding.SevInfo,
		"auto-logon":                        finding.SevHigh,
		"uac":                               finding.SevHigh,
		"uac-prompt":                        finding.SevHigh,
		"secure-boot":                       finding.SevMedium,
		"remote-desktop":                    finding.SevMedium,
		"remote-desktop-nla":                finding.SevHigh,
		"smb1":                              finding.SevHigh,
		"share:Fotos":                       finding.SevHigh,
		"share:Trabajo":                     finding.SevMedium,
		"listen-22":                         finding.SevMedium,
		"listen-5985":                       finding.SevMedium,
		"listen-8080":                       finding.SevInfo,
		"listen-windows-services":           finding.SevInfo,
		"brave-remote-debugging":            finding.SevHigh,
	}
	got := severities(rec)
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("%s: got %q, want %s", id, got[id], sev)
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("unexpected finding %s %s", id, got[id])
		}
	}
	for _, f := range rec.Findings {
		if f.Remediation.Summary == "" {
			t.Errorf("%s has no remediation text", f.Resource.ID)
		}
		if strings.Contains(fmt.Sprint(f.Evidence), "never read") {
			t.Errorf("%s carries the stored password", f.Resource.ID)
		}
	}
	if slices.Contains(reg.has, "DefaultPassword") == false {
		t.Error("auto-logon did not ask whether a password is stored")
	}
	if s := skips(rec); len(s) != 0 {
		t.Errorf("an elevated run skipped %v", s)
	}
	b := rec.ByResource(t, "windows_setting", "brave-remote-debugging")
	if b.Blast != finding.BlastBrowser || !strings.Contains(fmt.Sprint(b.Evidence["listening"]), "127.0.0.1") {
		t.Errorf("brave %+v", b)
	}
	if rec.ByResource(t, "windows_setting", "auto-logon").Evidence["password_in_registry"] != true {
		t.Error("auto-logon does not say the password is in the registry")
	}
	// Win32_EncryptableVolume, when it answers, decides over the shell property.
	if d := rec.ByResource(t, "windows_setting", "bitlocker-c").Evidence["source"]; !strings.HasPrefix(fmt.Sprint(d), "Win32_EncryptableVolume") {
		t.Errorf("C: source %v", d)
	}
}

// What a standard user cannot read is a scope not inspected, with the elevated command, never a
// clean result.
func TestStandardUserGetsTheElevatedCommandForWhatItCannotRead(t *testing.T) {
	c, _, _ := newTest(t, probeFile(t, "probe-standard-user.txt"), healthyRegistry())
	rec := inventory(t, c, connector.Request{})
	want := map[string]string{
		"check:bitlocker":    "manage-bde -status C:",
		"check:antivirus":    "Get-MpComputerStatus",
		"check:smb1":         "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
		"check:share-access": "Get-SmbShareAccess -Name 'Fotos'",
	}
	got := skips(rec)
	for scope, cmd := range want {
		s, ok := got[scope]
		if !ok {
			t.Errorf("%s was not reported as not inspected", scope)
			continue
		}
		if s.State != finding.StateUnsupported || !strings.Contains(s.Detail, "needs admin: run `"+cmd+"` in an elevated PowerShell") {
			t.Errorf("%s: %s %q", scope, s.State, s.Detail)
		}
	}
	if s := got["check:listen"]; s.State != finding.StateError {
		t.Errorf("a failure that is not a refusal is an error: %+v", s)
	}
	for _, line := range rec.Logs {
		for _, id := range []string{"bitlocker-c", "antivirus", "smb1"} {
			if strings.HasPrefix(line, "OK "+id+":") {
				t.Errorf("%s logged as passing: %s", id, line)
			}
		}
	}
	if f := rec.ByResource(t, "share", "share:Fotos"); f.Severity != finding.SevMedium {
		t.Errorf("an unreadable share is still a shared folder: %+v", f)
	}
}

func TestProbeFailureLeavesEveryProbeCheckNotInspected(t *testing.T) {
	c, fr, _ := newTest(t, "", healthyRegistry())
	fr.err = &cli.Error{Cmd: "powershell", Stderr: "boom", Err: errors.New("exit status 1")}
	rec := inventory(t, c, connector.Request{})
	got := skips(rec)
	for _, scope := range []string{"check:bitlocker", "check:firewall", "check:antivirus", "check:updates", "check:local-accounts", "check:smb1", "check:shares", "check:listen", "check:browser-remote-debugging"} {
		if s, ok := got[scope]; !ok || s.State != finding.StateError || !strings.Contains(s.Detail, "boom") {
			t.Errorf("%s: %+v", scope, s)
		}
	}
	// The registry checks still ran.
	if _, ok := got["check:uac"]; ok {
		t.Error("uac skipped although the registry answered")
	}
}

func TestRegistryKeyRefusedIsNotInspected(t *testing.T) {
	reg := healthyRegistry()
	reg.errs[regPath(HKLM, secureBootKey)] = fs.ErrPermission
	reg.errs[regPath(HKLM, systemPolicyKey)] = errors.New("bad handle")
	c, _, _ := newTest(t, probeFile(t, "probe-healthy.txt"), reg)
	got := skips(inventory(t, c, connector.Request{}))
	if s := got["check:secure-boot"]; s.State != finding.StateUnsupported || !strings.Contains(s.Detail, `Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'`) {
		t.Errorf("secure boot %+v", s)
	}
	if s := got["check:uac"]; s.State != finding.StateError {
		t.Errorf("uac %+v", s)
	}
	if s := got["check:screen-lock"]; s.State != finding.StateError {
		t.Errorf("screen lock reads the machine inactivity limit from the same key: %+v", s)
	}
}

func TestSecureBootStateAbsentIsNotInspected(t *testing.T) {
	reg := healthyRegistry()
	delete(reg.keys, regPath(HKLM, secureBootKey))
	c, _, _ := newTest(t, probeFile(t, "probe-healthy.txt"), reg)
	if s := skips(inventory(t, c, connector.Request{}))["check:secure-boot"]; s.State != finding.StateUnsupported || !strings.Contains(s.Detail, "legacy BIOS") {
		t.Errorf("%+v", s)
	}
}

func TestOffWindowsIsUnsupported(t *testing.T) {
	c, fr, _ := newTest(t, "", healthyRegistry())
	c.OS = "darwin"
	rec := inventory(t, c, connector.Request{})
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateUnsupported || len(rec.Findings) != 0 || len(fr.calls) != 0 {
		t.Fatalf("%+v %v", rec.Statuses, fr.calls)
	}
	if c.Doctor(context.Background(), connector.Request{}) != nil {
		t.Error("doctor checks something off Windows")
	}
	if _, err := c.WithCredentials(connector.Credentials{}).Plan(context.Background(), screenFinding()); err == nil {
		t.Error("planned a registry change off Windows")
	}
}

func TestGuardRunsOnlyTheProbe(t *testing.T) {
	c, fr, _ := newTest(t, "", healthyRegistry())
	ps, _ := c.powershell()
	for _, argv := range [][]string{
		{ps, "-NoProfile", "-NonInteractive", "-Command", "Remove-Item C:\\"},
		{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", probeScript},
		{ps, "-NoProfile", "-Command", probeScript},
	} {
		if _, err := c.guard().Run(context.Background(), argv...); !errors.Is(err, cli.ErrRefused) {
			t.Errorf("%q: %v", argv[:4], err)
		}
	}
	if len(fr.calls) != 0 {
		t.Errorf("ran %v", fr.calls)
	}
}

func TestConfigRejectsABadLockLimit(t *testing.T) {
	c, _, _ := newTest(t, probeFile(t, "probe-healthy.txt"), healthyRegistry())
	err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{lockLimitKey: "ten"}}, &httpxtest.Recorder{})
	if err == nil || !strings.Contains(err.Error(), lockLimitKey) {
		t.Fatal(err)
	}
}

func TestDescribe(t *testing.T) {
	d := New().Describe()
	if d.Name != "windows" || !slices.Equal(d.Needs, []string{"os:windows"}) || d.Theme != finding.ThemeWindows {
		t.Fatalf("%+v", d)
	}
	if got := New().Track(finding.Finding{}); got == nil || *got != (finding.Track{Group: finding.GroupFinding}) {
		t.Fatalf("%+v", got)
	}
}

func TestDoctorSaysWhatAStandardUserCannotRead(t *testing.T) {
	c, _, _ := newTest(t, probeFile(t, "probe-standard-user.txt"), healthyRegistry())
	levels := map[string]connector.Level{}
	for _, ch := range c.Doctor(context.Background(), connector.Request{}) {
		levels[ch.What] = ch.Level
		if ch.Level != connector.OK && ch.Fix == "" {
			t.Errorf("%s has no fix", ch.What)
		}
		if ch.What == "Microsoft Defender (MSFT_MpComputerStatus)" && !strings.Contains(ch.Fix, "Get-MpComputerStatus") {
			t.Errorf("defender fix %q", ch.Fix)
		}
	}
	for what, lvl := range map[string]connector.Level{
		"BitLocker (Win32_EncryptableVolume)":          connector.Warn,
		"Microsoft Defender (MSFT_MpComputerStatus)":   connector.Warn,
		"SMB1Protocol feature (Win32_OptionalFeature)": connector.Warn,
		"listening ports (MSFT_NetTCPConnection)":      connector.Warn,
		"Defender Firewall (INetFwPolicy2)":            connector.OK,
		"registry":                                     connector.OK,
	} {
		if levels[what] != lvl {
			t.Errorf("%s: %s, want %s", what, levels[what], lvl)
		}
	}
	c, fr, _ := newTest(t, "", healthyRegistry())
	fr.err = errors.New("not found")
	got := c.Doctor(context.Background(), connector.Request{})
	if len(got) != 1 || got[0].Level != connector.Fail || got[0].What != "Windows PowerShell" {
		t.Errorf("%+v", got)
	}
}
