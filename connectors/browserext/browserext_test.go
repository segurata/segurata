package browserext

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

// ct writes a time the way Chromium stores it.
func ct(t time.Time) string { return fmt.Sprint(t.UnixMicro() + 11644473600*1_000_000) }

func ago(days int) string { return ct(now.AddDate(0, 0, -days)) }

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ext(loc int, name string, installedDaysAgo, updatedDaysAgo int, api, hosts string, extra string) string {
	return fmt.Sprintf(`{"location":%d,"from_webstore":%t,"manifest":{"name":%q,"version":"1.0"},"first_install_time":%q,"last_update_time":%q,"active_permissions":{"api":[%s],"explicit_host":[%s]}%s}`,
		loc, loc != locUnpacked, name, ago(installedDaysAgo), ago(updatedDaysAgo), api, hosts, extra)
}

// fixture builds Brave with a daily profile and one untouched for two years, and a Chrome profile.
func fixture(t *testing.T) *Connector {
	home := t.TempDir()
	brave := filepath.Join(home, browsers[0].dirs["darwin"])
	mustWrite(t, filepath.Join(brave, "Local State"), fmt.Sprintf(`{"profile":{"info_cache":{"Default":{"active_time":%d},"Profile 4":{"active_time":%d}}}}`,
		now.Add(-time.Hour).Unix(), now.AddDate(-2, 0, 0).Unix()))
	unpacked := filepath.Join(home, "src", "tool")
	mustWrite(t, filepath.Join(unpacked, "manifest.json"), `{"name":"__MSG_appName__","version":"0.3","default_locale":"es"}`)
	mustWrite(t, filepath.Join(unpacked, "_locales", "es", "messages.json"), `{"APPNAME":{"message":"Lista de Espera"}}`)
	mustWrite(t, filepath.Join(brave, "Default", "Preferences"), `{"profile":{"name":"Personal"},"extensions":{"settings":{
		"builtin":{"location":5,"manifest":{"name":"Brave internal"}}}}}`)
	mustWrite(t, filepath.Join(brave, "Default", "Secure Preferences"), `{"extensions":{"settings":{
		"aeblfdkhhhdcdjpifhhbdiojplfjncoa":`+ext(1, "1Password", 100, 3, `"storage","nativeMessaging"`, `"<all_urls>"`, "")+`,
		"nngceckbapebfimnlniiiahkandclblb":`+ext(1, "Bitwarden", 900, 5, `"storage"`, `"<all_urls>"`, "")+`,
		"acmacodkjbdgmoleebolmdjonilkdbch":`+ext(1, "Rabby Wallet", 300, 10, `"storage"`, `"<all_urls>"`, "")+`,
		"hehggadaopoacecdllhhajmbjkdcmajg":`+ext(1, "ChatGPT", 50, 2, `"debugger","history","downloads"`, `"<all_urls>"`, "")+`,
		"neebplgakaahbhdphmkckjjcegoiijjo":`+ext(1, "Keepa - Amazon Price Tracker", 400, 20, `"webRequest","storage"`, `"<all_urls>"`, "")+`,
		"oldunpacked":`+ext(4, "Old helper", 800, 600, `"tabs"`, `"https://example.com/*"`, "")+`,
		"freshunpacked":{"location":4,"path":`+fmt.Sprintf("%q", unpacked)+`,"first_install_time":"`+ago(40)+`","last_update_time":"`+ago(5)+`","active_permissions":{"api":["downloads","scripting"],"explicit_host":["https://crm.example.com/*"]}},
		"docs":`+ext(6, "Docs Offline", 500, 30, `"storage"`, `"https://docs.google.com/*"`, "")+`,
		"clicker":`+ext(1, "Clicker", 30, 30, `"cookies"`, `"<all_urls>"`, `,"withholding_permissions":true`)+`,
		"off":`+ext(1, "Off", 30, 30, `"cookies"`, `"<all_urls>"`, `,"state":0`)+`}}}`)
	mustWrite(t, filepath.Join(brave, "Profile 4", "Preferences"), `{"profile":{"name":"Perfil 1"}}`)
	mustWrite(t, filepath.Join(brave, "Profile 4", "Secure Preferences"), `{"extensions":{"settings":{
		"nngceckbapebfimnlniiiahkandclblb":`+ext(1, "Bitwarden", 950, 700, `"storage"`, `"<all_urls>"`, "")+`,
		"nkbihfbeogaeaoehlefnkodbefgpgknn":`+ext(1, "MetaMask", 950, 700, `"storage"`, `"<all_urls>"`, "")+`}}}`)
	chrome := filepath.Join(home, browsers[1].dirs["darwin"])
	mustWrite(t, filepath.Join(chrome, "Default", "Secure Preferences"), `{"extensions":{"settings":{
		"reactdev":`+ext(1, "React Developer Tools", 100, 10, `"debugger"`, `"<all_urls>"`, "")+`}}}`)
	return &Connector{Home: func() (string, error) { return home, nil }, Now: func() time.Time { return now }, OS: "darwin"}
}

func run(t *testing.T, c *Connector) *httpxtest.Recorder {
	t.Helper()
	rec := &httpxtest.Recorder{}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestTriageVerdicts(t *testing.T) {
	rec := run(t, fixture(t))
	cases := []struct {
		browser, id, verdict string
		sev                  finding.Severity
		reason               string
	}{
		{"Brave", "hehggadaopoacecdllhhajmbjkdcmajg", "remove", finding.SevHigh, "debugger permission without being a dev tool"},
		{"Brave", "nngceckbapebfimnlniiiahkandclblb", "remove", finding.SevHigh, "[Personal] second password manager in this profile; 1Password is the primary one"},
		{"Brave", "oldunpacked", "remove", finding.SevMedium, "unpacked developer extension not updated since"},
		{"Brave", "freshunpacked", "review", finding.SevLow, "unpacked developer extension: no store review"},
		{"Brave", "acmacodkjbdgmoleebolmdjonilkdbch", "review", finding.SevMedium, "crypto wallet in a profile used for daily browsing"},
		{"Brave", "neebplgakaahbhdphmkckjjcegoiijjo", "review", finding.SevMedium, "reads and changes all sites and uses webRequest"},
		{"Brave", "aeblfdkhhhdcdjpifhhbdiojplfjncoa", "review", finding.SevMedium, "reads and changes all sites and uses nativeMessaging"},
		{"Brave", "nkbihfbeogaeaoehlefnkodbefgpgknn", "review", finding.SevLow, "not updated since"},
		{"Brave", "docs", "keep", finding.SevInfo, "no sensitive permissions"},
		{"Brave", "clicker", "keep", finding.SevInfo, "limited permissions: cookies, all sites, on click"},
		{"Brave", "off", "review", finding.SevLow, "disabled"},
		{"Chrome", "reactdev", "review", finding.SevMedium, "reads and changes all sites and uses debugger"},
	}
	for _, c := range cases {
		var f *finding.Finding
		for i := range rec.Findings {
			if rec.Findings[i].Account == c.browser && rec.Findings[i].Resource.ID == c.id {
				f = &rec.Findings[i]
			}
		}
		if f == nil {
			t.Errorf("%s %s: no finding", c.browser, c.id)
			continue
		}
		reasons := strings.Join(f.Evidence["reasons"].([]string), " | ")
		if f.Evidence["verdict"] != c.verdict || f.Severity != c.sev || !strings.Contains(reasons, c.reason) || !strings.Contains(f.Title, ": "+c.verdict+" (") {
			t.Errorf("%s: %s %s %q; want %s %s %q", f.Resource.Name, f.Evidence["verdict"], f.Severity, reasons, c.verdict, c.sev, c.reason)
		}
		if f.Remediation.Automatable || f.Remediation.Action != "" || !strings.Contains(f.Remediation.Summary, "://extensions/?id="+c.id) {
			t.Errorf("%s remediation %+v", c.id, f.Remediation)
		}
	}
	for _, f := range rec.Findings {
		if f.Resource.ID == "builtin" {
			t.Error("component extensions shipped with Brave should be skipped")
		}
	}
}

func TestOneFindingPerExtensionAcrossProfiles(t *testing.T) {
	rec := run(t, fixture(t))
	f := rec.ByResource(t, "browser_extension", "nngceckbapebfimnlniiiahkandclblb")
	profiles := f.Evidence["profiles"].([]map[string]any)
	if len(profiles) != 2 || profiles[0]["profile"] != "Personal" || profiles[1]["profile"] != "Perfil 1" {
		t.Fatalf("profiles %v", profiles)
	}
	if profiles[1]["updated"] != now.AddDate(0, 0, -700).Format(time.DateOnly) || profiles[1]["source"] != "web store" || profiles[1]["verdict"] != "review" {
		t.Errorf("Perfil 1 install %v", profiles[1])
	}
	if f.Evidence["category"] != catPasswords || f.Evidence["url"] != "brave://extensions/?id=nngceckbapebfimnlniiiahkandclblb" ||
		!strings.Contains(f.Remediation.Summary, "profiles Personal, Perfil 1") {
		t.Errorf("evidence %v summary %q", f.Evidence, f.Remediation.Summary)
	}
	lista := rec.ByResource(t, "browser_extension", "freshunpacked")
	if lista.Resource.Name != "Lista de Espera" || lista.Evidence["profiles"].([]map[string]any)[0]["source"] != "unpacked (developer mode)" {
		t.Errorf("unpacked manifest not read from its folder: %q %v", lista.Resource.Name, lista.Evidence["profiles"])
	}
	chat := rec.ByResource(t, "browser_extension", "hehggadaopoacecdllhhajmbjkdcmajg")
	if fmt.Sprint(chat.Evidence["capabilities"]) != "[read and change all sites debugger history downloads]" {
		t.Errorf("capabilities %v", chat.Evidence["capabilities"])
	}
}

func TestDuplicatePrimary(t *testing.T) {
	day := now.AddDate(0, 0, -400)
	pm := func(id, name string, at time.Time) install {
		return install{profile: "Personal", id: id, name: name, enabled: true, fromStore: true, location: locWebStore, installed: at, updated: now}
	}
	verdicts := func(ins []install, preferred []string) map[string]string {
		out := map[string]string{}
		for _, a := range assess(ins, now, preferred) {
			out[a.name] = a.verdict.String() + ": " + a.reasons[0]
		}
		return out
	}
	// Installed the same day (a migration): nothing says which one is kept.
	same := []install{pm("aeblfdkhhhdcdjpifhhbdiojplfjncoa", "1Password", day), pm("nngceckbapebfimnlniiiahkandclblb", "Bitwarden", day.Add(time.Minute))}
	got := verdicts(same, nil)
	if !strings.HasPrefix(got["1Password"], "review: another password manager in this profile (Bitwarden), installed the same day") ||
		!strings.HasPrefix(got["Bitwarden"], "review: another password manager") {
		t.Errorf("same day: %v", got)
	}
	// The config names the primary: the other one is to remove.
	got = verdicts(same, []string{"nngceckbapebfimnlniiiahkandclblb"})
	if got["1Password"] != "remove: second password manager in this profile; Bitwarden is the primary one" || !strings.HasPrefix(got["Bitwarden"], "keep") {
		t.Errorf("configured: %v", got)
	}
	// A duplicate in another profile is not a duplicate.
	other := pm("nngceckbapebfimnlniiiahkandclblb", "Bitwarden", day)
	other.profile = "Work"
	if got := verdicts([]install{pm("aeblfdkhhhdcdjpifhhbdiojplfjncoa", "1Password", day), other}, nil); !strings.HasPrefix(got["1Password"], "keep") {
		t.Errorf("across profiles: %v", got)
	}
	if ids := primaries(map[string]any{"primary": []any{"abc", 3}}); fmt.Sprint(ids) != "[abc]" {
		t.Errorf("primaries %v", ids)
	}
}

func TestNoBrowserIsUnsupported(t *testing.T) {
	c := &Connector{Home: func() (string, error) { return t.TempDir(), nil }, Now: func() time.Time { return now }, OS: "darwin"}
	rec := run(t, c)
	if len(rec.Findings) != 0 || len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateUnsupported {
		t.Fatalf("%v %v", rec.Findings, rec.Statuses)
	}
}

func TestUnreadablePreferencesKeepTheBrowserUninspected(t *testing.T) {
	c := fixture(t)
	home, _ := c.Home()
	b := browsers[0]
	mustWrite(t, filepath.Join(home, b.dirs[c.OS], "Profile 4", "Secure Preferences"), "{")
	rec := run(t, c)
	rec.ByResource(t, "browser_extension", "reactdev")
	if len(rec.Findings) != 1 {
		t.Fatalf("incomplete Brave profiles produced aggregate findings: %v", rec.Findings)
	}
	for _, st := range rec.Statuses {
		if st.Account == b.name && st.State == finding.StateError && strings.Contains(st.Detail, "Secure Preferences") {
			return
		}
	}
	t.Fatalf("missing incomplete browser status: %v", rec.Statuses)
}

// A profile directory without preferences files holds no extensions: the rest of the browser is
// still assessed.
func TestAProfileWithoutPreferencesIsAbsent(t *testing.T) {
	c := fixture(t)
	home, _ := c.Home()
	b := browsers[1]
	if err := os.MkdirAll(filepath.Join(home, b.dirs[c.OS], "Profile 3"), 0o700); err != nil {
		t.Fatal(err)
	}
	rec := run(t, c)
	rec.ByResource(t, "browser_extension", "reactdev")
	for _, st := range rec.Statuses {
		if st.Account == b.name && st.State != finding.StateOK {
			t.Fatalf("%s status %v", b.name, st)
		}
	}
}

func TestChromeTime(t *testing.T) {
	if got := chromeTime("13358625205255503"); got.Format(time.DateOnly) != "2024-04-26" {
		t.Errorf("got %s", got)
	}
	for _, s := range []string{"", "0", "x"} {
		if !chromeTime(s).IsZero() {
			t.Errorf("%q parsed", s)
		}
	}
}
