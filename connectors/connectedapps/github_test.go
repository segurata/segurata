package connectedapps

import (
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/finding"
)

const ghApps = "https://github.com/settings/connections/applications/"

// detailText is the innerText of an OAuth app's page, shaped like github.com in November 2026.
func detailText(name string, perms []string, orgs string) string {
	return "Skip to content\nSettings\nApplications\n" + name + "\n Last used within the last week  Developed by someone\n\n" +
		"Permissions\nRevoke access\n " + strings.Join(perms, "\n ") +
		"\n\nApplications act on your behalf to access your data based on the permissions you grant them.\n\n" +
		"Organization access\n" + orgs + "Footer\n© 2026 GitHub, Inc."
}

func githubPages() map[string]any {
	list1 := page(ghSettings+"/applications", "Authorized OAuth Apps\nYou have granted 5 applications access to your account.", rows(
		row{Name: "Acme CI", Href: ghApps + "AAA", Lines: []string{"Acme CI", "Last used within the last week · Owned by acme"}},
		row{Name: "Old Notes", Href: ghApps + "BBB", Lines: []string{"Old Notes", "Last used within the last 2 years · Owned by notes-inc"}},
		row{Name: "Broken App", Href: ghApps + "EEE", Lines: []string{"Broken App", "Never used · Owned by broken"}},
	))
	list1["login"] = "octo-tester"
	list1["next"] = ghSettings + "/applications?page=2"
	list2 := page(ghSettings+"/applications?page=2", "Authorized OAuth Apps", rows(
		row{Name: "Profile Peek", Href: ghApps + "CCC", Lines: []string{"Profile Peek", "Never used · Owned by peek"}},
		row{Name: "Profile Peek", Href: ghApps + "DDD", Lines: []string{"Profile Peek", "Never used · Owned by peek-two"}},
	))
	list2["login"] = "octo-tester"
	return map[string]any{
		ghSettings + "/applications":        list1,
		ghSettings + "/applications?page=2": list2,
		ghApps + "AAA": map[string]any{"text": detailText("Acme CI", []string{"Full control of private repositories", "Access user email addresses (read-only)"},
			" example-org \nLoading\nRequest\n pending-org \nLoading\nRequested\n granted-org \n")},
		ghApps + "BBB":                      map[string]any{"text": detailText("Old Notes", []string{"Read all user profile data"}, "")},
		ghApps + "CCC":                      map[string]any{"text": detailText("Profile Peek", []string{"Access user email addresses (read-only)"}, "")},
		ghApps + "DDD":                      map[string]any{"text": detailText("Profile Peek", []string{"Access user email addresses (read-only)"}, "")},
		ghSettings + "/apps/authorizations": map[string]any{"url": ghSettings + "/apps/authorizations", "title": "Confirm access", "text": "Confirm access\nPassword"},
		ghSettings + "/installations": page(ghSettings+"/installations", "Installed GitHub Apps", rows(
			row{Name: "Configure", Href: "https://github.com/settings/installations/1", Lines: []string{"Deploy Bot", "Configure"}},
			row{Name: "Configure", Href: "https://github.com/settings/installations/2", Lines: []string{"Sleepy App", "Suspended", "Configure"}},
		)),
		ghSettings + "/sessions": page(ghSettings+"/sessions", "Sessions", rows(
			row{Name: "", Href: "https://github.com/settings/sessions/987", Lines: []string{"Somewhere 192.0.2.1", "Details", "active · Your current session · Seen in ES", "Revoke"}},
		)),
	}
}

const sshKeys = `[{"id":1,"title":"laptop","key":"ssh-ed25519 AAAAC3NzaSYNTHETIC","created_at":"2020-01-01T00:00:00Z","last_used":"2024-06-01T00:00:00Z"}]` +
	`[{"id":2,"title":"ci","key":"ssh-rsa AAAAB3NzaSYNTHETIC","created_at":"2025-01-01T00:00:00Z","last_used":null}]`

func githubGh() ghFake {
	return ghFake{
		"/user/keys":             sshKeys,
		"/user/ssh_signing_keys": noScope("admin:ssh_signing_key"),
		"/user/gpg_keys":         noScope("admin:gpg_key"),
	}
}

func TestGitHubInventory(t *testing.T) {
	b := &fakeBrowser{pages: githubPages(), fail: map[string]error{ghApps + "EEE": errors.New("target crashed")}}
	rec := run(t, b, githubGh(), "github")

	acme := rec.byName(t, "Acme CI")
	if acme.Severity != finding.SevHigh || acme.Title != "Acme CI can read and write all your repositories, private ones included" {
		t.Errorf("acme: %s %q", acme.Severity, acme.Title)
	}
	if acme.Account != "github:octo-tester" || acme.Kind != finding.KindGrant || acme.Resource.Type != "github_oauth_app" || acme.Resource.ID != "github:Acme CI" {
		t.Errorf("acme identity: %+v", acme)
	}
	if got := acme.Evidence["org_access"]; !reflect.DeepEqual(got, []string{"granted-org"}) {
		t.Errorf("org access %v, want only the organization without a button", got)
	}
	if acme.Evidence["publisher"] != "acme" || acme.Evidence["last_used"] != "Last used within the last week" {
		t.Errorf("acme evidence %+v", acme.Evidence)
	}
	if acme.Remediation.URL != ghApps+"AAA" || acme.Remediation.Action != "" || !strings.Contains(acme.Remediation.Summary, "Revoke access") {
		t.Errorf("acme remediation %+v", acme.Remediation)
	}
	if acme.LastUsedAt != nil {
		t.Error("GitHub's coarse wording must not become a made-up date")
	}

	old := rec.byName(t, "Old Notes")
	if old.Severity != finding.SevMedium || !strings.HasSuffix(old.Title, "(not used for over a year)") {
		t.Errorf("a profile-only app unused for over a year goes from low to medium: %s %q", old.Severity, old.Title)
	}

	var peeks []finding.Finding
	for _, f := range rec.Findings {
		if f.Resource.Name == "Profile Peek" {
			peeks = append(peeks, f)
		}
	}
	if len(peeks) != 2 || peeks[0].Resource.ID != "github:Profile Peek" || peeks[1].Resource.ID != "github:Profile Peek#1" || peeks[0].ID == peeks[1].ID {
		t.Errorf("repeated names need an ordinal: %+v", peeks)
	}
	if peeks[0].Severity != finding.SevLow {
		t.Errorf("email-only app: %s", peeks[0].Severity)
	}

	deploy, sleepy := rec.byName(t, "Deploy Bot"), rec.byName(t, "Sleepy App")
	if deploy.Severity != finding.SevMedium || deploy.Resource.Type != "github_app_installed" || deploy.Remediation.URL != "https://github.com/settings/installations/1" {
		t.Errorf("deploy: %+v", deploy)
	}
	if sleepy.Severity != finding.SevLow || sleepy.Evidence["note"] != "Suspended" {
		t.Errorf("sleepy: %+v", sleepy)
	}

	sess := rec.byName(t, "Somewhere 192.0.2.1")
	if sess.Kind != finding.KindCredential || sess.Severity != finding.SevInfo || sess.Resource.ID != "github:987" || sess.Evidence["current"] != true {
		t.Errorf("session keyed by its number, not its IP: %+v", sess)
	}

	laptop := rec.byName(t, `SSH key "laptop"`)
	if laptop.Severity != finding.SevMedium || laptop.LastUsedAt == nil || laptop.CreatedAt == nil || laptop.Evidence["key_type"] != "ssh-ed25519" {
		t.Errorf("laptop key unused since 2024: %+v", laptop)
	}
	if ci := rec.byName(t, `SSH key "ci"`); ci.Severity != finding.SevLow || ci.LastUsedAt != nil {
		t.Errorf("ci key: %+v", ci)
	}
	all, _ := json.Marshal([]any{rec.Findings, rec.Statuses})
	if strings.Contains(string(all), "SYNTHETIC") {
		t.Error("public key material leaked into the output")
	}

	if len(rec.Findings) != 9 {
		t.Errorf("%d findings, want 9", len(rec.Findings))
	}
	want := []finding.State{finding.StateError, finding.StateOK, finding.StateReauth, finding.StateNoScope, finding.StateNoScope}
	if got := rec.state("github:octo-tester"); !reflect.DeepEqual(got, want) {
		t.Errorf("statuses %v, want %v", got, want)
	}
	if d := rec.detail("github:octo-tester", finding.StateOK); d != "4 OAuth apps, 1 unreadable" {
		t.Errorf("ok detail %q", d)
	}
	if d := rec.detail("github:octo-tester", finding.StateNoScope); !strings.Contains(d, "gh auth refresh -h github.com -s admin:ssh_signing_key") {
		t.Errorf("noscope must give the exact command: %q", d)
	}
}

func TestGitHubSignedOutStopsEarly(t *testing.T) {
	b := &fakeBrowser{pages: map[string]any{
		ghSettings + "/applications": page("https://github.com/login?return_to=%2Fsettings%2Fapplications", "Sign in to GitHub", nil),
	}}
	rec := run(t, b, ghFake{}, "github")
	if len(rec.Findings) != 0 || !reflect.DeepEqual(rec.state("github"), []finding.State{finding.StateSignedOut}) {
		t.Fatalf("findings %v statuses %v", rec.Findings, rec.Statuses)
	}
	if len(b.opened) != 1 {
		t.Errorf("opened %v after a sign-in wall", b.opened)
	}
}

func TestGitHubKeysWithoutGh(t *testing.T) {
	for name, c := range map[string]struct {
		err   error
		state finding.State
	}{
		"not installed": {exec.ErrNotFound, finding.StateUnsupported},
		"signed out":    {&cli.Error{Cmd: "gh api", Stderr: "To get started with GitHub CLI, please run:  gh auth login", Err: errors.New("exit status 4")}, finding.StateSignedOut},
		"other":         {errors.New("boom"), finding.StateError},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			e := &env{service: "github", gh: ghFake{"/user/keys": c.err, "/user/ssh_signing_keys": "[]", "/user/gpg_keys": "[]"}, emit: rec, now: now, seen: map[string]int{}}
			githubKeys(t.Context(), e, "octo-tester")
			if len(rec.Statuses) == 0 || rec.Statuses[0].State != c.state {
				t.Fatalf("statuses %+v, want %s first", rec.Statuses, c.state)
			}
		})
	}
}

func TestParseGitHubDetailWithoutOrganizations(t *testing.T) {
	d := parseGitHubDetail("Permissions\nRevoke access\nNo scopes\nApplications act on your behalf\nFooter")
	if !reflect.DeepEqual(d.scopes, []string{"No scopes"}) || d.orgs == nil || len(d.orgs) != 0 {
		t.Fatalf("%+v", d)
	}
	if d := parseGitHubDetail("Something else entirely"); d.scopes == nil || len(d.scopes) != 0 {
		t.Fatalf("missing sections give empty lists: %+v", d)
	}
}

func TestGhStale(t *testing.T) {
	for in, want := range map[string]bool{
		"Last used within the last 2 years":   true,
		"Last used within the last 5 years":   true,
		"Last used within the last 11 months": false,
		"Last used within the last week":      false,
		"Never used":                          false,
		"":                                    false,
	} {
		if got := ghStale(in); got != want {
			t.Errorf("ghStale(%q) = %v", in, got)
		}
	}
}

func TestGhAllowlistOnlyReadsKeysAndTheJSONStatus(t *testing.T) {
	for _, args := range [][]string{
		{"api", "--paginate", "/user/keys"},
		{"api", "--paginate", "/user/ssh_signing_keys"},
		{"api", "--paginate", "/user/gpg_keys"},
		{"auth", "status", "--json", "hosts"},
	} {
		if err := ghAllowlist.Check(args); err != nil {
			t.Errorf("%v refused: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"api", "-X", "DELETE", "/user/keys/1"},
		{"api", "--paginate", "/user/keys", "-X", "DELETE"},
		{"auth", "refresh", "-s", "admin:gpg_key"},
		{"api", "--paginate", "/user/emails"},
		{"auth", "status", "--show-token"},
		{"auth", "status"},
		{"auth", "token"},
		{"auth", "refresh"},
	} {
		if err := ghAllowlist.Check(args); !errors.Is(err, cli.ErrRefused) {
			t.Errorf("%v allowed", args)
		}
	}
}
