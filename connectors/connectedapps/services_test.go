package connectedapps

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/finding"
)

// xList is a synthetic oauth/list.json. The token fields are there to prove they never get out.
const xList = `{"applications":[
 {"app_id":"111","name":"Chirp Scheduler","organization":"Chirp Inc","token_type":"oauth1","can_read":true,"can_write":true,"email_access":true,
  "approved":1436392529000,"token":"SECRET-TOKEN-ONE","token_secret":"SECRET-TOKEN-TWO"},
 {"app_id":111,"name":"Chirp Scheduler","token_type":"oauth1","can_read":true,"can_read_dms":true,"approved":"1500000000000","token":"SECRET-TOKEN-THREE"},
 {"app_id":"222","name":"Read Only Reader","organization":{"name":"Reader Co"},"token_type":"oauth2","scopes":[{"name":"tweet.read"},{"name":"users.read"}],
  "approved":"2026-11-22T10:35:25Z","expires_at":"Fri May 21 10:35:25 +0000 2027","access_token":"SECRET-TOKEN-FOUR"},
 {"app_id":"333","name":"Login Only","token_type":"oauth2","scopes":[],"approved":"not a date"}
]}`

func xPage() map[string]any {
	p := page(xURL, "Connected apps", rows(row{Href: xURL + "/111"}, row{Href: xURL + "/222"}))
	p["login"] = "chirper"
	return p
}

func TestXReadsTheListResponseOnceAndDropsTokens(t *testing.T) {
	b := &fakeBrowser{pages: map[string]any{xURL: xPage()}, responses: map[string]*cdp.Response{xURL: {Status: 200, Body: []byte(xList)}}}
	rec := run(t, b, nil, "x")

	if len(b.opened) != 1 {
		t.Fatalf("opened %v: X must be read from the list page alone", b.opened)
	}
	all, _ := json.Marshal([]any{rec.Findings, rec.Statuses})
	if strings.Contains(string(all), "SECRET-TOKEN") {
		t.Fatal("a token reached the output")
	}
	if len(rec.Findings) != 3 {
		t.Fatalf("%d findings, want one per app", len(rec.Findings))
	}
	chirp := rec.byName(t, "Chirp Scheduler")
	if chirp.Severity != finding.SevHigh || chirp.Title != "Chirp Scheduler can read your direct messages" {
		t.Errorf("chirp: %s %q", chirp.Severity, chirp.Title)
	}
	if !reflect.DeepEqual(chirp.Evidence["scopes"], []string{"read", "write", "users.email", "dm.read"}) || chirp.Evidence["grants"] != 2 {
		t.Errorf("grants of one app merge: %+v", chirp.Evidence)
	}
	if chirp.CreatedAt == nil || !chirp.CreatedAt.Equal(time.UnixMilli(1500000000000).UTC()) {
		t.Errorf("created_at %v, want the latest approval", chirp.CreatedAt)
	}
	if chirp.Account != "x:@chirper" || chirp.Remediation.URL != xURL+"/111" || chirp.Evidence["publisher"] != "Chirp Inc" {
		t.Errorf("chirp: %+v", chirp)
	}
	reader := rec.byName(t, "Read Only Reader")
	if reader.Severity != finding.SevMedium || reader.Evidence["publisher"] != "Reader Co" || reader.Evidence["expires_at"] == nil {
		t.Errorf("reader: %+v", reader)
	}
	if login := rec.byName(t, "Login Only"); login.Severity != finding.SevLow || login.CreatedAt != nil || login.Scope != "x" {
		t.Errorf("login only: %+v", login)
	}
	if got := rec.state("x:@chirper"); !reflect.DeepEqual(got, []finding.State{finding.StateOK}) {
		t.Errorf("statuses %v", got)
	}
}

func TestXRateLimitedAndSignedOut(t *testing.T) {
	limited := `{"errors":[{"message":"Rate limit exceeded","code":88}]}`
	b := &fakeBrowser{pages: map[string]any{xURL: xPage()}, responses: map[string]*cdp.Response{xURL: {Status: 429, Body: []byte(limited)}}}
	rec := run(t, b, nil, "x")
	if d := rec.detail("x:@chirper", finding.StateError); !strings.Contains(d, "Rate limit exceeded") || !strings.Contains(d, "15 minutes") {
		t.Errorf("rate limit detail %q", d)
	}

	b = &fakeBrowser{pages: map[string]any{xURL: xPage()}}
	rec = run(t, b, nil, "x")
	if d := rec.detail("x:@chirper", finding.StateError); !strings.Contains(d, "did not fetch") {
		t.Errorf("no response: %q", d)
	}

	b = &fakeBrowser{pages: map[string]any{xURL: page("https://x.com/i/flow/login", "Sign in to X", nil)}}
	rec = run(t, b, nil, "x")
	if !reflect.DeepEqual(rec.state("x"), []finding.State{finding.StateSignedOut}) {
		t.Errorf("statuses %+v", rec.Statuses)
	}

	// Signed out of X, and only X selected: last run's findings of every service stay unresolved.
	if len(rec.Skipped()) != len(services)-1 || rec.Skipped()[0] != (finding.Skipped{Scope: "github", Reason: `not in the "services" config`}) {
		t.Errorf("services left out of the config must be declared skipped: %+v", rec.Skipped())
	}
	var tally finding.Tally
	for _, s := range rec.Statuses {
		tally.Status(s)
	}
	for _, s := range rec.Skipped() {
		tally.Declare(s.Scope, false, s.Reason)
	}
	end := tally.End(name, "", time.Now(), time.Now(), nil)
	for _, f := range []finding.Finding{{Account: "x:@chirper", Scope: "x"}, {Account: "github:octo", Scope: "github"}} {
		if _, unchecked := finding.CoverageOf(&end).UncheckedFinding(f); !unchecked {
			t.Errorf("%s counted as inspected", f.Account)
		}
	}
}

func TestSlackReadsEachSignedInWorkspace(t *testing.T) {
	const prof = "https://app.slack.com/apps-manage/T0ACME123/integrations/profile/"
	acme := page("https://acme-team.slack.com/apps/manage", "Apps", rows(
		row{Name: "Big Bot", Href: prof + "A1/permissions", Lines: []string{"Big Bot", "31 scopes", "Approved"}},
		row{Name: "Small Bot", Href: prof + "A2/permissions", Lines: []string{"Small Bot", "2 ámbitos"}},
		row{Name: "Middle Bot", Href: prof + "A3/permissions", Lines: []string{"Middle Bot", "6 scopes"}},
		row{Name: "Wanted Bot", Href: prof + "A4/permissions", Lines: []string{"Wanted Bot", "20 scopes", "Approval required"}},
	))
	b := &fakeBrowser{pages: map[string]any{
		slackSignin: page(slackSignin, "Your workspaces", rows(
			row{Href: "https://zeta-team.slack.com/"}, row{Href: "https://acme-team.slack.com/ssb"},
			row{Href: "https://app.slack.com/client"}, row{Href: "https://zeta-team.slack.com/messages"},
		)),
		"https://acme-team.slack.com/apps/manage": acme,
		"https://zeta-team.slack.com/apps/manage": page("https://zeta-team.slack.com/workspace-signin", "Sign in", nil),
	}}
	rec := run(t, b, nil, "slack")
	want := map[string]finding.Severity{"Big Bot": finding.SevHigh, "Small Bot": finding.SevLow, "Middle Bot": finding.SevMedium, "Wanted Bot": finding.SevInfo}
	for n, sev := range want {
		if f := rec.byName(t, n); f.Severity != sev || f.Account != "slack:acme-team.slack.com" {
			t.Errorf("%s: %s %s", n, f.Severity, f.Account)
		}
	}
	big := rec.byName(t, "Big Bot")
	if big.Title != "Big Bot can use 31 permissions in acme-team.slack.com" || big.Resource.ID != "slack:acme-team.slack.com/Big Bot" || big.Evidence["scope_count"] != 31 {
		t.Errorf("big: %+v", big)
	}
	if !reflect.DeepEqual(rec.state("slack:zeta-team.slack.com"), []finding.State{finding.StateSignedOut}) {
		t.Errorf("zeta statuses %+v", rec.Statuses)
	}
	// The workspace id the apps' links name, for attribution; none for a signed-out workspace.
	if ws := rec.byName(t, "acme-team.slack.com"); ws.Resource.Type != "slack_workspace" || ws.Evidence["team_id"] != "T0ACME123" || ws.Severity != finding.SevInfo {
		t.Errorf("workspace record: %+v", ws)
	}
	for _, f := range rec.Findings {
		if f.Resource.Type == "slack_workspace" && f.Resource.Name != "acme-team.slack.com" {
			t.Errorf("workspace record for a workspace not read: %+v", f)
		}
	}

	rec = run(t, &fakeBrowser{pages: map[string]any{slackSignin: page(slackSignin, "Sign in to Slack", nil)}, neverReady: map[string]bool{slackSignin: true}}, nil, "slack")
	if !reflect.DeepEqual(rec.state("slack"), []finding.State{finding.StateSignedOut}) {
		t.Errorf("no workspaces: %+v", rec.Statuses)
	}
}

// slackList is an admin.apps.installed.list response with these apps.
func slackList(apps ...map[string]any) *cdp.Response {
	body, _ := json.Marshal(map[string]any{"ok": true, "apps": apps})
	return &cdp.Response{Status: 200, Body: body}
}

func slackInstalledApp(id, name string, bot, user []string) map[string]any {
	return map[string]any{"id": id, "name": name, "declared_bot_scopes": bot, "declared_user_scopes": user, "is_internal": false,
		"icons": map[string]any{"image_32": "https://example.test/i.png"}}
}

// The manage page's own app list gives each app's declared scopes, per workspace: an app is graded
// by what they let it do, the scope count stays as evidence, and a row the list lacks (an app
// waiting for approval) keeps the row's reading. A workspace whose list renders no row still has
// its apps and its id (from the page URL). The page is loaded once per workspace.
func TestSlackGradesAppsByTheirDeclaredScopes(t *testing.T) {
	const acmeURL = "https://app.slack.com/apps-manage/T0ACME123/integrations/installed"
	const prof = "https://app.slack.com/apps-manage/T0ACME123/integrations/profile/"
	acme := map[string]any{"url": acmeURL, "text": "Installed apps", "fetched": true, "rows": rows(
		row{Name: "Poster", Href: prof + "A1/permissions", Lines: []string{"Poster", "3 scopes", "Approved"}},
		row{Name: "Wanted Bot", Href: prof + "A9/permissions", Lines: []string{"Wanted Bot", "20 scopes", "Approval required"}},
	)}
	zeta := map[string]any{"url": "https://app.slack.com/apps-manage/T0ZETA999/integrations/installed", "text": "Installed apps", "fetched": true}
	b := &fakeBrowser{pages: map[string]any{
		slackSignin: page(slackSignin, "Your workspaces", rows(row{Href: "https://acme-team.slack.com/"}, row{Href: "https://zeta-team.slack.com/"})),
		"https://acme-team.slack.com/apps/manage": acme,
		"https://zeta-team.slack.com/apps/manage": zeta,
	}, responses: map[string]*cdp.Response{
		"https://acme-team.slack.com/apps/manage": slackList(
			slackInstalledApp("A1", "Poster", []string{"chat:write", "chat:write.public", "commands"}, nil),
			slackInstalledApp("A2", "Reader", nil, []string{"channels:history", "im:history", "users:read"}),
			slackInstalledApp("A3", "Shared Bot", []string{"incoming-webhook"}, nil),
		),
		"https://zeta-team.slack.com/apps/manage": slackList(
			slackInstalledApp("A3", "Shared Bot", []string{"chat:write", "channels:history"}, nil),
		),
	}}
	rec := run(t, b, nil, "slack")

	poster := rec.byName(t, "Poster")
	if poster.Severity != finding.SevMedium || poster.Title != "Poster can post as a bot and post in public channels it was not added to" ||
		poster.Evidence["scope_count"] != 3 || poster.Remediation.URL != prof+"A1/permissions" || poster.Evidence["note"] != "Approved" {
		t.Errorf("poster: %+v", poster)
	}
	if caps, _ := poster.Evidence["capabilities"].([]string); !reflect.DeepEqual(caps, []string{"post", "post_public"}) {
		t.Errorf("poster capabilities %v", poster.Evidence["capabilities"])
	}
	reader := rec.byName(t, "Reader")
	if reader.Severity != finding.SevHigh || !strings.Contains(reader.Title, "read messages as the person who installed it") ||
		!reflect.DeepEqual(reader.Evidence["user_scopes"], []string{"channels:history", "im:history", "users:read"}) ||
		reader.Remediation.URL != prof+"A2/permissions" {
		t.Errorf("reader: %+v", reader)
	}
	if w := rec.byName(t, "Wanted Bot"); w.Severity != finding.SevInfo || w.Evidence["scope_count"] != 20 {
		t.Errorf("pending app: %+v", w)
	}
	// One app, two workspaces, two declarations.
	var shared []finding.Finding
	for _, f := range rec.Findings {
		if f.Resource.Name == "Shared Bot" {
			shared = append(shared, f)
		}
	}
	if len(shared) != 2 || shared[0].Account != "slack:acme-team.slack.com" || shared[0].Severity != finding.SevLow ||
		shared[1].Account != "slack:zeta-team.slack.com" || shared[1].Severity != finding.SevHigh ||
		shared[1].Remediation.URL != "https://app.slack.com/apps-manage/T0ZETA999/integrations/profile/A3/permissions" {
		t.Errorf("shared bot: %+v", shared)
	}
	if ws := rec.byName(t, "zeta-team.slack.com"); ws.Evidence["team_id"] != "T0ZETA999" {
		t.Errorf("zeta workspace record: %+v", ws)
	}
	if d := rec.detail("slack:acme-team.slack.com", finding.StateOK); d != "4 apps" {
		t.Errorf("acme status %q (%+v)", d, rec.Statuses)
	}

	// No list and no row: nothing can be listed, so the workspace is unverified, not "0 apps".
	b = &fakeBrowser{pages: map[string]any{
		slackSignin: page(slackSignin, "Your workspaces", rows(row{Href: "https://acme-team.slack.com/"})),
		"https://acme-team.slack.com/apps/manage": map[string]any{"url": acmeURL, "text": "Installed apps\nFilter"},
	}, responses: map[string]*cdp.Response{"https://acme-team.slack.com/apps/manage": {Status: 200, Body: []byte(`{"ok":false,"error":"not_allowed"}`)}},
		neverReady: map[string]bool{"https://acme-team.slack.com/apps/manage": true}}
	rec = run(t, b, nil, "slack")
	if d := rec.detail("slack:acme-team.slack.com", finding.StateUnverified); !strings.Contains(d, `the app list answered "not_allowed"`) || len(rec.Findings) != 0 {
		t.Errorf("unlisted workspace: %+v %+v", rec.Statuses, rec.Findings)
	}
}

func TestNotionReadsDeveloperConnections(t *testing.T) {
	b := &fakeBrowser{pages: map[string]any{notionURL: map[string]any{"url": notionURL, "text": "Integrations", "cells": [][][]string{
		{{"W", "Writer Bot", "Read, update, and insert content, read and insert comments, and read user information"}, {"API token", "Internal to Example Space"}, {"Ada Example"}, {"Nov 11, 2026"}},
		{{"Reader", "Read content"}, {"API token", "Interna de Example Space"}, {"Ada", "Example"}, {"18 nov 2025"}},
	}}}}
	rec := run(t, b, nil, "notion")
	w := rec.byName(t, "Writer Bot")
	if w.Severity != finding.SevHigh || w.Account != "notion:Example Space" || w.CreatedAt == nil || w.Evidence["publisher"] != "Ada Example" {
		t.Errorf("writer: %+v", w)
	}
	if r := rec.byName(t, "Reader"); r.Severity != finding.SevMedium || r.Account != "notion:Example Space" || r.Evidence["publisher"] != "Ada Example" {
		t.Errorf("reader: %+v", r)
	}
	if !reflect.DeepEqual(rec.state("notion:Example Space"), []finding.State{finding.StateOK}) {
		t.Errorf("statuses %+v", rec.Statuses)
	}

	rec = run(t, &fakeBrowser{pages: map[string]any{notionURL: map[string]any{"url": "https://www.notion.so/login", "text": "Log in"}}}, nil, "notion")
	if !reflect.DeepEqual(rec.state("notion"), []finding.State{finding.StateSignedOut}) {
		t.Errorf("signed out: %+v", rec.Statuses)
	}
}

const fbDetailPath = "/settings/applications/app_details/?app_id="

func fbDetailPage(name, sharing string) map[string]any {
	return map[string]any{"url": "https://www.facebook.com" + fbDetailPath, "text": "Settings and privacy\nAll websites and apps\n" + name +
		"\nRemove\nLogged in with Facebook\nAdded on Oct 9, 2014\nActive\nOnly me\nRemove\nInfo you're sharing with " + name + "\n" + sharing +
		"\nTo learn more about how " + name + " uses your information, view their Privacy Policy.\nReport this app"}
}

func TestFacebookListsActiveAppsWithoutClickingSeeMore(t *testing.T) {
	const base = "https://www.facebook.com" + fbDetailPath
	list := page(fbURL, "Apps and websites", rows(
		row{Name: "Ver y editar", Href: base + "10", Lines: []string{"Libros Club", "Añadida el 15 mar. 2016", "Activa", "Ver y editar", "Suprimir"}},
		row{Name: "View and edit", Href: base + "20", Lines: []string{"Poster Pro", "Added on Sep 7, 2015", "Active", "View and edit", "Remove"}},
	))
	list["more"] = true
	b := &fakeBrowser{pages: map[string]any{
		fbURL: list,
		base + "10": map[string]any{"text": "Todos los sitios web y aplicaciones\nLibros Club\nSuprimir\nSesión iniciada con Facebook\nAñadida el 15 mar. 2016\nActiva\nSolo yo\nSuprimir\n" +
			"Información que estás compartiendo con Libros Club\nNombre y foto del perfil\nEsto forma parte de tu perfil público y es accesible en todo momento.\nObligatorio\n" +
			"Dirección de correo electrónico\nTo learn more about how Libros Club uses your information\nDenunciar esta aplicación"},
		base + "20": fbDetailPage("Poster Pro", "Name and profile picture\nRequired\nPublish posts on your behalf"),
	}}
	rec := run(t, b, nil, "facebook")
	libros := rec.byName(t, "Libros Club")
	if libros.Severity != finding.SevLow || !reflect.DeepEqual(libros.Evidence["scopes"], []string{"Nombre y foto del perfil", "Dirección de correo electrónico"}) {
		t.Errorf("libros: %s %+v", libros.Severity, libros.Evidence)
	}
	if libros.CreatedAt == nil || !libros.CreatedAt.Equal(time.Date(2016, 3, 15, 0, 0, 0, 0, time.UTC)) || libros.Evidence["facebook_login"] != true ||
		libros.Evidence["audience"] != "Solo yo" || libros.Evidence["state"] != "Activa" || libros.Remediation.URL != base+"10" || libros.Account != "facebook" {
		t.Errorf("libros: %+v", libros)
	}
	if poster := rec.byName(t, "Poster Pro"); poster.Severity != finding.SevHigh || poster.Resource.ID != "facebook:Poster Pro" {
		t.Errorf("poster: %+v", poster)
	}
	if d := rec.detail("facebook", finding.StateOK); !strings.Contains(d, "2 apps") || !strings.Contains(d, `does not click`) {
		t.Errorf("a cut list must say so: %q", d)
	}
}

func TestFacebookStates(t *testing.T) {
	for name, c := range map[string]struct {
		page  map[string]any
		state finding.State
	}{
		"signed out": {page("https://www.facebook.com/login/?next=x", "Log in", nil), finding.StateSignedOut},
		"checkpoint": {page("https://www.facebook.com/checkpoint/1", "Confirm", nil), finding.StateReauth},
		"empty":      {page(fbURL, "Apps and websites\nView removed apps and websites", nil), finding.StateUnverified},
	} {
		t.Run(name, func(t *testing.T) {
			rec := run(t, &fakeBrowser{pages: map[string]any{fbURL: c.page}}, nil, "facebook")
			if !reflect.DeepEqual(rec.state("facebook"), []finding.State{c.state}) || len(rec.Findings) != 0 {
				t.Fatalf("statuses %+v", rec.Statuses)
			}
		})
	}
}

func TestPageOnlyServices(t *testing.T) {
	const ig = "https://www.instagram.com/accounts/manage_access/"
	const li = "https://www.linkedin.com/mypreferences/d/data-sharing-for-permitted-services"
	const ms = "https://account.live.com/consent/Manage"
	long := strings.Repeat("Some account page text. ", 30)
	cases := []struct {
		name, svc, url string
		page           map[string]any
		state          finding.State
	}{
		{"instagram empty es", "instagram", ig, page(ig, "Aplicaciones y sitios web\nActivas\nNo has autorizado a ninguna aplicación a acceder a tu cuenta de Instagram.", nil), finding.StateOK},
		{"instagram empty en", "instagram", ig, page(ig, "Apps and websites\nYou have not authorized any applications to access your Instagram account.", nil), finding.StateOK},
		{"instagram with apps", "instagram", ig, page(ig, "Estos son los sitios web y aplicaciones que has conectado\nSome App\nSuprimir", nil), finding.StateUnverified},
		{"instagram signed out", "instagram", ig, page("https://www.instagram.com/accounts/login/?next=x", "Log in", nil), finding.StateSignedOut},
		{"linkedin empty", "linkedin", li, page(li, "Permitted services\nYou have not granted access to any services.", nil), finding.StateOK},
		{"linkedin with services", "linkedin", li, page(li, "Permitted services\nSome Service\nRemove", nil), finding.StateUnverified},
		{"linkedin signed out", "linkedin", li, page("https://www.linkedin.com/login?session_redirect=x", "Sign in", nil), finding.StateSignedOut},
		{"microsoft signed out", "microsoft", ms, page("https://login.live.com/oauth20_authorize.srf?x", "Sign in", nil), finding.StateSignedOut},
		{"microsoft signed in", "microsoft", ms, page(ms, long, nil), finding.StateUnverified},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := run(t, &fakeBrowser{pages: map[string]any{c.url: c.page}}, nil, c.svc)
			if !reflect.DeepEqual(rec.state(c.svc), []finding.State{c.state}) || len(rec.Findings) != 0 {
				t.Fatalf("statuses %+v findings %d", rec.Statuses, len(rec.Findings))
			}
		})
	}
}

func TestSelectServices(t *testing.T) {
	all, err := selectServices(nil)
	if err != nil || len(all) != len(services) {
		t.Fatalf("default: %d %v", len(all), err)
	}
	some, err := selectServices(map[string]any{"services": []any{"x", "github"}})
	if err != nil || len(some) != 2 || some[0].name != "x" || some[1].name != "github" {
		t.Fatalf("subset: %+v %v", some, err)
	}
	if _, err := selectServices(map[string]any{"services": []any{"myspace"}}); err == nil || !strings.Contains(err.Error(), "known: github") {
		t.Errorf("unknown service: %v", err)
	}
	if _, err := selectServices(map[string]any{"services": "github"}); err == nil {
		t.Error("a string instead of a list must be an error")
	}
	if _, err := selectServices(map[string]any{"services": []any{}}); err == nil {
		t.Error("an empty list would inspect nothing and must be an error")
	}
}

func TestBrowserErrorsBecomeStatuses(t *testing.T) {
	b := &fakeBrowser{fail: map[string]error{fbURL: errTest}}
	rec := run(t, b, nil, "facebook")
	if d := rec.detail("facebook", finding.StateError); d != errTest.Error() {
		t.Fatalf("statuses %+v", rec.Statuses)
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTest = testErr("target crashed")

func TestFlexTime(t *testing.T) {
	cases := map[string]*time.Time{
		`1436392529000`:                    new(time.UnixMilli(1436392529000).UTC()),
		`"1436392529000"`:                  new(time.UnixMilli(1436392529000).UTC()),
		`"2026-11-22T10:35:25Z"`:           new(time.Date(2026, 11, 22, 10, 35, 25, 0, time.UTC)),
		`"Wed Jul 08 21:55:29 +0000 2015"`: new(time.Date(2015, 7, 8, 21, 55, 29, 0, time.UTC)),
		`null`:                             nil,
		`"soon"`:                           nil,
	}
	for in, want := range cases {
		var f flexTime
		if err := json.Unmarshal([]byte(in), &f); err != nil {
			t.Fatal(err)
		}
		if (f.t == nil) != (want == nil) || f.t != nil && !f.t.Equal(*want) {
			t.Errorf("%s → %v, want %v", in, f.t, want)
		}
	}
}

// xOldList has two apps approved more than ten years before now and one recent app.
const xOldList = `{"applications":[
 {"app_id":"1","name":"Old Blog","organization":"Old Blog Inc","token_type":"oauth1","can_read":true,"can_write":true,"approved":"2009-11-10T22:57:07Z"},
 {"app_id":"2","name":"Old Reader","token_type":"oauth1","can_read":true,"approved":"2012-01-07T03:21:45Z"},
 {"app_id":"3","name":"New Reader","token_type":"oauth1","can_read":true,"approved":"2021-03-16T00:03:07Z"},
 {"app_id":"4","name":"Mid Writer","token_type":"oauth1","can_read":true,"can_write":true,"approved":"2020-07-25T15:01:00Z"}
]}`

func TestXGroupsAppsApprovedMoreThanTenYearsAgo(t *testing.T) {
	b := &fakeBrowser{pages: map[string]any{xURL: xPage()}, responses: map[string]*cdp.Response{xURL: {Status: 200, Body: []byte(xOldList)}}}
	rec := run(t, b, nil, "x")
	if len(rec.Findings) != 3 {
		t.Fatalf("%d findings, want the two recent apps and one batch", len(rec.Findings))
	}
	if rec.Findings[0].Resource.Name != "Mid Writer" || rec.Findings[1].Resource.Name != "New Reader" {
		t.Errorf("recent apps not listed oldest first: %s, %s", rec.Findings[0].Resource.Name, rec.Findings[1].Resource.Name)
	}
	batch := rec.Findings[2]
	if batch.Resource.Type != "x_old_apps" || batch.Severity != finding.SevHigh || batch.Account != "x:@chirper" ||
		batch.Title != "Revoke 2 X apps authorized before November 2016 (services mostly defunct)" {
		t.Fatalf("batch: %s %s %q", batch.Resource.Type, batch.Severity, batch.Title)
	}
	if !reflect.DeepEqual(batch.Evidence["names"], []string{"Old Blog", "Old Reader"}) || !strings.Contains(batch.Remediation.Summary, "Old Blog, Old Reader") {
		t.Errorf("batch evidence %v / %q", batch.Evidence["names"], batch.Remediation.Summary)
	}
	if batch.CreatedAt == nil || batch.CreatedAt.Year() != 2009 {
		t.Errorf("batch created_at %v, want the oldest approval", batch.CreatedAt)
	}
	if rec.Findings[0].Evidence["age_years"] != 6 {
		t.Errorf("age_years %v", rec.Findings[0].Evidence["age_years"])
	}
}

func TestOwnNotionIntegrationIsLow(t *testing.T) {
	b := &fakeBrowser{pages: map[string]any{notionURL: map[string]any{"url": notionURL, "text": "Integrations", "cells": [][][]string{
		{{"Mine", "Read, update, and insert content"}, {"API token", "Internal to Example Space"}, {"Ada Example (You)"}, {"Nov 11, 2026"}},
		{{"Theirs", "Read, update, and insert content"}, {"API token", "Internal to Example Space"}, {"Bob Example"}, {"Nov 11, 2026"}},
	}}}}
	rec := run(t, b, nil, "notion")
	if m := rec.byName(t, "Mine"); m.Severity != finding.SevLow || !strings.HasSuffix(m.Title, "(your own integration)") {
		t.Errorf("own integration: %s %q", m.Severity, m.Title)
	}
	if o := rec.byName(t, "Theirs"); o.Severity != finding.SevHigh {
		t.Errorf("someone else's integration: %s", o.Severity)
	}
}

func TestGitHubCLIIsADependencyToNarrowNotRevoke(t *testing.T) {
	e := &env{service: "github", emit: &recorder{}, now: now, seen: map[string]int{}}
	e.report(grant{who: "octo", resType: "github_oauth_app", name: "GitHub CLI", scopes: []string{
		"Full control of orgs and teams, read and write org projects", "Delete repositories", "Full control of private repositories"}})
	f := e.emit.(*recorder).Findings[0]
	if f.Severity != finding.SevHigh || f.Title != "GitHub CLI can delete your repositories (segurata depends on it)" || f.Evidence["dependency"] != "segurata depends on it" {
		t.Errorf("finding %s %q %v", f.Severity, f.Title, f.Evidence)
	}
	if !strings.Contains(f.Remediation.Summary, "`gh auth refresh -h github.com -r delete_repo,admin:org`") ||
		!strings.Contains(f.Remediation.Summary, "do not revoke") || strings.Contains(f.Remediation.Summary, "Revoke access") {
		t.Errorf("remediation %q", f.Remediation.Summary)
	}

	e.report(grant{who: "octo", resType: "github_oauth_app", name: "Some CLI", scopes: []string{"Delete repositories"}})
	if other := e.emit.(*recorder).Findings[1]; other.Evidence["dependency"] != nil {
		t.Errorf("only segurata's own dependencies are labelled: %+v", other)
	}
}

func TestDecodeGivesTheZeroValueForAnotherShape(t *testing.T) {
	if p := decode[listPage]([]byte(`{"url":"https://example.com/login","rows":"not a list"}`)); p.URL != "" {
		t.Fatalf("decode kept part of a value of another shape: %+v", p)
	}
	if p := decode[listPage]([]byte(`{"url":"https://example.com/"}`)); p.URL != "https://example.com/" {
		t.Fatalf("decode = %+v", p)
	}
}

// Every readiness check gets the zero page when the page returns something of another shape, and
// must not take it for a loaded page.
func TestNoServiceTakesAPageOfAnotherShapeForReady(t *testing.T) {
	for _, other := range []any{"not a page", map[string]any{}, []any{1, 2}} {
		for _, s := range services {
			b := &fakeBrowser{other: other}
			run(t, b, ghFake{}, s.name)
			if len(b.accepted) > 0 {
				t.Errorf("%s accepted %v for %v", s.name, other, b.accepted)
			}
		}
	}
}
