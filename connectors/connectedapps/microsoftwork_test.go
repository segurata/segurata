package connectedapps

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/finding"
)

// msTiles is a synthetic api/v2/me/tiles response in the shape seen on 2026-11-24. The launch
// URLs carry the sign-in name, which must not get out.
const msTiles = `{"@odata.context":"x","value":[
 {"id":"AzureADThirdParty|11111111-1111-1111-1111-111111111111","provider":"AzureADThirdParty","providerId":"11111111-1111-1111-1111-111111111111",
  "displayName":"Error Tracker","fastLaunchUrl":"https://launcher.example/signin?login_hint=someone%40example.com","assignmentType":"Granted"},
 {"id":"AzureADThirdParty|22222222-2222-2222-2222-222222222222","provider":"AzureADThirdParty","providerId":"22222222-2222-2222-2222-222222222222",
  "displayName":"Wiki Pro","assignmentType":"Assigned"},
 {"id":"OfficeFirstParty|Admin","provider":"OfficeFirstParty","providerId":"Admin","displayName":"Admin","persistentLaunchUrl":"https://admin.example/?login_hint=someone%40example.com"},
 {"id":"OfficeFirstParty|Purview","provider":"OfficeFirstParty","providerId":"Purview","displayName":"Purview"},
 {"id":"Bookmark|1","provider":"Bookmark","providerId":"1","displayName":"Intranet"}
]}`

const msStepUpURL = "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=x&claims=%7B%22id_token%22%3A%7B%22amr%22%3A%7B%22values%22%3A%5B%22mfa%22%5D%7D%7D%7D"

func msFake(apps map[string]any, tiles string, security map[string]any) *fakeBrowser {
	b := &fakeBrowser{pages: map[string]any{msWorkAppsURL: apps}}
	if tiles != "" {
		b.responses = map[string]*cdp.Response{msWorkAppsURL: {Status: 200, Body: []byte(tiles)}}
	}
	if security != nil {
		b.pages[msWorkSecurityURL] = security
	}
	return b
}

func fetched(url, text string) map[string]any {
	return map[string]any{"url": url, "text": text, "fetched": true}
}

func TestMicrosoftWorkListsEnterpriseAppsAndChecksSecurityInfo(t *testing.T) {
	b := msFake(fetched(msWorkAppsURL, "Apps"), msTiles,
		map[string]any{"url": msStepUpURL, "text": "someone@example.com\nEnter code\nEnter the code displayed in the Authenticator app on your mobile device"})
	rec := run(t, b, nil, "microsoft-work")

	all, _ := json.Marshal([]any{rec.findings, rec.statuses})
	if strings.Contains(string(all), "someone") {
		t.Fatal("the sign-in name in a launch URL reached the output")
	}
	if len(rec.findings) != 2 {
		t.Fatalf("%d findings, want the two enterprise apps", len(rec.findings))
	}
	tracker := rec.byName(t, "Error Tracker")
	if tracker.Severity != finding.SevLow || tracker.Title != "Error Tracker can sign you in with your work account" ||
		tracker.Account != "microsoft-work" || tracker.Scope != "microsoft-work" || tracker.Remediation.URL != msWorkAppsURL ||
		tracker.Resource.ID != "microsoft-work:11111111-1111-1111-1111-111111111111" || tracker.Evidence["assignment_type"] != "Granted" ||
		!strings.Contains(tracker.Evidence["note"].(string), "Permissions") {
		t.Errorf("tracker: %+v", tracker)
	}
	if got := rec.state("microsoft-work"); !reflect.DeepEqual(got, []finding.State{finding.StateOK, finding.StateReauth}) {
		t.Fatalf("statuses %+v", rec.statuses)
	}
	ok, reauth := rec.statuses[0], rec.statuses[1]
	if ok.Scope != "" || !strings.Contains(ok.Detail, "2 enterprise apps") || !strings.Contains(ok.Detail, "not listed: 1 Bookmark, 2 OfficeFirstParty") {
		t.Errorf("ok status %+v", ok)
	}
	if reauth.Scope != msWorkSecurityScope || !strings.Contains(reauth.Detail, "Microsoft Authenticator app") || !strings.Contains(reauth.Detail, msWorkSecurityURL) {
		t.Errorf("security info status %+v", reauth)
	}
}

func TestMicrosoftWorkStates(t *testing.T) {
	const pick = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=x"
	for _, c := range []struct {
		name     string
		b        *fakeBrowser
		want     []finding.State
		scopes   []string
		detail   string
		security bool // whether Security info was loaded
	}{
		{"signed out", msFake(map[string]any{"url": pick, "text": "Sign in\nPick an account"}, "", nil),
			[]finding.State{finding.StateSignedOut}, []string{""}, "work or school account", false},
		{"second factor before My Apps", msFake(map[string]any{"url": msStepUpURL, "text": "Approve sign in request"}, "", nil),
			[]finding.State{finding.StateReauth}, []string{""}, "second factor", false},
		{"tiles not fetched", msFake(fetched(msWorkAppsURL, "Apps"), "", fetched(msWorkSecurityURL, "Security info\nSign-in methods")),
			[]finding.State{finding.StateUnverified, finding.StateUnverified}, []string{"", msWorkSecurityScope}, "did not fetch", true},
		{"tiles in another shape", msFake(fetched(msWorkAppsURL, "Apps"), `{"tiles":[]}`, map[string]any{"url": pick, "text": "Sign in"}),
			[]finding.State{finding.StateUnverified, finding.StateSignedOut}, []string{"", msWorkSecurityScope}, "expected shape", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := run(t, c.b, nil, "microsoft-work")
			if got := rec.state("microsoft-work"); !reflect.DeepEqual(got, c.want) || len(rec.findings) != 0 {
				t.Fatalf("statuses %+v findings %d", rec.statuses, len(rec.findings))
			}
			for i, s := range rec.statuses {
				if s.Scope != c.scopes[i] {
					t.Errorf("status %d scope %q, want %q", i, s.Scope, c.scopes[i])
				}
			}
			if !strings.Contains(rec.statuses[0].Detail, c.detail) {
				t.Errorf("detail %q", rec.statuses[0].Detail)
			}
			if loaded := len(c.b.opened) == 2; loaded != c.security {
				t.Errorf("opened %v", c.b.opened)
			}
		})
	}
}

func TestMSLoginState(t *testing.T) {
	for _, c := range []struct {
		p    fetchPage
		want finding.State
	}{
		{fetchPage{URL: msWorkAppsURL, Text: "Enter code"}, ""},
		{fetchPage{URL: "https://login.microsoftonline.com/common/oauth2/authorize", Text: "Sign in"}, finding.StateSignedOut},
		{fetchPage{URL: "https://login.live.com/oauth20_authorize.srf", Text: "Usar su cuenta de Microsoft"}, finding.StateSignedOut},
		{fetchPage{URL: msStepUpURL, Text: ""}, finding.StateReauth},
		{fetchPage{URL: "https://login.microsoftonline.com/x", Text: "Especificar el código\nEscriba el código que se muestra en la aplicación Authenticator"}, finding.StateReauth},
		{fetchPage{URL: "https://login.microsoftonline.com/x", Text: "Verify your identity"}, finding.StateReauth},
	} {
		if got := msLoginState(c.p); got != c.want {
			t.Errorf("%+v: %q, want %q", c.p, got, c.want)
		}
	}
	for text, want := range map[string]string{
		"Escriba el código que se muestra en la aplicación Authenticator": "the Microsoft Authenticator app",
		"We texted your phone +XX XXXXXXX12":                              "an SMS code",
		"Use your passkey":                                                "a passkey or security key",
		"Approve sign in request":                                         "",
	} {
		if got := msStepUpMethod(text); got != want {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
}

func TestMSReadyWaitsOutTheSignInHop(t *testing.T) {
	ready := msReady()
	hop, _ := json.Marshal(fetchPage{URL: "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"})
	form, _ := json.Marshal(fetchPage{URL: "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize", Text: "Pick an account"})
	loading, _ := json.Marshal(fetchPage{URL: msWorkAppsURL, Text: "Apps"})
	done, _ := json.Marshal(fetchPage{URL: msWorkAppsURL, Fetched: true})
	for i, c := range []struct {
		raw  []byte
		want bool
	}{{hop, false}, {hop, false}, {form, false}, {loading, false}, {done, false}, {done, true}, {form, false}, {form, true}} {
		if got := ready(c.raw); got != c.want {
			t.Errorf("read %d: %v, want %v", i, got, c.want)
		}
	}
	prompt, _ := json.Marshal(fetchPage{URL: msStepUpURL, Text: "someone@example.com"})
	filled, _ := json.Marshal(fetchPage{URL: msStepUpURL, Text: "someone@example.com\nEnter code"})
	ready = msReady()
	for i, c := range []struct {
		raw  []byte
		want bool
	}{{prompt, false}, {filled, false}, {filled, true}} {
		if got := ready(c.raw); got != c.want {
			t.Errorf("prompt read %d: %v, want %v", i, got, c.want)
		}
	}
}

func TestMicrosoftPersonalSignedOutPointsToMicrosoftWork(t *testing.T) {
	const ms = "https://account.live.com/consent/Manage"
	rec := run(t, &fakeBrowser{pages: map[string]any{ms: page("https://login.live.com/oauth20_authorize.srf?x", "Sign in", nil)}}, nil, "microsoft")
	if d := rec.detail("microsoft", finding.StateSignedOut); !strings.Contains(d, ms) || !strings.Contains(d, "microsoft-work") {
		t.Errorf("detail %q", d)
	}
}
