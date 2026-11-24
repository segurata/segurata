package googlepersonal

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestSignInPageForReauthWaitsForThatAccountsConnections(t *testing.T) {
	p, ok := GooglePersonal{}.SignInPage(finding.Status{Account: "Admin@example.test", State: finding.StateReauth})
	if !ok || p.URL != "https://myaccount.google.com/connections?authuser=Admin%40example.test" || p.Expr != connectionsJS || p.Brief {
		t.Fatalf("page %+v ok %v", p, ok)
	}
	if !strings.Contains(p.Do, "Admin@example.test") {
		t.Fatalf("Do %q does not name the account", p.Do)
	}
	loaded := strings.Repeat("Third-party apps and services ", 10)
	for _, c := range []struct {
		name string
		page map[string]any
		done bool
	}{
		{"still verifying", map[string]any{"url": "https://myaccount.google.com/connections", "mail": "admin@example.test", "text": reauthEN}, false},
		{"sign-in form", map[string]any{"url": "https://accounts.google.com/v3/signin/challenge", "mail": "admin@example.test", "text": loaded}, false},
		{"another account", map[string]any{"url": "https://myaccount.google.com/connections", "mail": "other@example.test", "text": loaded}, false},
		{"loading", map[string]any{"url": "https://myaccount.google.com/connections", "mail": "admin@example.test", "text": "Google"}, false},
		{"connections", map[string]any{"url": "https://myaccount.google.com/connections", "mail": "admin@example.test", "text": loaded}, true},
		{"with apps", map[string]any{"url": "https://myaccount.google.com/connections", "mail": "admin@example.test", "text": "x", "apps": []appLink{{Name: "A"}}}, true},
	} {
		raw, _ := json.Marshal(c.page)
		if got := p.Done(raw); got != c.done {
			t.Errorf("%s: done = %v, want %v", c.name, got, c.done)
		}
	}
}

func TestSignInPageForSignedOutBrowserAndOtherStates(t *testing.T) {
	p, ok := GooglePersonal{}.SignInPage(finding.Status{Account: "authuser 0", State: finding.StateSignedOut})
	if !ok || p.URL != connectionsURL(0) {
		t.Fatalf("page %+v ok %v", p, ok)
	}
	raw, _ := json.Marshal(map[string]any{"url": "https://myaccount.google.com/u/0/connections", "mail": "any@example.test", "text": strings.Repeat("x", 300)})
	if !p.Done(raw) {
		t.Fatal("any signed-in account clears a signed-out browser")
	}
	for _, st := range []finding.Status{
		{Account: "a@example.test", State: finding.StateError},
		{Account: "authuser 3", State: finding.StateReauth}, // no email to sign in to
	} {
		if _, ok := (GooglePersonal{}).SignInPage(st); ok {
			t.Errorf("%+v: page offered", st)
		}
	}
}
