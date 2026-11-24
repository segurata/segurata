package connectedapps

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestSignInPages(t *testing.T) {
	long := strings.Repeat("x", 500)
	type check struct {
		value map[string]any
		done  bool
	}
	for _, c := range []struct {
		name   string
		st     finding.Status
		url    string
		brief  bool
		checks []check
	}{
		{"github sudo", finding.Status{Account: "github:octo", State: finding.StateReauth,
			Detail: "authorized GitHub Apps need sudo mode: open https://github.com/settings/apps/authorizations, confirm your identity, and run again within a few minutes"},
			"https://github.com/settings/apps/authorizations", true, []check{
				{page("https://github.com/settings/apps/authorizations", "Confirm access\nPassword", nil), false},
				{page("https://github.com/sessions/sudo", "", nil), false},
				{page("https://github.com/settings/apps/authorizations", "", rows(row{Name: "App", Href: "h"})), true},
				{page("https://github.com/settings/apps/authorizations", "No authorized applications", nil), true},
			}},
		{"github installations sudo", finding.Status{Account: "github:octo", State: finding.StateReauth,
			Detail: "installed GitHub Apps need sudo mode: open https://github.com/settings/installations, confirm your identity, and run again"},
			"https://github.com/settings/installations", true, nil},
		{"github signed out", finding.Status{Account: "github", State: finding.StateSignedOut, Detail: "not signed in to GitHub in the browser: https://github.com/settings/applications"},
			"https://github.com/settings/applications", false, []check{
				{page("https://github.com/login?return_to=x", "Sign in", nil), false},
				{page("https://github.com/settings/applications", "", rows(row{Name: "App", Href: "h"})), true},
			}},
		{"x", finding.Status{Account: "x", State: finding.StateSignedOut}, xURL, false, []check{
			{page("https://x.com/i/flow/login", "", nil), false},
			{page(xURL, "", rows(row{Href: "h"})), true},
		}},
		{"slack", finding.Status{Account: "slack", State: finding.StateSignedOut}, slackSignin, false, []check{
			{page(slackSignin, "", nil), false},
			{page(slackSignin, "", rows(row{Href: "https://acme.slack.com/"})), true},
		}},
		{"slack workspace", finding.Status{Account: "slack:acme.slack.com", State: finding.StateSignedOut}, "https://acme.slack.com/apps/manage", false, []check{
			{page("https://acme.slack.com/signin", "", nil), false},
			{page("https://acme.slack.com/apps/manage", "No apps", nil), true},
		}},
		{"notion", finding.Status{Account: "notion", State: finding.StateSignedOut}, notionURL, false, []check{
			{map[string]any{"url": "https://www.notion.so/login", "text": "No connections"}, false},
			{map[string]any{"url": notionURL, "text": "No connections"}, true},
		}},
		{"facebook checkpoint", finding.Status{Account: "facebook", State: finding.StateReauth}, fbURL, false, []check{
			{page("https://www.facebook.com/checkpoint/1", "Removed apps and websites", nil), false},
			{page(fbURL, "Removed apps and websites", nil), true},
		}},
		{"microsoft", finding.Status{Account: "microsoft", State: finding.StateSignedOut}, "https://account.live.com/consent/Manage", false, []check{
			{page("https://login.live.com/oauth", long, nil), false},
			{page("https://account.live.com/consent/Manage", "short", nil), false},
			{page("https://account.live.com/consent/Manage", long, nil), true},
		}},
		{"dropbox", finding.Status{Account: "dropbox", State: finding.StateSignedOut}, dropboxURL, false, []check{
			{map[string]any{"url": "https://www.dropbox.com/login?cont=x", "fetched": true}, false},
			{map[string]any{"url": dropboxURL, "fetched": false}, false},
			{map[string]any{"url": dropboxURL, "fetched": true}, true},
		}},
	} {
		p, ok := (&Connector{}).SignInPage(c.st)
		if !ok || p.URL != c.url || p.Brief != c.brief || p.Do == "" || p.Expr == "" || p.Done == nil {
			t.Errorf("%s: page %+v ok %v", c.name, p, ok)
			continue
		}
		for i, ch := range c.checks {
			raw, _ := json.Marshal(ch.value)
			if got := p.Done(raw); got != ch.done {
				t.Errorf("%s check %d: done = %v, want %v", c.name, i, got, ch.done)
			}
		}
	}
}

func TestNoSignInPageForCLIStatusesOrOtherStates(t *testing.T) {
	for _, st := range []finding.Status{
		{Account: "github:octo", State: finding.StateSignedOut, Detail: "gh is not signed in: run `gh auth login` to list GitHub keys"},
		{Account: "github:octo", State: finding.StateNoScope},
		{Account: "x", State: finding.StateError},
		{Account: "linkedin", State: finding.StateUnverified},
		{Account: "unknown", State: finding.StateSignedOut},
	} {
		if p, ok := (&Connector{}).SignInPage(st); ok {
			t.Errorf("%+v: page %+v", st, p)
		}
	}
}

func TestEveryServiceThatSignsOutHasASignInPage(t *testing.T) {
	for _, s := range services {
		if _, ok := (&Connector{}).SignInPage(finding.Status{Account: s.name, State: finding.StateSignedOut, Detail: "not signed in in the browser"}); !ok {
			t.Errorf("%s: no sign-in page", s.name)
		}
	}
}
