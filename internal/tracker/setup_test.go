package tracker

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
)

func TestSetupStatusesRebuildWhatTheConnectorReported(t *testing.T) {
	it := &Item{Kind: KindSetup, Key: "setup:connected-apps|github:octo|reauth", Findings: []FindingRef{
		{ID: "status:a#1", Connector: "connected-apps", Account: "github:octo", Title: "authorized apps need sudo mode"},
		{ID: "status:a#2", Connector: "connected-apps", Account: "github:octo", Title: "gone already", Gone: true},
		{ID: "status:a#3", Connector: "gcp", Instance: "work", Account: "a@x", Scope: "project p", Title: "installed apps need sudo mode"},
	}}
	got := it.SetupStatuses()
	want := []finding.Status{
		{Type: "status", Connector: "connected-apps", Account: "github:octo", State: finding.StateReauth, Detail: "authorized apps need sudo mode"},
		{Type: "status", Connector: "gcp", Instance: "work", Account: "a@x", Scope: "project p", State: finding.StateReauth, Detail: "installed apps need sudo mode"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if s := (&Item{Kind: KindFix, Key: "x|reauth", Findings: it.Findings}).SetupStatuses(); s != nil {
		t.Fatalf("a fix item has statuses: %v", s)
	}
}

func signInItem(id, key string, status Status, detail string) *Item {
	conn, _, _ := strings.Cut(strings.TrimPrefix(key, "setup:"), "|")
	return &Item{ID: id, Kind: KindSetup, Key: key, Status: status, Title: key,
		Findings: []FindingRef{{ID: "status:" + key + "#1", Connector: conn, Title: detail}}}
}

func TestBrowserSignInAndTheStatusLine(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	browser := func(c string) bool { return c == "google-personal" || c == "connected-apps" }
	cases := []struct {
		it   *Item
		want bool
	}{
		{signInItem("T-1", "setup:google-personal|a@x|reauth", Open, "verify it's you"), true},
		{signInItem("T-2", "setup:connected-apps|dropbox|signedout", Open, "not signed in in the browser"), true},
		{signInItem("T-3", "setup:connected-apps|github:me|signedout", Open, "gh is not signed in: run `gh auth login`"), false},
		{signInItem("T-4", "setup:gcp|a@x|reauth", Open, "expired: run gcloud auth login for this account"), false},
		{signInItem("T-5", "setup:google-personal|b@x|reauth", Done, "verify it's you"), false},
		{signInItem("T-6", "setup:google-personal|c@x|error", Open, "boom"), false},
	}
	for _, c := range cases {
		if got := c.it.BrowserSignIn(browser, now); got != c.want {
			t.Errorf("%s: BrowserSignIn = %v, want %v", c.it.Key, got, c.want)
		}
	}
	if cases[0].it.BrowserSignIn(nil, now) {
		t.Error("BrowserSignIn without the browser connectors")
	}
	render := func(items []*Item, browser func(string) bool) string {
		d := &doc.Doc{}
		Blockers(d, items, now, browser)
		var b bytes.Buffer
		if err := doc.Render(&b, d, doc.Text); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	const line = "`segurata signin` opens the pages that need you."
	var all []*Item
	for _, c := range cases {
		all = append(all, c.it)
	}
	if s := render(all, browser); !strings.Contains(s, line) {
		t.Fatalf("no signin line:\n%s", s)
	}
	if s := render(all[2:], browser); strings.Contains(s, line) {
		t.Fatalf("signin line without a browser sign-in:\n%s", s)
	}
	if s := render(all, nil); strings.Contains(s, line) {
		t.Fatalf("signin line without the browser connectors (report):\n%s", s)
	}
}
