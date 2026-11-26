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

// dropboxList is a synthetic get_linked_apps response in the shape seen on 2026-11-24. The
// bolt token proves fields segurata does not name never get out.
const dropboxList = `{"bolt_token":"SECRET-TOKEN-ONE","user_apps":[
 {"id":1,"name":"Scan Pal","publisher_company":"Scan Co","publisher_url":"https://www.dropbox.com/referrer_cleansing_redirect?hmac=x&url=https%3A%2F%2Fscan.example%2Fsupport","pending":false,
  "access_type":"Full Dropbox","access_type_desc":"This app has full read/write access to any file inside the user's Dropbox.",
  "scope_list_messages":["<b>Edit</b> content of your Dropbox files and folders"],"first_linked_ts":1585064574000,"uses_sandbox":false,"app_folder":null,"type":"api_app"},
 {"id":2,"name":"Notes Sync","publisher_company":"","publisher_url":null,"access_type":"App folder","access_type_desc":"This app can only access its own folder.",
  "first_linked_ts":1700000000000,"uses_sandbox":true,"app_folder":"Apps/Notes Sync"},
 {"id":3,"name":"Photo Viewer","access_type":"Scoped App","access_type_desc":"account_info.read files.metadata.read files.content.read","first_linked_ts":1750000000000},
 {"id":4,"name":"Backup Bot","access_type":"Scoped App","access_type_desc":"account_info.read private:files.content.write","first_linked_ts":1760000000000},
 {"id":5,"name":"Mystery App","access_type":"Something New","first_linked_ts":1770000000000},
 {"id":6,"name":"Peek","access_type":"Full Dropbox","access_type_desc":"This app has read-only access to any file inside the user's Dropbox."},
 {"id":7,"name":"Old Uploader","access_type":"Full Dropbox","access_type_desc":"full read/write access","first_linked_ts":1325376000000}
],"team_apps":[{"id":8,"name":"Team Archiver","access_type":"App folder","first_linked_ts":1760000000000}]}`

func dropboxFake(body string) *fakeBrowser {
	p := map[string]any{"url": dropboxURL, "text": "View Dropbox content", "fetched": true}
	b := &fakeBrowser{pages: map[string]any{dropboxURL: p}}
	if body != "" {
		b.responses = map[string]*cdp.Response{dropboxURL: {Status: 200, Body: []byte(body)}}
	}
	return b
}

func TestDropboxReadsTheAppListResponse(t *testing.T) {
	b := dropboxFake(dropboxList)
	rec := run(t, b, nil, "dropbox")

	if len(b.opened) != 1 {
		t.Fatalf("opened %v: Dropbox must be read from the list page alone", b.opened)
	}
	all, _ := json.Marshal([]any{rec.findings, rec.statuses})
	if strings.Contains(string(all), "SECRET-TOKEN") {
		t.Fatal("a token reached the output")
	}
	if len(rec.findings) != 8 {
		t.Fatalf("%d findings, want seven recent apps and one batch", len(rec.findings))
	}
	for _, c := range []struct {
		name  string
		sev   finding.Severity
		title string
	}{
		{"Scan Pal", finding.SevHigh, "Scan Pal can read and change every file in your Dropbox"},
		{"Notes Sync", finding.SevLow, "Notes Sync can read and change the files in its own app folder"},
		{"Photo Viewer", finding.SevMedium, "Photo Viewer can read the files in your Dropbox"},
		{"Backup Bot", finding.SevHigh, "Backup Bot can read and change the files in your Dropbox"},
		{"Mystery App", finding.SevMedium, "Mystery App can access your Dropbox"},
		{"Peek", finding.SevMedium, "Peek can read every file in your Dropbox"},
		{"Team Archiver", finding.SevLow, "Team Archiver can read and change the files in its own app folder"},
	} {
		f := rec.byName(t, c.name)
		if f.Severity != c.sev || f.Title != c.title || f.Account != "dropbox" || f.Scope != "dropbox" || f.Remediation.URL != dropboxURL {
			t.Errorf("%s: %s %q %s", c.name, f.Severity, f.Title, f.Account)
		}
	}
	scan := rec.byName(t, "Scan Pal")
	if scan.Evidence["publisher"] != "Scan Co" || scan.Evidence["publisher_url"] != "https://scan.example/support" ||
		!reflect.DeepEqual(scan.Evidence["permissions"], []string{"Edit content of your Dropbox files and folders"}) || scan.Evidence["access"] != dropboxFull {
		t.Errorf("scan evidence %+v", scan.Evidence)
	}
	if scan.CreatedAt == nil || !scan.CreatedAt.Equal(time.UnixMilli(1585064574000).UTC()) || scan.Evidence["age_years"] != 6 {
		t.Errorf("scan created %v age %v", scan.CreatedAt, scan.Evidence["age_years"])
	}
	if notes := rec.byName(t, "Notes Sync"); notes.Evidence["app_folder"] != "Apps/Notes Sync" {
		t.Errorf("notes evidence %+v", notes.Evidence)
	}
	if photo := rec.byName(t, "Photo Viewer"); !reflect.DeepEqual(photo.Evidence["scopes"], []string{"account_info.read", "files.metadata.read", "files.content.read"}) {
		t.Errorf("photo scopes %v", photo.Evidence["scopes"])
	}
	if team := rec.byName(t, "Team Archiver"); team.Evidence["team_app"] != true {
		t.Errorf("team evidence %+v", team.Evidence)
	}
	if peek := rec.byName(t, "Peek"); peek.CreatedAt != nil || rec.findings[6].Resource.Name != "Peek" {
		t.Errorf("an undated app is listed last, after the dated ones: %v", rec.findings[6].Resource.Name)
	}
	batch := rec.findings[7]
	if batch.Resource.Type != "dropbox_old_apps" || batch.Severity != finding.SevHigh ||
		batch.Title != "Disconnect 1 Dropbox app linked before November 2016" || !strings.Contains(batch.Remediation.Summary, "Old Uploader") {
		t.Errorf("batch: %s %s %q %q", batch.Resource.Type, batch.Severity, batch.Title, batch.Remediation.Summary)
	}
	if got := rec.state("dropbox"); !reflect.DeepEqual(got, []finding.State{finding.StateOK}) {
		t.Errorf("statuses %v", got)
	}
}

func TestDropboxStates(t *testing.T) {
	signedOut := &fakeBrowser{pages: map[string]any{dropboxURL: map[string]any{"url": "https://www.dropbox.com/login?cont=x", "text": "Sign in"}}}
	for _, c := range []struct {
		name   string
		b      *fakeBrowser
		state  finding.State
		detail string
	}{
		{"signed out", signedOut, finding.StateSignedOut, "not signed in"},
		{"no response", dropboxFake(""), finding.StateUnverified, "did not fetch"},
		{"unknown shape", dropboxFake(`{"apps":[]}`), finding.StateUnverified, "expected shape"},
		{"empty", dropboxFake(`{"user_apps":[],"team_apps":[]}`), finding.StateOK, "0 connected apps"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := run(t, c.b, nil, "dropbox")
			if d := rec.detail("dropbox", c.state); !strings.Contains(d, c.detail) || len(rec.findings) != 0 || len(rec.statuses) != 1 {
				t.Errorf("statuses %+v findings %d", rec.statuses, len(rec.findings))
			}
		})
	}
}

func TestDropboxReadyWaitsForTwoReadsOfTheFetchedList(t *testing.T) {
	ready := dropboxReady()
	fetched, _ := json.Marshal(fetchPage{URL: dropboxURL, Fetched: true})
	loading, _ := json.Marshal(fetchPage{URL: dropboxURL})
	for i, c := range []struct {
		raw  []byte
		want bool
	}{{loading, false}, {fetched, false}, {loading, false}, {fetched, false}, {fetched, true}} {
		if got := ready(c.raw); got != c.want {
			t.Errorf("read %d: %v, want %v", i, got, c.want)
		}
	}
}
