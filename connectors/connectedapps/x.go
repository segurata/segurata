package connectedapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

const (
	xURL    = "https://x.com/settings/connected_apps"
	xRevoke = `Open the page and choose "Revoke app permissions".`
)

// X loads every grant from one call, oauth/list.json, and rate-limits it hard: opening each
// app's page burns through the limit within a few dozen apps. So the list page is loaded once
// and that response, which the page fetched itself, is read. It carries each grant's token:
// xGrant decodes only the fields below, so the tokens are dropped on decode and never stored.
var xListRE = regexp.MustCompile(`/oauth/list\.json`)

var xJS = inPage(`
  const handle = ((document.querySelector('a[data-testid="AppTabBar_Profile_Link"]') || {getAttribute: () => ""}).getAttribute("href") || "").replace("/", "");
  return {...page, login: handle, rows: [...document.querySelectorAll('a[href*="/settings/connected_apps/"]')].map((a) => ({href: a.href}))};`)

var (
	xSignedOutRE = regexp.MustCompile(`/(login|i/flow)`)
	xBrokenRE    = regexp.MustCompile(`went wrong|Algo salió mal`)
)

func xReady(p listPage) bool {
	return len(p.Rows) > 0 || xSignedOutRE.MatchString(p.URL) || xBrokenRE.MatchString(p.Text)
}

func xService(ctx context.Context, e *env) {
	raw, resp, err := e.b.capture(ctx, xURL, xJS, readyWhen(xReady), 50, xListRE)
	if err != nil {
		e.fail("", err)
		return
	}
	p, _ := decode[listPage](raw)
	if p.URL == "" || xSignedOutRE.MatchString(p.URL) {
		e.status("", finding.StateSignedOut, "not signed in to X in the browser: %s", xURL)
		return
	}
	who := ""
	if p.Login != "" {
		who = "@" + p.Login
	}
	apps, err := parseXApps(resp)
	if err != nil {
		e.status(who, finding.StateError, "%v; wait 15 minutes and run again", err)
		return
	}
	// Oldest approval first, so apps of one severity are listed by age; undated ones last.
	sort.SliceStable(apps, func(i, j int) bool {
		a, b := apps[i].approved, apps[j].approved
		return a != nil && (b == nil || a.Before(*b))
	})
	var old []grant
	for _, a := range apps {
		extra := map[string]any{"grants": a.grants, "token_type": a.tokenType}
		if a.expires != nil {
			extra["expires_at"] = a.expires
		}
		if a.approved != nil {
			extra["age_years"] = int(e.now.Sub(*a.approved).Hours() / 24 / 365)
		}
		g := grant{who: who, resType: "x_app", name: a.name, scopes: a.scopes, publisher: a.org,
			created: a.approved, url: xURL + "/" + a.id, revoke: xRevoke, extra: extra}
		if a.approved != nil && e.now.Sub(*a.approved) > xOldAfter {
			old = append(old, g)
			continue
		}
		e.report(g)
	}
	if len(old) > 0 {
		e.emit.Finding(xOldAppsFinding(e, who, old))
	}
	e.status(who, finding.StateOK, "%d connected apps", len(apps))
}

// xOldAfter is the approval age past which X apps are revoked as one batch: most services
// authorized on X that long ago are defunct (Posterous, Vine, Klout, Delicious), and nobody
// reviews them one by one.
const xOldAfter = 10 * 365 * 24 * time.Hour

// xOldAppsFinding is one finding for every app approved more than xOldAfter ago, as bad as the
// worst of them, listing each with its date and what it can do.
func xOldAppsFinding(e *env, who string, old []grant) finding.Finding {
	worst := finding.SevInfo
	var names []string
	var apps []map[string]any
	for _, g := range old {
		sev, label := assess(e.service, g)
		if sev.Rank() > worst.Rank() {
			worst = sev
		}
		names = append(names, g.name)
		apps = append(apps, map[string]any{"name": g.name, "approved": g.created.Format(time.DateOnly), "severity": sev,
			"can": label, "publisher": g.publisher, "url": g.url})
	}
	years := int(xOldAfter.Hours() / 24 / 365)
	cutoff := e.now.Add(-xOldAfter).Format("January 2006")
	return finding.Finding{
		ID:        finding.StableID(name, "x_old_apps", e.account(who)),
		Account:   e.account(who),
		Resource:  finding.Resource{Type: "x_old_apps", ID: "x:old-apps", Name: fmt.Sprintf("X apps approved more than %d years ago", years)},
		Kind:      finding.KindGrant,
		Severity:  worst,
		Title:     fmt.Sprintf("Revoke %d X apps authorized before %s (services mostly defunct)", len(old), cutoff),
		Evidence:  map[string]any{"service": e.service, "apps": apps, "names": names, "older_than_years": years},
		CreatedAt: old[0].created,
		Remediation: finding.Remediation{
			Summary: fmt.Sprintf("Open %s and revoke each of them (%s): \"Revoke app permissions\" on its page. Services you still use ask you to connect again.", xURL, strings.Join(names, ", ")),
			URL:     xURL,
		},
	}
}

// xGrant is one grant in oauth/list.json. Fields not named here, the tokens among them, are
// discarded by the decoder.
type xGrant struct {
	AppID        flexString      `json:"app_id"`
	Name         string          `json:"name"`
	Organization json.RawMessage `json:"organization"`
	TokenType    string          `json:"token_type"`
	Scopes       []struct {
		Name string `json:"name"`
	} `json:"scopes"`
	CanRead      bool     `json:"can_read"`
	CanWrite     bool     `json:"can_write"`
	CanReadDMs   bool     `json:"can_read_dms"`
	AdsRead      bool     `json:"has_ads_read_access"`
	AdsReadWrite bool     `json:"has_ads_read_write_access"`
	EmailAccess  bool     `json:"email_access"`
	Approved     flexTime `json:"approved"`
	ExpiresAt    flexTime `json:"expires_at"`
}

// xApp merges every grant of one app: X keeps one grant per token.
type xApp struct {
	id, name, org, tokenType string
	scopes                   []string
	grants                   int
	approved, expires        *time.Time // latest approval, latest expiry
}

// parseXApps reads the captured oauth/list.json response.
func parseXApps(resp *response) ([]xApp, error) {
	if resp == nil {
		return nil, errors.New("X did not fetch the app list")
	}
	var body struct {
		Applications *[]xGrant `json:"applications"`
		Errors       []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(resp.body, &body); err != nil || body.Applications == nil {
		why := fmt.Sprintf("HTTP %d", resp.status)
		switch {
		case len(body.Errors) > 0:
			why = body.Errors[0].Message
		case body.Message != "":
			why = body.Message
		}
		return nil, fmt.Errorf("X did not return the app list (%s)", why)
	}
	var out []xApp
	index := map[string]int{}
	for _, g := range *body.Applications {
		i, ok := index[string(g.AppID)]
		if !ok {
			i = len(out)
			index[string(g.AppID)] = i
			out = append(out, xApp{id: string(g.AppID), name: g.Name, org: xOrg(g.Organization), tokenType: g.TokenType, scopes: []string{}})
		}
		a := &out[i]
		a.grants++
		a.scopes = union(a.scopes, xScopes(g))
		if t := g.Approved.t; t != nil && (a.approved == nil || t.After(*a.approved)) {
			a.approved = t
		}
		if t := g.ExpiresAt.t; t != nil && (a.expires == nil || t.After(*a.expires)) {
			a.expires = t
		}
	}
	return out, nil
}

// xScopes lists OAuth 2 scopes as X names them, or the OAuth 1 flags under the same vocabulary.
func xScopes(g xGrant) []string {
	var s []string
	if g.Scopes != nil {
		for _, sc := range g.Scopes {
			s = append(s, sc.Name)
		}
	} else {
		for _, f := range []struct {
			on   bool
			name string
		}{{g.CanRead, "read"}, {g.CanWrite, "write"}, {g.CanReadDMs, "dm.read"}, {g.AdsRead, "ads.read"}, {g.AdsReadWrite, "ads.write"}} {
			if f.on {
				s = append(s, f.name)
			}
		}
	}
	if g.EmailAccess {
		s = union(s, []string{"users.email"})
	}
	return s
}

// xOrg is the publisher: a string, or an object with a name.
func xOrg(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Name string `json:"name"`
	}
	json.Unmarshal(raw, &o)
	return o.Name
}

// flexString accepts a JSON string or number.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	*f = flexString(strings.Trim(string(b), `"`))
	return nil
}

// flexTime accepts milliseconds since the epoch, as a number or a string, an RFC 3339 string, or
// the classic Twitter format ("Wed Jul 08 21:55:29 +0000 2015"). Anything else is left unset
// rather than guessed.
type flexTime struct{ t *time.Time }

func (f *flexTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		t := time.UnixMilli(ms).UTC()
		f.t = &t
		return nil
	}
	for _, layout := range []string{time.RFC3339, time.RubyDate} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			f.t = &t
			return nil
		}
	}
	return nil
}

// union appends to a the entries of b it does not already hold. Never returns nil.
func union(a, b []string) []string {
	out := append([]string{}, a...)
	have := map[string]bool{}
	for _, s := range a {
		have[s] = true
	}
	for _, s := range b {
		if !have[s] {
			have[s] = true
			out = append(out, s)
		}
	}
	return out
}
