package connectedapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/cdp"
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
	raw, resp, err := e.b.Capture(ctx, xURL, xJS, readyWhen(xReady), 50, xListRE)
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
	grants := make([]grant, 0, len(apps))
	for _, a := range apps {
		extra := map[string]any{"grants": a.grants, "token_type": a.tokenType}
		if a.expires != nil {
			extra["expires_at"] = a.expires
		}
		grants = append(grants, grant{who: who, resType: "x_app", name: a.name, scopes: a.scopes, publisher: a.org,
			created: a.approved, url: xURL + "/" + a.id, revoke: xRevoke, extra: extra})
	}
	e.reportByAge(who, grants, xOld)
	e.status(who, finding.StateOK, "%d connected apps", len(apps))
}

// xOld words the batch of X apps approved more than oldAfter ago.
var xOld = oldBatch{title: "X", verb: "Revoke", approved: "authorized", note: " (services mostly defunct)", url: xURL,
	each: `"Revoke app permissions" on its page`, again: "Services you still use ask you to connect again."}

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
func parseXApps(resp *cdp.Response) ([]xApp, error) {
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
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.Applications == nil {
		why := fmt.Sprintf("HTTP %d", resp.Status)
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
