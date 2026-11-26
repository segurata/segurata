package connectedapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/finding"
)

// The connected apps page fills its collapsed rows from one call, account/get_linked_apps, which
// carries each app's access, permissions, publisher and link date (checked 2026-11-24). That
// response is read, since expanding the rows would mean clicking.
const (
	dropboxURL    = "https://www.dropbox.com/account/connected_apps"
	dropboxRevoke = `Open the page, expand the app under "View Dropbox content" and choose "Disconnect".`
)

var (
	dropboxListRE      = regexp.MustCompile(`/account/get_linked_apps`)
	dropboxSignedOutRE = regexp.MustCompile(`dropbox\.com/login`)
)

var dropboxJS = fetchedJS("/account/get_linked_apps")

func dropboxOut(p fetchPage) bool { return p.URL == "" || dropboxSignedOutRE.MatchString(p.URL) }

// dropboxReady: the response can finish a moment after its resource timing entry appears.
func dropboxReady() func(fetchPage) bool {
	return twice(func(p fetchPage) bool {
		return p.URL != "" && (dropboxSignedOutRE.MatchString(p.URL) || p.Fetched)
	})
}

var dropboxOld = oldBatch{title: "Dropbox", verb: "Disconnect", approved: "linked", url: dropboxURL,
	each: `expand it under "View Dropbox content" and choose "Disconnect"`, again: "Apps you still use ask you to connect again."}

func dropbox(ctx context.Context, e *env) {
	p, resp, err := capture(ctx, e, dropboxURL, dropboxJS, dropboxReady(), 50, dropboxListRE)
	if err != nil {
		e.fail("", err)
		return
	}
	if dropboxOut(p) {
		e.status("", finding.StateSignedOut, "not signed in to Dropbox in the browser: %s", dropboxURL)
		return
	}
	apps, err := parseDropboxApps(resp)
	if err != nil {
		e.status("", finding.StateUnverified, "%v, so segurata does not parse it: review %s by hand", err, dropboxURL)
		return
	}
	grants := make([]grant, 0, len(apps))
	for _, a := range apps {
		grants = append(grants, a.grant())
	}
	e.reportByAge("", grants, dropboxOld)
	e.status("", finding.StateOK, "%d connected apps", len(apps))
}

// dropboxApp is one app in get_linked_apps; fields not named here are dropped on decode.
type dropboxApp struct {
	Name         string          `json:"name"`
	Publisher    string          `json:"publisher_company"`
	PublisherURL string          `json:"publisher_url"`
	Pending      bool            `json:"pending"`
	AccessType   string          `json:"access_type"`
	AccessDesc   string          `json:"access_type_desc"`
	Permissions  []string        `json:"scope_list_messages"`
	FirstLinked  flexTime        `json:"first_linked_ts"`
	UsesSandbox  bool            `json:"uses_sandbox"`
	AppFolder    json.RawMessage `json:"app_folder"`
	team         bool
}

// parseDropboxApps returns the user's apps, then the team's. A response without user_apps is a
// page segurata does not know.
func parseDropboxApps(resp *cdp.Response) ([]dropboxApp, error) {
	if resp == nil {
		return nil, errors.New("Dropbox did not fetch the app list")
	}
	var body struct {
		User *[]dropboxApp `json:"user_apps"`
		Team []dropboxApp  `json:"team_apps"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.User == nil {
		return nil, fmt.Errorf("Dropbox's app list did not have the expected shape (HTTP %d)", resp.Status)
	}
	for i := range body.Team {
		body.Team[i].team = true
	}
	return append(*body.User, body.Team...), nil
}

const (
	dropboxFull      = "full_dropbox"
	dropboxAppFolder = "app_folder"
	dropboxScoped    = "scoped"
)

var (
	dropboxReadOnlyRE = regexp.MustCompile(`(?i)read[- ]?only`)
	dropboxTagRE      = regexp.MustCompile(`<[^>]*>`)
)

// access: an app confined to its own folder is app_folder whatever else it says.
func (a dropboxApp) access() string {
	folder := strings.TrimSpace(string(a.AppFolder))
	switch t := strings.ToLower(a.AccessType); {
	case a.UsesSandbox || folder != "" && folder != "null" || strings.Contains(t, "app folder"):
		return dropboxAppFolder
	case strings.Contains(t, "full dropbox"):
		return dropboxFull
	case strings.Contains(t, "scoped"):
		return dropboxScoped
	}
	return ""
}

func (a dropboxApp) grant() grant {
	access := a.access()
	extra := map[string]any{"access_type": a.AccessType, "access": access}
	var permissions []string
	for _, m := range a.Permissions {
		permissions = append(permissions, dropboxTagRE.ReplaceAllString(m, ""))
	}
	if permissions != nil {
		extra["permissions"] = permissions
	}
	if access == dropboxFull && dropboxReadOnlyRE.MatchString(a.AccessDesc) {
		extra["read_only"] = true
	}
	if folder := strings.Trim(string(a.AppFolder), `"`); folder != "" && folder != "null" {
		extra["app_folder"] = folder
	}
	if site := dropboxSite(a.PublisherURL); site != "" {
		extra["publisher_url"] = site
	}
	if a.team {
		extra["team_app"] = true
	}
	if a.Pending {
		extra["pending"] = true
	}
	var scopes []string
	if access == dropboxScoped {
		scopes = strings.Fields(a.AccessDesc)
	}
	return grant{resType: "dropbox_app", name: a.Name, scopes: scopes, publisher: a.Publisher,
		created: a.FirstLinked.t, url: dropboxURL, revoke: dropboxRevoke, extra: extra}
}

// dropboxSite is the publisher's site behind Dropbox's referrer-cleansing redirect.
func dropboxSite(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return ""
	}
	if dest := u.Query().Get("url"); dest != "" {
		return dest
	}
	return raw
}

// dropboxSeverity: every file writable is high, read-only medium, an app folder low.
func dropboxSeverity(service string, g grant) (finding.Severity, string) {
	switch g.extra["access"] {
	case dropboxAppFolder:
		return finding.SevLow, "read and change the files in its own app folder"
	case dropboxFull:
		if g.extra["read_only"] == true {
			return finding.SevMedium, "read every file in your Dropbox"
		}
		return finding.SevHigh, "read and change every file in your Dropbox"
	case dropboxScoped:
		if len(g.scopes) > 0 {
			return worstScope(service, g.scopes)
		}
	}
	return finding.SevMedium, "access your Dropbox"
}
