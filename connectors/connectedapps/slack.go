package connectedapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/finding"
)

const (
	slackSignin = "https://slack.com/signin"
	slackRevoke = `Open the page, then "Configuration" › "Remove app" (needs a workspace admin if you are not one).`
)

// slack.com/signin lists the workspaces this browser is signed in to.
var slackSigninJS = inPage(`
  return {...page, rows: [...document.querySelectorAll('a[href*=".slack.com/"]')].map((a) => ({href: a.href}))};`)

const (
	slackAppSel   = `a[href*="/integrations/profile/"]`
	slackListPath = "/api/admin.apps.installed.list"
)

// slackAppsJS reads the app rows when the list renders, and whether the page has fetched its app
// list (from its resource timing: it sends nothing). In a hidden target the list may never render
// (checked 2026-11-24), so the fetched list is what counts.
var slackAppsJS = inPage(`return {...page, rows: rows('` + slackAppSel + `'),
  fetched: performance.getEntriesByType("resource").some((e) => e.name.includes(` + strconv.Quote(slackListPath) + `))};`)

var slackListRE = regexp.MustCompile(regexp.QuoteMeta(slackListPath))

// slackPage is what slackAppsJS returns.
type slackPage struct {
	listPage
	Fetched bool `json:"fetched"`
}

var (
	slackScopesRE      = regexp.MustCompile(`^(\d+) (ámbitos?|scopes?)$`)
	slackNoteRE        = regexp.MustCompile(`^(Aprobado|Aprobación necesaria|Approved|Approval required|Restringido|Restricted)`)
	slackPendingRE     = regexp.MustCompile(`^(Aprobación necesaria|Approval required|Restringido|Restricted)`)
	slackEmptyRE       = regexp.MustCompile(`(?i)no hay aplicaciones|no apps`)
	slackSignedOutRE   = regexp.MustCompile(`signin`)
	slackServiceHostRE = regexp.MustCompile(`^(app|api|www|status|slack)\.`)
)

// slackWorkspaces returns the workspace hosts linked from the sign-in page, sorted.
func slackWorkspaces(rows []row) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		u, err := url.Parse(r.Href)
		if err != nil || !strings.HasSuffix(u.Hostname(), ".slack.com") || slackServiceHostRE.MatchString(u.Hostname()) {
			continue
		}
		if h := u.Hostname(); !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

type slackApp struct {
	id, name, href, note string
	count                int
	pending              bool // approval required or restricted: requested, not installed
}

// slackAppIDRE reads an app's id from its link: …/integrations/profile/<app>/….
var slackAppIDRE = regexp.MustCompile(`/integrations/profile/(A[A-Z0-9]+)`)

// parseSlackApp reads a row of <workspace>/apps/manage: the list shows how many scopes each app
// has and whether it waits for approval.
func parseSlackApp(r row) slackApp {
	a := slackApp{name: r.Name, href: r.Href}
	if m := slackAppIDRE.FindStringSubmatch(r.Href); m != nil {
		a.id = m[1]
	}
	var notes []string
	for _, l := range r.Lines {
		if m := slackScopesRE.FindStringSubmatch(l); m != nil && a.count == 0 {
			a.count, _ = strconv.Atoi(m[1])
		}
		if slackNoteRE.MatchString(l) {
			notes = append(notes, l)
			a.pending = a.pending || slackPendingRE.MatchString(l)
		}
	}
	a.note = strings.Join(notes, " ")
	return a
}

// slackInstalled is one app of the admin.apps.installed.list response the manage page fetches:
// the scopes declared for this workspace, the bot's and the user token's. Fields not named here
// are discarded by the decoder.
type slackInstalled struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	BotScopes  []string `json:"declared_bot_scopes"`
	UserScopes []string `json:"declared_user_scopes"`
	Internal   bool     `json:"is_internal"`
}

// parseSlackInstalled reads the captured app list.
func parseSlackInstalled(resp *cdp.Response) ([]slackInstalled, error) {
	if resp == nil {
		return nil, errors.New("the page did not fetch its app list")
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("the app list answered HTTP %d", resp.Status)
	}
	var v struct {
		OK    bool             `json:"ok"`
		Error string           `json:"error"`
		Apps  []slackInstalled `json:"apps"`
	}
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return nil, fmt.Errorf("the app list is not the JSON segurata knows: %v", err)
	}
	if !v.OK {
		return nil, fmt.Errorf("the app list answered %q", v.Error)
	}
	return v.Apps, nil
}

// slackListed reports whether a workspace's app page shows its apps or its empty message.
func slackListed(p listPage) bool { return len(p.Rows) > 0 || slackEmptyRE.MatchString(p.Text) }

// slackReady passes once the page is a sign-in page, or has fetched its app list or shown its rows
// for two reads in a row (the response can finish a moment after its timing entry appears).
func slackReady() func(slackPage) bool {
	return twice(func(p slackPage) bool {
		return p.URL != "" && (slackSignedOutRE.MatchString(p.URL) || p.Fetched || slackListed(p.listPage))
	})
}

// slackSignedIn reports whether the sign-in page lists a workspace this browser is signed in to.
func slackSignedIn(p listPage) bool { return len(slackWorkspaces(p.Rows)) > 0 }

func slack(ctx context.Context, e *env) {
	p, err := load(ctx, e, slackSignin, slackSigninJS, slackSignedIn, 30)
	if err != nil {
		e.fail("", err)
		return
	}
	hosts := slackWorkspaces(p.Rows)
	if len(hosts) == 0 {
		e.status("", finding.StateSignedOut, "no Slack workspace signed in to the browser: %s", slackSignin)
		return
	}
	for _, host := range hosts {
		if ctx.Err() != nil {
			return
		}
		slackWorkspace(ctx, e, host)
	}
}

// slackWorkspace reports the apps of one workspace: those in the app list the manage page fetches,
// classified by their declared scopes, and the rows the page shows that the list lacks (apps
// waiting for approval), by their scope count. The page is loaded once; no app page is opened.
func slackWorkspace(ctx context.Context, e *env, host string) {
	manage := "https://" + host + "/apps/manage"
	p, resp, err := capture(ctx, e, manage, slackAppsJS, slackReady(), 40, slackListRE)
	if err != nil {
		e.fail(host, err)
		return
	}
	if p.URL == "" || slackSignedOutRE.MatchString(p.URL) {
		e.status(host, finding.StateSignedOut, "signed out of this workspace: %s", manage)
		return
	}
	team := slackTeam(p.URL, p.Rows)
	installed, listErr := parseSlackInstalled(resp)
	if listErr != nil && !slackListed(p.listPage) {
		e.status(host, finding.StateUnverified, "%v and no app row rendered, so segurata cannot list the apps: review %s by hand", listErr, manage)
		return
	}
	rowApps := make([]slackApp, len(p.Rows))
	byID := map[string]slackApp{}
	for i, r := range p.Rows {
		rowApps[i] = parseSlackApp(r)
		if id := rowApps[i].id; id != "" {
			byID[id] = rowApps[i]
		}
	}
	listed := map[string]bool{}
	for _, in := range installed {
		listed[in.ID] = true
		a := byID[in.ID]
		href := a.href
		if href == "" && team != "" {
			href = "https://app.slack.com/apps-manage/" + team + "/integrations/profile/" + in.ID + "/permissions"
		}
		e.report(grant{who: host, scope: host, resType: "slack_app", name: in.Name, scopes: nonNil(in.BotScopes), userScopes: nonNil(in.UserScopes),
			count: len(in.BotScopes) + len(in.UserScopes), note: a.note, url: href, revoke: slackRevoke,
			extra: map[string]any{"pending_approval": false, "internal": in.Internal, "capabilities": slackCapList(slackCaps(in.BotScopes, in.UserScopes))}})
	}
	n := len(installed)
	for _, a := range rowApps {
		if a.id == "" || !listed[a.id] {
			e.report(grant{who: host, scope: host, resType: "slack_app", name: a.name, count: a.count, note: a.note,
				url: a.href, revoke: slackRevoke, extra: map[string]any{"pending_approval": a.pending}})
			n++
		}
	}
	if team != "" {
		e.emit.Finding(slackWorkspaceFinding(e.account(host), host, team))
	}
	if listErr != nil {
		e.status(host, finding.StateUnverified, "%d apps by scope count only: %v; review their permissions at %s", n, listErr, manage)
		return
	}
	e.status(host, finding.StateOK, "%d apps", n)
}

// nonNil is s, or an empty list for nil: an app the list declares no scopes of has none.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// slackTeamRE reads the workspace id from an app's link: app.slack.com/apps-manage/<team>/integrations/….
var slackTeamRE = regexp.MustCompile(`/apps-manage/(T[A-Z0-9]{6,})/`)

// slackTeam is the workspace id the page's URL or its apps' links name, or "".
func slackTeam(pageURL string, rows []row) string {
	if m := slackTeamRE.FindStringSubmatch(pageURL); m != nil {
		return m[1]
	}
	for _, r := range rows {
		if m := slackTeamRE.FindStringSubmatch(r.Href); m != nil {
			return m[1]
		}
	}
	return ""
}

// slackWorkspaceFinding records, as an info finding, the id of a workspace signed in to, so
// attribution knows which workspace a leaked webhook belongs to.
func slackWorkspaceFinding(account, host, team string) finding.Finding {
	return finding.Finding{Account: account, Scope: host, Resource: finding.Resource{Type: attribution.SlackWorkspaceType, ID: team, Name: host},
		Kind: finding.KindSetting, Severity: finding.SevInfo, Title: "Slack workspace " + host + " is " + team,
		Evidence: map[string]any{"team_id": team, "host": host}}
}
