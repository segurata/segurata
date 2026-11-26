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

var slackSigninJS = inPage(`
  return {...page, rows: [...document.querySelectorAll('a[href*=".slack.com/"]')].map((a) => ({href: a.href}))};`)

const (
	slackAppSel   = `a[href*="/integrations/profile/"]`
	slackListPath = "/api/admin.apps.installed.list"
)

// In a hidden target the app list may never render (checked 2026-11-24), so the list the page
// fetched is what counts.
var slackAppsJS = inPage(`return {...page, rows: rows('` + slackAppSel + `'),
  fetched: performance.getEntriesByType("resource").some((e) => e.name.includes(` + strconv.Quote(slackListPath) + `))};`)

var slackListRE = regexp.MustCompile(regexp.QuoteMeta(slackListPath))

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
	pending              bool // requested, not installed
}

var slackAppIDRE = regexp.MustCompile(`/integrations/profile/(A[A-Z0-9]+)`)

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

// slackInstalled is one app of the admin.apps.installed.list response the manage page fetches.
type slackInstalled struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	BotScopes  []string `json:"declared_bot_scopes"`
	UserScopes []string `json:"declared_user_scopes"`
	Internal   bool     `json:"is_internal"`
}

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

func slackListed(p listPage) bool { return len(p.Rows) > 0 || slackEmptyRE.MatchString(p.Text) }

// slackReady: the response can finish a moment after its timing entry appears.
func slackReady() func(slackPage) bool {
	return twice(func(p slackPage) bool {
		return p.URL != "" && (slackSignedOutRE.MatchString(p.URL) || p.Fetched || slackListed(p.listPage))
	})
}

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

// slackWorkspace grades the apps of the fetched list by their declared scopes, and the rows the
// list lacks (waiting for approval) by their scope count.
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

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

var slackTeamRE = regexp.MustCompile(`/apps-manage/(T[A-Z0-9]{6,})/`)

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

// slackWorkspaceFinding records a workspace's id so attribution knows whose a leaked webhook is.
func slackWorkspaceFinding(account, host, team string) finding.Finding {
	return finding.Finding{Account: account, Scope: host, Resource: finding.Resource{Type: attribution.SlackWorkspaceType, ID: team, Name: host},
		Kind: finding.KindSetting, Severity: finding.SevInfo, Title: "Slack workspace " + host + " is " + team,
		Evidence: map[string]any{"team_id": team, "host": host}}
}
