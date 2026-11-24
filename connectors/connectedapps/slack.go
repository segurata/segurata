package connectedapps

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
)

const (
	slackSignin = "https://slack.com/signin"
	slackRevoke = `Open the page, then "Configuration" › "Remove app" (needs a workspace admin if you are not one).`
)

// slack.com/signin lists the workspaces this browser is signed in to.
var slackSigninJS = inPage(`
  return {...page, rows: [...document.querySelectorAll('a[href*=".slack.com/"]')].map((a) => ({href: a.href}))};`)

const slackAppSel = `a[href*="/integrations/profile/"]`

var slackAppsJS = inPage(`return {...page, rows: rows('` + slackAppSel + `')};`)

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
	name, href, note string
	count            int
	pending          bool // approval required or restricted: requested, not installed
}

// parseSlackApp reads a row of <workspace>/apps/manage. The list shows only how many scopes each
// app has; the app's own page shows the developer's defaults, not what this workspace granted,
// so it is not read.
func parseSlackApp(r row) slackApp {
	a := slackApp{name: r.Name, href: r.Href}
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

func slack(ctx context.Context, e *env) {
	raw, err := e.b.load(ctx, slackSignin, slackSigninJS, readyWhen(func(p listPage) bool { return len(slackWorkspaces(p.Rows)) > 0 }), 30)
	if err != nil {
		e.fail("", err)
		return
	}
	p, _ := decode[listPage](raw)
	hosts := slackWorkspaces(p.Rows)
	if len(hosts) == 0 {
		e.status("", finding.StateSignedOut, "no Slack workspace signed in to the browser: %s", slackSignin)
		return
	}
	for _, host := range hosts {
		if ctx.Err() != nil {
			return
		}
		manage := "https://" + host + "/apps/manage"
		raw, err := e.b.load(ctx, manage, slackAppsJS, readyWhen(func(p listPage) bool {
			return len(p.Rows) > 0 || slackSignedOutRE.MatchString(p.URL) || slackEmptyRE.MatchString(p.Text)
		}), 40)
		if err != nil {
			e.fail(host, err)
			continue
		}
		p, _ := decode[listPage](raw)
		if p.URL == "" || slackSignedOutRE.MatchString(p.URL) {
			e.status(host, finding.StateSignedOut, "signed out of this workspace: %s", manage)
			continue
		}
		for _, r := range p.Rows {
			a := parseSlackApp(r)
			e.report(grant{who: host, scope: host, resType: "slack_app", name: a.name, count: a.count, note: a.note,
				url: a.href, revoke: slackRevoke, extra: map[string]any{"pending_approval": a.pending}})
		}
		if team := slackTeam(p.Rows); team != "" {
			e.emit.Finding(slackWorkspaceFinding(e.account(host), host, team))
		}
		e.status(host, finding.StateOK, "%d apps", len(p.Rows))
	}
}

// slackTeamRE reads the workspace id from an app's link: app.slack.com/apps-manage/<team>/integrations/….
var slackTeamRE = regexp.MustCompile(`/apps-manage/(T[A-Z0-9]{6,})/`)

// slackTeam is the workspace id the apps' links name, or "" for a workspace with no app listed.
func slackTeam(rows []row) string {
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
