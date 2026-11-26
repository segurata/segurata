package connectedapps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/pagetext"
	"github.com/segurata/segurata/internal/fanout"
	"github.com/segurata/segurata/internal/finding"
)

const (
	ghSettings      = "https://github.com/settings"
	ghOAuthSel      = `a[href*="/settings/connections/applications/"]`
	ghConcurrency   = 6 // OAuth app pages open at once
	ghKeysURL       = ghSettings + "/keys"
	ghRevokeOAuth   = `Open the page and choose "Revoke access". The app keeps any data it already copied.`
	ghRevokeApp     = `Open the page, choose "Configure", then "Uninstall" at the bottom (GitHub asks you to confirm your identity first).`
	ghRevokeKey     = `If you no longer use it, delete it on the SSH and GPG keys page.`
	ghRevokeSession = `If you do not recognise it, open the page and revoke the session.`
)

// GitHub puts the login in a meta tag on every signed-in page.
const ghLogin = `login: (document.querySelector('meta[name="user-login"]') || {}).content || ""`

var ghOAuthJS = inPage(`
  const next = [...document.querySelectorAll('a[rel="next"], a.next_page'), ...[...document.querySelectorAll("a")].filter((a) => a.innerText.trim() === "Next")].map((a) => a.href)[0] || "";
  return {...page, ` + ghLogin + `, rows: rows('` + ghOAuthSel + `'), next};`)

var ghAuthorizedJS = inPage(`
  return {...page, ` + ghLogin + `, rows: rows('a[href*="/settings/connections/applications/"], a[href*="/settings/apps/authorizations/"]')};`)

// A pending permission update adds a second link under /permissions/, which is not an app.
var ghInstalledJS = inPage(`
  return {...page, ` + ghLogin + `, rows: everyRow('a[href*="/settings/installations/"]:not([href*="/permissions/"])')};`)

var ghSessionsJS = inPage(`
  return {...page, ` + ghLogin + `, rows: everyRow('a[href*="/settings/sessions/"]')};`)

const ghDetailJS = `({text: document.body ? document.body.innerText : ""})`

var (
	ghSignedOutRE = regexp.MustCompile(`^/(login|session)`)
	ghSudoRE      = regexp.MustCompile(`Confirm access|sudo mode`)
	ghEmptyRE     = regexp.MustCompile(`(?i)not granted any|No authorized|haven.t authorized|no installed|haven.t installed`)
	ghMetaRE      = regexp.MustCompile(`Never used|Last used|Owned by`)
	ghUsedRE      = regexp.MustCompile(`^(Never used|Last used[^·]*)`)
	ghOwnerRE     = regexp.MustCompile(`Owned by (.+)$`)
	ghYearsRE     = regexp.MustCompile(`within the last (\d+) years`)
)

func ghSignedOut(p listPage) bool {
	u, err := url.Parse(p.URL)
	return err == nil && ghSignedOutRE.MatchString(u.Path)
}

func ghSudo(p listPage) bool { return ghSudoRE.MatchString(p.Title + "\n" + p.Text) }

func ghListReady(p listPage) bool {
	return len(p.Rows) > 0 || ghSignedOut(p) || ghSudo(p) || ghEmptyRE.MatchString(p.Text)
}

func github(ctx context.Context, e *env) {
	login, ok := githubOAuth(ctx, e)
	if !ok {
		return
	}
	githubAuthorized(ctx, e, login)
	githubInstalled(ctx, e, login)
	githubSessions(ctx, e, login)
	githubKeys(ctx, e, login)
}

type ghApp struct {
	name, href, used, owner string
	stale                   bool
}

// parseGitHubApp reads a row of the OAuth or authorized-apps list and its "Last used · Owned by" line.
func parseGitHubApp(r row) ghApp {
	a := ghApp{name: r.Name, href: r.Href}
	for _, l := range r.Lines {
		if !ghMetaRE.MatchString(l) {
			continue
		}
		if m := ghUsedRE.FindStringSubmatch(l); m != nil {
			a.used = strings.TrimSpace(m[1])
		}
		if m := ghOwnerRE.FindStringSubmatch(l); m != nil {
			a.owner = strings.TrimSpace(m[1])
		}
		break
	}
	a.stale = ghStale(a.used)
	return a
}

// ghStale reads GitHub's coarse wording: "within the last 2 years" means more than a year ago.
// "Never used" carries no date, so it is not stale.
func ghStale(used string) bool {
	m := ghYearsRE.FindStringSubmatch(used)
	if m == nil {
		return false
	}
	n, _ := strconv.Atoi(m[1])
	return n >= 2
}

// githubOAuth lists authorized OAuth apps across pages and reads each app's page for its
// permissions and organization access. It returns false when GitHub is signed out.
func githubOAuth(ctx context.Context, e *env) (string, bool) {
	var apps []ghApp
	login := ""
	for next, seen := ghSettings+"/applications", map[string]bool{}; next != "" && !seen[next]; {
		seen[next] = true
		p, err := load(ctx, e, next, ghOAuthJS, ghListReady, 40)
		if err != nil {
			e.fail(login, err)
			return login, false
		}
		if p.URL == "" || ghSignedOut(p) {
			e.status("", finding.StateSignedOut, "not signed in to GitHub in the browser: %s/applications", ghSettings)
			return "", false
		}
		if login == "" {
			login = p.Login
		}
		for _, r := range p.Rows {
			apps = append(apps, parseGitHubApp(r))
		}
		next = p.Next
	}

	details := make([]ghDetail, len(apps))
	errs := make([]error, len(apps))
	fanout.Each(len(apps), ghConcurrency, func(i int) {
		p, err := load(ctx, e, apps[i].href, ghDetailJS, func(p listPage) bool {
			return strings.Contains(p.Text, "Permissions") || strings.Contains(p.Text, "Organization access")
		}, 30)
		if err != nil {
			errs[i] = err
			return
		}
		details[i] = parseGitHubDetail(p.Text)
	})
	failed := 0
	for i, a := range apps {
		if errs[i] != nil {
			failed++
			e.status(login, finding.StateError, "OAuth app %s: %v", a.name, errs[i])
			continue
		}
		e.report(grant{who: login, resType: "github_oauth_app", name: a.name, scopes: details[i].scopes,
			orgs: details[i].orgs, publisher: a.owner, usedText: a.used, stale: a.stale, url: a.href, revoke: ghRevokeOAuth})
	}
	e.status(login, finding.StateOK, "%d OAuth apps, %d unreadable", len(apps)-failed, failed)
	return login, true
}

type ghDetail struct {
	scopes []string // never nil
	orgs   []string // never nil
}

var (
	ghPermsStartRE = regexp.MustCompile(`^Permissions$`)
	ghPermsEndRE   = regexp.MustCompile(`^Applications act on your behalf`)
	ghPermsSkipRE  = regexp.MustCompile(`^Revoke access$`)
	ghOrgsStartRE  = regexp.MustCompile(`^Organization access$`)
	ghOrgsEndRE    = regexp.MustCompile(`^Footer$`)
	ghOrgButtonRE  = regexp.MustCompile(`^(Loading|Request|Requested|Grant|Denied)$`)
)

// parseGitHubDetail reads an OAuth app's page. Under "Organization access" an organization the
// app cannot reach is followed by a button ("Request", "Grant"); one it can reach has none.
func parseGitHubDetail(text string) ghDetail {
	lines := pagetext.Lines(text)
	d := ghDetail{scopes: between(lines, ghPermsStartRE, ghPermsEndRE, ghPermsSkipRE), orgs: []string{}}
	org := between(lines, ghOrgsStartRE, ghOrgsEndRE, nil)
	for i, l := range org {
		if ghOrgButtonRE.MatchString(l) || i+1 < len(org) && ghOrgButtonRE.MatchString(org[i+1]) {
			continue
		}
		d.orgs = append(d.orgs, l)
	}
	return d
}

// between returns the lines after start and before end, except skip ones. Never nil.
func between(lines []string, start, end, skip *regexp.Regexp) []string {
	out := []string{}
	in := false
	for _, l := range lines {
		switch {
		case !in:
			in = start.MatchString(l)
		case end.MatchString(l):
			return out
		case skip == nil || !skip.MatchString(l):
			out = append(out, l)
		}
	}
	return out
}

// githubAuthorized lists authorized GitHub Apps, shown only in sudo mode: the password prompt is
// reported as reauth.
func githubAuthorized(ctx context.Context, e *env, login string) {
	u := ghSettings + "/apps/authorizations"
	p, err := load(ctx, e, u, ghAuthorizedJS, ghListReady, 30)
	if err != nil {
		e.fail(login, err)
		return
	}
	if ghSudo(p) {
		e.status(login, finding.StateReauth, "authorized GitHub Apps need sudo mode: open %s, confirm your identity, and run again within a few minutes", u)
		return
	}
	for _, r := range p.Rows {
		a := parseGitHubApp(r)
		e.report(grant{who: login, resType: "github_app_authorized", name: a.name, publisher: a.owner,
			usedText: a.used, stale: a.stale, url: a.href, revoke: ghRevokeOAuth})
	}
}

// githubInstalled lists GitHub Apps installed on the personal account; their permissions need
// sudo mode and are not read.
func githubInstalled(ctx context.Context, e *env, login string) {
	p, err := load(ctx, e, ghSettings+"/installations", ghInstalledJS, ghListReady, 30)
	if err != nil {
		e.fail(login, err)
		return
	}
	if ghSudo(p) {
		e.status(login, finding.StateReauth, "installed GitHub Apps need sudo mode: open %s/installations, confirm your identity, and run again", ghSettings)
		return
	}
	for _, r := range p.Rows {
		name, note := parseGitHubInstalled(r)
		e.report(grant{who: login, resType: "github_app_installed", name: name, note: note, url: r.Href, revoke: ghRevokeApp})
	}
}

// parseGitHubInstalled reads an installed app's name, then notes such as "Suspended".
func parseGitHubInstalled(r row) (name, note string) {
	var rest []string
	for _, l := range r.Lines {
		if l == "Configure" {
			continue
		}
		if name == "" {
			name = l
			continue
		}
		rest = append(rest, l)
	}
	return name, strings.Join(rest, " ")
}

func githubSessions(ctx context.Context, e *env, login string) {
	p, err := load(ctx, e, ghSettings+"/sessions", ghSessionsJS, func(p listPage) bool { return len(p.Rows) > 0 || ghSudo(p) }, 30)
	if err != nil {
		e.fail(login, err)
		return
	}
	for _, r := range p.Rows {
		s := parseGitHubSession(r)
		e.report(grant{who: login, resType: "github_session", kind: finding.KindCredential, name: s.name, key: lastSegment(r.Href),
			usedText: s.seen, note: s.note, url: r.Href, revoke: ghRevokeSession, extra: map[string]any{"current": s.current}})
	}
}

// lastSegment is the session number of /settings/sessions/<n>, which outlives its IP.
func lastSegment(href string) string {
	u, err := url.Parse(href)
	if err != nil {
		return href
	}
	p := strings.TrimRight(u.Path, "/")
	return p[strings.LastIndex(p, "/")+1:]
}

type ghSession struct {
	name, seen, note string
	current          bool
}

var ghSeenRE = regexp.MustCompile(`(?i)Seen|Last accessed|active`)

func parseGitHubSession(r row) ghSession {
	var ls []string
	for _, l := range r.Lines {
		if l != "Details" && l != "Revoke" {
			ls = append(ls, l)
		}
	}
	var s ghSession
	if len(ls) == 0 {
		return s
	}
	s.name = ls[0]
	for _, l := range ls[1:] {
		if s.seen == "" && ghSeenRE.MatchString(l) {
			s.seen = l
		}
		if strings.Contains(l, "current session") {
			s.current = true
		}
	}
	s.note = strings.Join(ls[1:], " · ")
	return s
}

// ghAuthStatus prints the signed-in accounts and their scopes as JSON, never the token.
var ghAuthStatus = []string{"auth", "status", "--json", "hosts"}

type ghAccount struct {
	Login       string `json:"login"`
	Active      bool   `json:"active"`
	State       string `json:"state"`
	Scopes      string `json:"scopes"` // comma-separated
	TokenSource string `json:"tokenSource"`
}

func parseGhStatus(out []byte) (acct ghAccount, found bool, err error) {
	var st struct {
		Hosts map[string][]ghAccount `json:"hosts"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return ghAccount{}, false, err
	}
	for _, a := range st.Hosts["github.com"] {
		if a.Active {
			return a, true, nil
		}
	}
	return ghAccount{}, false, nil
}

func (a ghAccount) has(scope string) bool {
	return slices.Contains(strings.Split(strings.ReplaceAll(a.Scopes, " ", ""), ","), scope)
}

// ghStderr is what gh printed on failure, or the error itself.
func ghStderr(err error) string {
	if ce, ok := errors.AsType[*cli.Error](err); ok {
		return ce.Stderr
	}
	return err.Error()
}

// ghAllowlist is every gh command inventory and doctor may run.
var ghAllowlist = cli.CheckFunc(func(args []string) error {
	if slices.Equal(args, ghAuthStatus) {
		return nil
	}
	if len(args) == 3 && args[0] == "api" && args[1] == "--paginate" {
		for _, k := range ghKeyEndpoints {
			if args[2] == k.path {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: gh %s", cli.ErrRefused, strings.Join(args, " "))
})

var ghKeyEndpoints = []struct {
	resType, path, scope, label string
}{
	{"github_ssh_key", "/user/keys", "admin:public_key", "SSH key"},
	{"github_ssh_signing_key", "/user/ssh_signing_keys", "admin:ssh_signing_key", "SSH signing key"},
	{"github_gpg_key", "/user/gpg_keys", "admin:gpg_key", "GPG key"},
}

// ghKey never keeps the public key itself, only its type.
type ghKey struct {
	ID       json.Number `json:"id"`
	Title    string      `json:"title"`
	Name     string      `json:"name"`
	KeyID    string      `json:"key_id"`
	Key      string      `json:"key"`
	Created  *time.Time  `json:"created_at"`
	LastUsed *time.Time  `json:"last_used"`
	Expires  *time.Time  `json:"expires_at"`
}

func (k ghKey) label() string {
	for _, s := range []string{k.Title, k.Name, k.KeyID, k.ID.String()} {
		if s != "" {
			return s
		}
	}
	return "unnamed"
}

func (k ghKey) keyType() string {
	if t, _, _ := strings.Cut(k.Key, " "); t != "" && !strings.HasPrefix(t, "-----") {
		return t
	}
	if k.KeyID != "" {
		return "gpg"
	}
	return ""
}

var (
	ghNoScopeRE   = regexp.MustCompile(`needs the .* scope|HTTP 404|Not Found`)
	ghSignedOffRE = regexp.MustCompile(`(?i)not logged in|auth login`)
)

// githubKeys lists SSH, signing and GPG keys. A missing scope is noscope, with the command that
// adds it.
func githubKeys(ctx context.Context, e *env, login string) {
	for _, ep := range ghKeyEndpoints {
		out, err := e.gh.Run(ctx, "api", "--paginate", ep.path)
		if err != nil {
			msg := ghStderr(err)
			switch {
			case errors.Is(err, exec.ErrNotFound):
				e.status(login, finding.StateUnsupported, "the gh CLI is not installed: GitHub keys not listed (%s)", ghKeysURL)
				return
			case ghSignedOffRE.MatchString(msg):
				e.status(login, finding.StateSignedOut, "gh is not signed in: run `gh auth login` to list GitHub keys")
				return
			case ghNoScopeRE.MatchString(msg):
				e.status(login, finding.StateNoScope, "%ss not listed: gh lacks the %s scope; run: gh auth refresh -h github.com -s %s", ep.label, ep.scope, ep.scope)
				continue
			}
			e.status(login, finding.StateError, "gh api %s: %v", ep.path, err)
			continue
		}
		keys, err := parseGitHubKeys(out)
		if err != nil {
			e.status(login, finding.StateError, "gh api %s: %v", ep.path, err)
			continue
		}
		for _, k := range keys {
			extra := map[string]any{"key_type": k.keyType()}
			if k.Expires != nil {
				extra["expires_at"] = k.Expires
			}
			e.report(grant{who: login, resType: ep.resType, kind: finding.KindCredential, name: ep.label + " " + strconv.Quote(k.label()),
				created: k.Created, lastUsed: k.LastUsed, url: ghKeysURL, revoke: ghRevokeKey, extra: extra})
		}
	}
}

// parseGitHubKeys reads `gh api --paginate`, which concatenates one JSON array per page.
func parseGitHubKeys(out []byte) ([]ghKey, error) {
	var all []ghKey
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	for dec.More() {
		var page []ghKey
		if err := dec.Decode(&page); err != nil {
			return nil, fmt.Errorf("unexpected output: %w", err)
		}
		all = append(all, page...)
	}
	return all, nil
}
