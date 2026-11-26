package workspace

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

// Help pages checked on 2026-11-24.
const (
	twoSVURL   = "https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
	adminsURL  = "https://knowledge.workspace.google.com/admin/users/security-best-practices-for-administrator-accounts"
	removeURL  = "https://knowledge.workspace.google.com/admin/users/delete-or-remove-a-user-from-your-organization"
	appsURL    = "https://knowledge.workspace.google.com/admin/apps/control-which-apps-access-google-workspace-data"
	dailyUse   = 3 * 24 * time.Hour // a super admin signed in this recently is used day to day
	scopesBase = "https://www.googleapis.com/auth/"
)

type account struct {
	email                      string
	superAdmin, delegatedAdmin bool
	enrolled, enforced         bool
	suspended, archived        bool
	lastLogin, created         *time.Time
	idleDays                   int // since the last login, or since creation without one; -1 unknown
}

func newAccount(u user, now time.Time) account {
	a := account{email: strings.ToLower(u.PrimaryEmail), superAdmin: u.IsAdmin, delegatedAdmin: u.IsDelegatedAdmin,
		enrolled: u.IsEnrolledIn2Sv, enforced: u.IsEnforcedIn2Sv, suspended: u.Suspended, archived: u.Archived,
		lastLogin: httpx.ParseTime(&u.LastLoginTime), created: httpx.ParseTime(&u.CreationTime), idleDays: -1}
	if a.lastLogin != nil && a.lastLogin.Year() <= 1970 {
		a.lastLogin = nil // the Directory API reports "never" as the Unix epoch
	}
	switch {
	case a.lastLogin != nil:
		a.idleDays = httpx.Days(now, *a.lastLogin)
	case a.created != nil:
		a.idleDays = httpx.Days(now, *a.created)
	}
	return a
}

func (a account) live() bool  { return !a.suspended && !a.archived }
func (a account) admin() bool { return a.superAdmin || a.delegatedAdmin }

func (a account) role() string {
	switch {
	case a.superAdmin:
		return "super admin"
	case a.delegatedAdmin:
		return "delegated admin"
	}
	return "user"
}

func (a account) before(b account) bool {
	if a.superAdmin != b.superAdmin {
		return a.superAdmin
	}
	if a.delegatedAdmin != b.delegatedAdmin {
		return a.delegatedAdmin
	}
	return a.email < b.email
}

func (a account) lastLoginText() string {
	if a.lastLogin == nil {
		return "never"
	}
	return a.lastLogin.Format("2006-01-02")
}

func (a account) evidence() map[string]any {
	return map[string]any{"role": a.role(), "enrolled_2sv": a.enrolled, "enforced_2sv": a.enforced,
		"suspended": a.suspended, "archived": a.archived, "last_login": a.lastLoginText()}
}

func userFindings(domain string, accounts []account, inactiveDays int, now time.Time) []finding.Finding {
	var twoSV, admins, stale []finding.Finding
	superAdmins := 0
	for _, a := range accounts {
		if a.superAdmin {
			superAdmins++
		}
	}
	for _, a := range accounts {
		base := finding.Finding{Account: domain, CreatedAt: a.created, LastUsedAt: a.lastLogin, Evidence: a.evidence()}
		if f, ok := twoSVFinding(base, a); ok {
			twoSV = append(twoSV, f)
		}
		if a.admin() {
			admins = append(admins, adminFinding(base, a, superAdmins, now))
		}
		if f, ok := staleFinding(base, a, inactiveDays); ok {
			stale = append(stale, f)
		}
	}
	return append(append(twoSV, admins...), stale...)
}

func twoSVFinding(f finding.Finding, a account) (finding.Finding, bool) {
	if !a.live() || (a.enrolled && a.enforced) {
		return f, false
	}
	f.Resource = finding.Resource{Type: "user_2sv", ID: a.email, Name: a.email}
	f.Kind = finding.KindSetting
	who := textfmt.UpperFirst(a.role()) + " " + a.email
	switch {
	case !a.enrolled && a.admin():
		f.Severity, f.Title = finding.SevCritical, who+" has no 2-Step Verification"
	case !a.enrolled:
		f.Severity, f.Title = finding.SevHigh, who+" has no 2-Step Verification"
	case a.admin():
		f.Severity, f.Title = finding.SevMedium, who+" uses 2-Step Verification, but it is not enforced"
	default:
		f.Severity, f.Title = finding.SevLow, who+" uses 2-Step Verification, but it is not enforced"
	}
	f.Remediation = finding.Remediation{URL: twoSVURL,
		Summary: "Have the user enroll (a security key or passkey for admins), then enforce 2-Step Verification for their organizational unit in Admin console > Security > Authentication > 2-step verification"}
	return f, true
}

func adminFinding(f finding.Finding, a account, superAdmins int, now time.Time) finding.Finding {
	f.Resource = finding.Resource{Type: "admin", ID: a.email, Name: a.email}
	f.Kind = finding.KindSetting
	f.Evidence["super_admins"] = superAdmins
	f.Severity = finding.SevInfo
	f.Title = fmt.Sprintf("%s is a %s (last sign-in %s)", a.email, a.role(), a.lastLoginText())
	f.Remediation = finding.Remediation{URL: adminsURL, Summary: "Keep admin roles to the people who need them"}
	if a.superAdmin {
		f.Remediation.Summary = "Give each super admin a separate account for daily work and sign in to the super admin account only for tasks that need it; keep more than one super admin, each held by a different person"
		if a.live() && a.lastLogin != nil && now.Sub(*a.lastLogin) < dailyUse {
			f.Severity = finding.SevMedium
			f.Title = fmt.Sprintf("Super admin %s looks used day to day (last sign-in %s)", a.email, a.lastLoginText())
		}
	}
	return f
}

func staleFinding(f finding.Finding, a account, inactiveDays int) (finding.Finding, bool) {
	f.Resource = finding.Resource{Type: "user_inactive", ID: a.email, Name: a.email}
	f.Kind = finding.KindSetting
	f.Evidence["idle_days"] = a.idleDays
	f.Remediation = finding.Remediation{URL: removeURL}
	switch {
	case !a.live():
		state := "suspended"
		if !a.suspended {
			state = "archived"
		}
		f.Severity, f.Title = finding.SevLow, fmt.Sprintf("%s is %s (last sign-in %s)", a.email, state, a.lastLoginText())
		f.Remediation.Summary = "Delete the account after transferring its data, or keep it on purpose with segurata accept"
	case a.idleDays > inactiveDays:
		f.Severity = finding.SevMedium
		if a.admin() {
			f.Severity = finding.SevHigh
		}
		if a.lastLogin == nil {
			f.Title = fmt.Sprintf("%s has never signed in (created %d days ago)", a.email, a.idleDays)
		} else {
			f.Title = fmt.Sprintf("%s has not signed in for %d days", a.email, a.idleDays)
		}
		if a.admin() {
			f.Title = textfmt.UpperFirst(a.role()) + " " + f.Title
		}
		f.Remediation.Summary = "If nobody uses the account, suspend or delete it after transferring its Drive and Gmail data"
	default:
		return f, false
	}
	return f, true
}

type scopeRule struct {
	re    *regexp.Regexp
	sev   finding.Severity
	label string
}

// scopeRules match a scope without the googleapis prefix; first match wins.
var scopeRules = []scopeRule{
	{regexp.MustCompile(`^admin\..*\.readonly$`), finding.SevHigh, "read the domain's admin data"},
	{regexp.MustCompile(`^admin\.`), finding.SevCritical, "change the domain's admin settings"},
	{regexp.MustCompile(`^mail\.google\.com/?$`), finding.SevHigh, "read, send and delete all Gmail"},
	{regexp.MustCompile(`^gmail\.(readonly|modify|compose|send|insert|settings\..*)$`), finding.SevHigh, "read or send Gmail"},
	{regexp.MustCompile(`^drive(\.readonly)?$`), finding.SevHigh, "access every Drive file"},
	{regexp.MustCompile(`^(spreadsheets|documents|presentations)(\.readonly)?$`), finding.SevHigh, "access every Doc, Sheet or Slides file"},
	{regexp.MustCompile(`^cloud-platform(\.read-only)?$`), finding.SevHigh, "use Google Cloud with full access"},
	{regexp.MustCompile(`^drive\.(file|appdata)$`), finding.SevLow, "access the Drive files it created or was given"},
	{regexp.MustCompile(`^(openid|email|profile|userinfo\.(email|profile))$`), finding.SevInfo, "Sign in with Google only"},
}

var unknownScope = scopeRule{sev: finding.SevMedium, label: "access other Google data"}

func classifyScope(scope string) scopeRule {
	s := strings.TrimPrefix(strings.TrimPrefix(scope, scopesBase), "https://")
	for _, r := range scopeRules {
		if r.re.MatchString(s) {
			return r
		}
	}
	return unknownScope
}

// assessScopes returns the worst rule, the earlier scope on a tie; no scopes counts as sign-in.
func assessScopes(scopes []string) scopeRule {
	worst := scopeRule{sev: finding.SevInfo, label: "Sign in with Google only"}
	for i, s := range scopes {
		if r := classifyScope(s); i == 0 || r.sev.Rank() > worst.sev.Rank() {
			worst = r
		}
	}
	return worst
}

type app struct {
	clientID, name    string
	users, scopes     []string
	native, anonymous bool
}

func aggregate(grants []grant) []app {
	byClient := map[string]*app{}
	for _, g := range grants {
		a := byClient[g.ClientID]
		if a == nil {
			a = &app{clientID: g.ClientID, name: cmp.Or(g.DisplayText, g.ClientID)}
			byClient[g.ClientID] = a
		}
		a.users = append(a.users, g.user)
		a.scopes = append(a.scopes, g.Scopes...)
		a.native = a.native || g.NativeApp
		a.anonymous = a.anonymous || g.Anonymous
	}
	out := make([]app, 0, len(byClient))
	for _, a := range byClient {
		sort.Strings(a.users)
		slices.Sort(a.scopes)
		a.scopes = slices.Compact(a.scopes)
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].users) != len(out[j].users) {
			return len(out[i].users) > len(out[j].users)
		}
		return out[i].name < out[j].name
	})
	return out
}

// appFindings adds an info finding for apps that show up only in the token activity.
func appFindings(domain string, apps []app, activity map[string]*appActivity) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, a := range apps {
		rule := assessScopes(a.scopes)
		ev := map[string]any{"client_id": a.clientID, "users": a.users, "user_count": len(a.users), "scopes": a.scopes,
			"native_app": a.native, "anonymous": a.anonymous}
		f := finding.Finding{Account: domain, Kind: finding.KindGrant, Severity: rule.sev,
			Resource: finding.Resource{Type: "oauth_app", ID: a.clientID, Name: a.name},
			Title:    fmt.Sprintf("%s can %s (%s)", a.name, rule.label, textfmt.Count(len(a.users), "user", "users")),
			Evidence: ev,
			Remediation: finding.Remediation{URL: appsURL,
				Summary: "In Admin console > Security > Access and data control > API controls > Manage third-party app access, trust, limit or block the app; then remove it from the accounts that should not have it"}}
		if rule.sev == finding.SevInfo {
			f.Title = fmt.Sprintf("%s: Sign in with Google (%s)", a.name, textfmt.Count(len(a.users), "user", "users"))
		}
		if act := lookup(activity, a.clientID, a.name); act != nil {
			seen[activityKey(act)] = true
			ev["authorizations_30d"], ev["revocations_30d"] = act.authorize, act.revoke
			f.LastUsedAt = httpx.ParseTime(&act.lastEvent)
		}
		out = append(out, f)
	}
	for _, k := range slices.Sorted(maps.Keys(activity)) {
		act := activity[k]
		if seen[activityKey(act)] {
			continue
		}
		out = append(out, finding.Finding{Account: domain, Kind: finding.KindGrant, Severity: finding.SevInfo,
			Resource:   finding.Resource{Type: "oauth_activity", ID: k, Name: act.app},
			Title:      fmt.Sprintf("%s: %s and %s in the last 30 days, no current grants", act.app, textfmt.Count(act.authorize, "authorization", "authorizations"), textfmt.Count(act.revoke, "revocation", "revocations")),
			Evidence:   map[string]any{"client_id": act.clientID, "authorizations_30d": act.authorize, "revocations_30d": act.revoke},
			LastUsedAt: httpx.ParseTime(&act.lastEvent),
			Remediation: finding.Remediation{URL: appsURL,
				Summary: "Nothing holds a grant now; check the app is one the tenant expects, and block it in API controls if not"}})
	}
	return out
}

func activityKey(a *appActivity) string { return cmp.Or(a.clientID, a.app) }

// lookup falls back to the name for events that carried no client id.
func lookup(activity map[string]*appActivity, clientID, name string) *appActivity {
	if act := activity[clientID]; act != nil {
		return act
	}
	return activity[name]
}
