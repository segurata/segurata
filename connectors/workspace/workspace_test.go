package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Synthetic tenant: no real accounts, apps or tokens.
const (
	domain    = "example.com"
	fakeToken = "ya29.synthetic-access-token-0123456789"
)

var now = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)

// fakeGcloud records each call and its environment and answers with a token or a failure.
type fakeGcloud struct {
	mu    sync.Mutex
	calls [][]string
	envs  [][]string
	err   error
}

func (g *fakeGcloud) factory(configured string, env []string) (cli.Runner, error) {
	return cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.calls = append(g.calls, args)
		g.envs = append(g.envs, env)
		if g.err != nil {
			return nil, g.err
		}
		return []byte(fakeToken + "\n"), nil
	}), nil
}

// tokenInfoServer answers tokeninfo like Google does: POST with the token in a form body.
func tokenInfoServer(t *testing.T, code int, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			t.Errorf("tokeninfo must be a POST without a query, got %s %s", r.Method, r.URL)
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("access_token") != fakeToken {
			t.Errorf("tokeninfo did not get the token in the form body")
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

const allScopes = `"https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.user.security https://www.googleapis.com/auth/admin.reports.audit.readonly"`

func validInfo(t *testing.T) *httptest.Server {
	return tokenInfoServer(t, 200, `{"scope":`+allScopes+`}`)
}

// tenant serves a directory with pagination, OAuth tokens per user and token activity.
func tenant(t *testing.T, extra map[string]httpxtest.Route) *httpxtest.Server {
	t.Helper()
	page1 := []map[string]any{
		{"primaryEmail": "boss@example.com", "isAdmin": true, "isEnrolledIn2Sv": false, "lastLoginTime": "2026-11-22T10:00:00.000Z", "creationTime": "2020-01-01T00:00:00.000Z"},
		{"primaryEmail": "deleg@example.com", "isDelegatedAdmin": true, "isEnrolledIn2Sv": true, "lastLoginTime": "2026-01-01T00:00:00.000Z"},
		{"primaryEmail": "ok@example.com", "isEnrolledIn2Sv": true, "isEnforcedIn2Sv": true, "lastLoginTime": "2026-11-22T00:00:00.000Z"},
	}
	page2 := []map[string]any{
		{"primaryEmail": "gone@example.com", "suspended": true, "lastLoginTime": "2025-01-01T00:00:00.000Z"},
		{"primaryEmail": "new@example.com", "lastLoginTime": "1970-01-01T00:00:00.000Z", "creationTime": "2026-11-01T00:00:00.000Z"},
		{"primaryEmail": "idle@example.com", "isEnrolledIn2Sv": true, "isEnforcedIn2Sv": true, "lastLoginTime": "1970-01-01T00:00:00.000Z", "creationTime": "2025-06-01T00:00:00.000Z"},
		{"primaryEmail": "spare@example.com", "isAdmin": true, "isEnrolledIn2Sv": true, "isEnforcedIn2Sv": true, "lastLoginTime": "2026-10-01T00:00:00.000Z"},
	}
	tokens := func(items ...map[string]any) httpxtest.Route { return httpxtest.Static(map[string]any{"items": items}) }
	routes := map[string]httpxtest.Route{
		"/directory/v1/users": func(q url.Values) (int, any) {
			if q.Get("customer") != "my_customer" || !strings.Contains(q.Get("fields"), "isEnforcedIn2Sv") {
				t.Errorf("users.list query: %v", q)
			}
			if q.Get("pageToken") == "p2" {
				return 200, map[string]any{"users": page2}
			}
			return 200, map[string]any{"users": page1, "nextPageToken": "p2"}
		},
		"/directory/v1/users/boss@example.com/tokens": tokens(
			map[string]any{"clientId": "c1", "displayText": "Mailer", "scopes": []string{"https://mail.google.com/"}}),
		"/directory/v1/users/ok@example.com/tokens": tokens(
			map[string]any{"clientId": "c1", "displayText": "Mailer", "scopes": []string{"https://www.googleapis.com/auth/drive.file"}},
			map[string]any{"clientId": "c2", "displayText": "Scheduler", "scopes": []string{"https://www.googleapis.com/auth/calendar"}},
			map[string]any{"clientId": "c3", "displayText": "Login", "scopes": []string{"openid", "email"}}),
		"/directory/v1/users/deleg@example.com/tokens": tokens(),
		"/directory/v1/users/new@example.com/tokens":   tokens(),
		"/directory/v1/users/idle@example.com/tokens":  tokens(),
		"/directory/v1/users/spare@example.com/tokens": tokens(),
		"/reports/v1/activity/users/all/applications/token": func(q url.Values) (int, any) {
			if q.Get("startTime") != "2026-10-24T00:00:00Z" {
				t.Errorf("activity startTime: %q", q.Get("startTime"))
			}
			return 200, map[string]any{"items": []map[string]any{
				{"id": map[string]any{"time": "2026-11-10T00:00:00.000Z"}, "events": []map[string]any{{"name": "authorize",
					"parameters": []map[string]any{{"name": "app_name", "value": "Mailer"}, {"name": "client_id", "value": "c1"}}}}},
				{"id": map[string]any{"time": "2026-11-12T00:00:00.000Z"}, "events": []map[string]any{{"name": "revoke",
					"parameters": []map[string]any{{"name": "app_name", "value": "Old Tool"}, {"name": "client_id", "value": "c9"}}}}},
			}}
		},
	}
	for k, v := range extra {
		routes[k] = v
	}
	return httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + fakeToken}, "X-Goog-User-Project": {"quota-1"}}, routes)
}

// credsHome makes a home folder whose default tenant config holds stored credentials.
func credsHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	dir := DefaultConfigDir(home, domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "application_default_credentials.json"), []byte(`{"type":"authorized_user"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func newTest(home string, api *httpxtest.Server, info *httptest.Server, g *fakeGcloud) *Connector {
	c := New()
	c.home, c.now, c.gcloud = home, func() time.Time { return now }, g.factory
	if api != nil {
		c.apiURL = api.URL
	}
	if info != nil {
		c.tokenInfoURL = info.URL
	}
	return c
}

func inventory(t *testing.T, c *Connector, cfg map[string]any, secrets map[string]string) *httpxtest.Recorder {
	t.Helper()
	rec := &httpxtest.Recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: cfg, Secrets: secrets}, rec); err != nil {
		t.Fatal(err)
	}
	for i := range rec.Findings {
		rec.Findings[i].Connector = connectorName
		rec.Findings[i].Fill(now)
	}
	return rec
}

func onlyStatus(t *testing.T, rec *httpxtest.Recorder) finding.Status {
	t.Helper()
	if len(rec.Statuses) != 1 || len(rec.Findings) != 0 {
		t.Fatalf("want exactly one status and no findings, got %+v and %d findings", rec.Statuses, len(rec.Findings))
	}
	return rec.Statuses[0]
}

func TestFullAudit(t *testing.T) {
	g := &fakeGcloud{}
	home := credsHome(t)
	api := tenant(t, nil)
	rec := inventory(t, newTest(home, api, validInfo(t), g), map[string]any{"domain": "Example.com", "quota_project": "quota-1"}, nil)

	if len(api.Misses) > 0 {
		t.Fatalf("unexpected API paths: %v", api.Misses)
	}
	if api.Hits["/directory/v1/users/gone@example.com/tokens"] != 0 {
		t.Fatal("tokens of a suspended account must not be listed")
	}
	if len(g.calls) != 1 || !slices.Equal(g.calls[0], []string{"auth", "application-default", "print-access-token", "--scopes=" + strings.Join(Scopes, ",")}) {
		t.Fatalf("gcloud calls: %v", g.calls)
	}
	if !slices.Contains(g.envs[0], "CLOUDSDK_CONFIG="+DefaultConfigDir(home, domain)) {
		t.Fatalf("gcloud must run with the tenant's own config: %v", g.envs[0])
	}
	rec.AssertNoSecret(t, fakeToken)

	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateOK || rec.Statuses[0].Account != domain ||
		rec.Statuses[0].Detail != "7 accounts, 6 active, 3 third-party apps" {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}

	want := []struct {
		typ, id string
		sev     finding.Severity
		title   string
	}{
		{"user_2sv", "boss@example.com", finding.SevCritical, "Super admin boss@example.com has no 2-Step Verification"},
		{"user_2sv", "deleg@example.com", finding.SevMedium, "Delegated admin deleg@example.com uses 2-Step Verification, but it is not enforced"},
		{"user_2sv", "new@example.com", finding.SevHigh, "User new@example.com has no 2-Step Verification"},
		{"admin", "boss@example.com", finding.SevMedium, "Super admin boss@example.com looks used day to day (last sign-in 2026-11-22)"},
		{"admin", "spare@example.com", finding.SevInfo, "spare@example.com is a super admin (last sign-in 2026-10-01)"},
		{"admin", "deleg@example.com", finding.SevInfo, "deleg@example.com is a delegated admin (last sign-in 2026-01-01)"},
		{"user_inactive", "deleg@example.com", finding.SevHigh, "Delegated admin deleg@example.com has not signed in for 326 days"},
		{"user_inactive", "gone@example.com", finding.SevLow, "gone@example.com is suspended (last sign-in 2025-01-01)"},
		{"user_inactive", "idle@example.com", finding.SevMedium, "idle@example.com has never signed in (created 540 days ago)"},
		{"oauth_app", "c1", finding.SevHigh, "Mailer can read, send and delete all Gmail (2 users)"},
		{"oauth_app", "c3", finding.SevInfo, "Login: Sign in with Google (1 user)"},
		{"oauth_app", "c2", finding.SevMedium, "Scheduler can access other Google data (1 user)"},
		{"oauth_activity", "c9", finding.SevInfo, "Old Tool: 0 authorizations and 1 revocation in the last 30 days, no current grants"},
	}
	if len(rec.Findings) != len(want) {
		for _, f := range rec.Findings {
			t.Logf("%s %s %s %s", f.Resource.Type, f.Resource.ID, f.Severity, f.Title)
		}
		t.Fatalf("want %d findings, got %d", len(want), len(rec.Findings))
	}
	for i, w := range want {
		f := rec.Findings[i]
		if f.Resource.Type != w.typ || f.Resource.ID != w.id || f.Severity != w.sev || f.Title != w.title || f.Account != domain {
			t.Errorf("finding %d: got %s %s %s %q", i, f.Resource.Type, f.Resource.ID, f.Severity, f.Title)
		}
		if f.Remediation.URL == "" || f.Remediation.Summary == "" || f.Remediation.Automatable {
			t.Errorf("finding %d: manual remediation with a help page expected: %+v", i, f.Remediation)
		}
	}

	mailer := rec.ByResource(t, "oauth_app", "c1")
	if !slices.Equal(mailer.Evidence["users"].([]string), []string{"boss@example.com", "ok@example.com"}) ||
		!slices.Equal(mailer.Evidence["scopes"].([]string), []string{"https://mail.google.com/", "https://www.googleapis.com/auth/drive.file"}) ||
		mailer.Evidence["authorizations_30d"] != 1 || mailer.LastUsedAt == nil || mailer.Kind != finding.KindGrant {
		t.Fatalf("Mailer evidence: %+v last used %v", mailer.Evidence, mailer.LastUsedAt)
	}
	idle := rec.ByResource(t, "user_inactive", "idle@example.com")
	if idle.LastUsedAt != nil || idle.CreatedAt == nil {
		t.Fatalf("a never-used account has no last use, only a creation date: %v %v", idle.LastUsedAt, idle.CreatedAt)
	}
	if rec.ByResource(t, "admin", "boss@example.com").Evidence["super_admins"] != 2 {
		t.Fatal("admin findings count the super admins")
	}
}

func TestInactiveDaysSetting(t *testing.T) {
	rec := inventory(t, newTest(credsHome(t), tenant(t, nil), validInfo(t), &fakeGcloud{}),
		map[string]any{"domain": domain, "quota_project": "quota-1", "inactive_days": float64(400)}, nil)
	for _, f := range rec.Findings {
		if f.Resource.Type == "user_inactive" && f.Resource.ID != "gone@example.com" && f.Resource.ID != "idle@example.com" {
			t.Errorf("%s is under 400 days idle: %s", f.Resource.ID, f.Title)
		}
	}
}

func TestNoTenantConfigured(t *testing.T) {
	g := &fakeGcloud{}
	st := onlyStatus(t, inventory(t, newTest(t.TempDir(), nil, nil, g), nil, nil))
	if st.State != finding.StateMissingCredentials || !strings.Contains(st.Detail, `"workspace:example.com": {"config": {"domain": "example.com"}}`) {
		t.Fatalf("status: %+v", st)
	}
	if len(g.calls) != 0 {
		t.Fatal("must not run gcloud without a tenant")
	}
}

func TestMissingCredentialsGivesTheOneTimeSetup(t *testing.T) {
	g := &fakeGcloud{}
	home := t.TempDir()
	st := onlyStatus(t, inventory(t, newTest(home, nil, nil, g), map[string]any{"domain": domain}, nil))
	if st.State != finding.StateMissingCredentials || st.Account != domain {
		t.Fatalf("status: %+v", st)
	}
	signIn := []string{`CLOUDSDK_CONFIG="` + DefaultConfigDir(home, domain) + `" gcloud auth application-default login`,
		"--client-id-file=$HOME/Downloads/client_secret.json",
		"--scopes=openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform,"}
	if runtime.GOOS == "windows" {
		signIn = []string{"$env:CLOUDSDK_CONFIG = '" + DefaultConfigDir(home, domain) + "'; gcloud auth application-default login `",
			"--scopes='openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform,"}
	}
	for _, want := range slices.Concat([]string{
		"No admin credentials for example.com with the read-only Admin SDK scopes.",
		`enable "Admin SDK API" and create an OAuth client ID`,
		"set the WORKSPACE_ACCESS_TOKEN secret",
	}, signIn, Scopes) {
		if !strings.Contains(st.Detail, want) {
			t.Errorf("setup steps lack %q:\n%s", want, st.Detail)
		}
	}
	if len(g.calls) != 0 {
		t.Fatal("must never run gcloud (let alone a login) without stored credentials")
	}
}

// In PowerShell the tenant's config folder is set for the sign-in only: an env prefix does not exist
// there, and a $env: left set would send every later gcloud command to the tenant.
func TestLoginHelpInPowerShell(t *testing.T) {
	help := loginHelpFor("windows", settings{domain: domain, cloudsdkConfig: `C:\Users\it's\.config\segurata\gcloud-example.com`})
	for _, want := range []string{
		`$env:CLOUDSDK_CONFIG = 'C:\Users\it''s\.config\segurata\gcloud-example.com'; gcloud auth application-default login ` + "`",
		`--client-id-file="$HOME\Downloads\client_secret.json" ` + "`",
		"; Remove-Item Env:CLOUDSDK_CONFIG",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("PowerShell sign-in lacks %q:\n%s", want, help)
		}
	}
	if strings.Contains(help, `CLOUDSDK_CONFIG="`) || strings.Contains(help, " \\\n") {
		t.Errorf("POSIX syntax in the PowerShell steps:\n%s", help)
	}
}

func TestAccessTokenSecretSkipsGcloud(t *testing.T) {
	g := &fakeGcloud{}
	rec := inventory(t, newTest(t.TempDir(), tenant(t, nil), validInfo(t), g),
		map[string]any{"domain": domain, "quota_project": "quota-1"}, map[string]string{secretName: fakeToken})
	if len(g.calls) != 0 || len(rec.Findings) == 0 {
		t.Fatalf("gcloud calls %v, findings %d", g.calls, len(rec.Findings))
	}
}

func TestCloudsdkConfigSetting(t *testing.T) {
	home := credsHome(t)
	g := &fakeGcloud{}
	custom := filepath.Join(home, "elsewhere")
	if err := os.MkdirAll(custom, 0o700); err != nil {
		t.Fatal(err)
	}
	st := onlyStatus(t, inventory(t, newTest(home, nil, nil, g), map[string]any{"domain": domain, "cloudsdk_config": "~/elsewhere"}, nil))
	if !strings.Contains(st.Detail, `CLOUDSDK_CONFIG="`+custom+`"`) {
		t.Fatalf("~ must expand to the home folder: %s", st.Detail)
	}
}

func TestTokenProblems(t *testing.T) {
	cases := []struct {
		name  string
		gerr  error
		info  *httptest.Server
		state finding.State
		want  string
	}{
		{"expired login", &cli.Error{Cmd: "gcloud auth", Stderr: "ERROR: (gcloud.auth.application-default.print-access-token) There was a problem refreshing your current auth tokens: ('invalid_grant: Bad Request')", Err: errors.New("exit status 1")},
			nil, finding.StateReauth, "gcloud could not issue a token for example.com (ERROR: (gcloud.auth.application-default.print-access-token) There was a problem"},
		{"gcloud missing", fmt.Errorf("gcloud: %w", exec.ErrNotFound), nil, finding.StateUnsupported, "install the Google Cloud SDK"},
		{"invalid token", nil, tokenInfoServer(t, 400, `{"error_description":"Invalid Value"}`), finding.StateReauth, "The token is not valid (Invalid Value)."},
		{"lacks scopes", nil, tokenInfoServer(t, 200, `{"scope":"openid"}`), finding.StateMissingCredentials, "The token lacks scopes: https://www.googleapis.com/auth/admin.directory.user.readonly, https://www.googleapis.com/auth/admin.directory.user.security."},
		{"other domain", nil, tokenInfoServer(t, 200, `{"scope":`+allScopes+`,"email":"admin@other.org"}`), finding.StateMissingCredentials,
			"The credentials for example.com belong to admin@other.org, outside that domain. Sign in again with an admin account of example.com."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := onlyStatus(t, inventory(t, newTest(credsHome(t), nil, tc.info, &fakeGcloud{err: tc.gerr}), map[string]any{"domain": domain}, nil))
			if st.State != tc.state || !strings.Contains(st.Detail, tc.want) {
				t.Fatalf("got %s %q", st.State, st.Detail)
			}
		})
	}
}

func TestCredentialsOfAnotherTenant(t *testing.T) {
	api := httpxtest.NewServer(t, nil, map[string]httpxtest.Route{
		"/directory/v1/users": httpxtest.Static(map[string]any{"users": []map[string]any{{"primaryEmail": "a@other.org"}}}),
	})
	st := onlyStatus(t, inventory(t, newTest(credsHome(t), api, validInfo(t), &fakeGcloud{}), map[string]any{"domain": domain}, nil))
	if st.State != finding.StateMissingCredentials || !strings.Contains(st.Detail, "list the users of another tenant") {
		t.Fatalf("got %+v", st)
	}
}

func TestWithoutReportsScope(t *testing.T) {
	info := tokenInfoServer(t, 200, `{"scope":"https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.user.security","email":"boss@example.com"}`)
	api := tenant(t, nil)
	rec := inventory(t, newTest(credsHome(t), api, info, &fakeGcloud{}), map[string]any{"domain": domain, "quota_project": "quota-1"}, nil)
	if api.Hits["/reports/v1/activity/users/all/applications/token"] != 0 {
		t.Fatal("must not call the Reports API without its scope")
	}
	st := rec.Statuses[len(rec.Statuses)-1]
	if st.State != finding.StateOK || !strings.Contains(st.Detail, "signed in as boss@example.com; token activity skipped") {
		t.Fatalf("status: %+v", st)
	}
}

func TestAdminSDKErrors(t *testing.T) {
	cases := []struct {
		code  int
		msg   string
		state finding.State
		want  string
	}{
		{403, "Not Authorized to access this resource/api", finding.StateError, "The account must be an admin of example.com"},
		{401, "Invalid Credentials", finding.StateReauth, "gcloud auth application-default login"},
		{403, "Admin SDK API has not been used in project 1 before or it is disabled", finding.StateError, "set quota_project"},
	}
	for _, tc := range cases {
		api := httpxtest.NewServer(t, nil, map[string]httpxtest.Route{"/directory/v1/users": httpxtest.Fail(tc.code, tc.msg)})
		st := onlyStatus(t, inventory(t, newTest(credsHome(t), api, validInfo(t), &fakeGcloud{}), map[string]any{"domain": domain}, nil))
		if st.State != tc.state || !strings.Contains(st.Detail, tc.want) {
			t.Errorf("%d %s: got %s %q", tc.code, tc.msg, st.State, st.Detail)
		}
	}
}

func TestPartialFailuresKeepTheRest(t *testing.T) {
	api := tenant(t, map[string]httpxtest.Route{
		"/directory/v1/users/ok@example.com/tokens":         httpxtest.Fail(403, "Not Authorized to access this resource/api"),
		"/reports/v1/activity/users/all/applications/token": httpxtest.Fail(403, "Not Authorized to access this resource/api"),
	})
	rec := inventory(t, newTest(credsHome(t), api, validInfo(t), &fakeGcloud{}), map[string]any{"domain": domain, "quota_project": "quota-1"}, nil)
	rec.ByResource(t, "oauth_app", "c1") // still seen through boss@
	var details []string
	for _, st := range rec.Statuses {
		if st.State == finding.StateOK {
			t.Fatal("no ok status after a partial failure")
		}
		details = append(details, st.Detail)
	}
	got := strings.Join(details, "\n")
	if !strings.Contains(got, "tokens.list failed for 1 account(s) (ok@example.com)") || !strings.Contains(got, "token activity: Forbidden (403") {
		t.Fatalf("statuses: %s", got)
	}
}

func TestReadOnlyAllowlist(t *testing.T) {
	for _, args := range [][]string{
		{"auth", "application-default", "login"},
		{"auth", "application-default", "revoke"},
		{"auth", "print-access-token"},
		{"config", "set", "account", "x"},
	} {
		if err := readOnly.Check(args); !errors.Is(err, cli.ErrRefused) {
			t.Errorf("%v must be refused", args)
		}
	}
}

func TestParseSettings(t *testing.T) {
	for _, bad := range []map[string]any{
		{"domain": "not a domain"},
		{"domain": 3},
		{"domain": ""},
		{"domain": "  "},
		{"domain": domain, "cloudsdk_config": ""},
		{"domain": domain, "quota_project": ""},
		{"domain": domain, "gcloud_path": ""},
		{"domain": domain, "gcloud_path": []any{"/x"}},
		{"domain": domain, "inactive_days": float64(-30)},
		{"domain": domain, "inactive_days": float64(1.5)},
		{"domain": domain, "inactive_days": float64(0)},
		{"domain": domain, "inactive_days": "90"},
	} {
		if _, err := parseSettings(bad, "/home/u"); err == nil {
			t.Errorf("%v must be rejected", bad)
		}
	}
	home := t.TempDir()
	s, err := parseSettings(map[string]any{"domain": domain}, home)
	if err != nil || s.inactiveDays != 90 || s.cloudsdkConfig != filepath.Join(home, ".config", "segurata", "gcloud-example.com") {
		t.Fatalf("defaults: %+v %v", s, err)
	}
}

func TestClassifyScope(t *testing.T) {
	for scope, want := range map[string]finding.Severity{
		"https://mail.google.com/":                                      finding.SevHigh,
		"https://www.googleapis.com/auth/gmail.readonly":                finding.SevHigh,
		"https://www.googleapis.com/auth/gmail.settings.sharing":        finding.SevHigh,
		"https://www.googleapis.com/auth/drive":                         finding.SevHigh,
		"https://www.googleapis.com/auth/drive.readonly":                finding.SevHigh,
		"https://www.googleapis.com/auth/spreadsheets":                  finding.SevHigh,
		"https://www.googleapis.com/auth/cloud-platform":                finding.SevHigh,
		"https://www.googleapis.com/auth/admin.directory.user":          finding.SevCritical,
		"https://www.googleapis.com/auth/admin.directory.user.readonly": finding.SevHigh,
		"https://www.googleapis.com/auth/drive.file":                    finding.SevLow,
		"https://www.googleapis.com/auth/calendar":                      finding.SevMedium,
		"https://www.googleapis.com/auth/gmail.labels":                  finding.SevMedium,
		"openid": finding.SevInfo,
		"https://www.googleapis.com/auth/userinfo.email": finding.SevInfo,
	} {
		if got := classifyScope(scope).sev; got != want {
			t.Errorf("%s: got %s, want %s", scope, got, want)
		}
	}
	if assessScopes(nil).sev != finding.SevInfo {
		t.Error("no scopes is sign-in only")
	}
}

// tokeninfo gets the token in a POST body, which a 307 or 308 would send again to wherever it
// points: the client follows no redirect, and the token reaches no other server.
func TestTokenInfoRedirectIsNotFollowed(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		leaked = leaked || strings.Contains(string(body), fakeToken) || strings.Contains(r.URL.String(), fakeToken)
		_, _ = w.Write([]byte(`{"scope":` + allScopes + `}`))
	}))
	t.Cleanup(other.Close)
	info := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/tokeninfo", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(info.Close)
	rec := inventory(t, newTest(credsHome(t), nil, info, &fakeGcloud{}), map[string]any{"domain": domain}, nil)
	if leaked {
		t.Fatal("the token was sent again to the redirect target")
	}
	st := onlyStatus(t, rec)
	if st.State != finding.StateReauth || strings.Contains(st.Detail, fakeToken) {
		t.Fatalf("got %s %q", st.State, st.Detail)
	}
}
