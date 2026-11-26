package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/budget"
	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// outcome is one recorded gcloud answer: a fixture file for stdout, or a stderr fixture for a failure.
type outcome struct{ stdout, stderr string }

// fakeRunner replays recorded answers keyed by the command line without --format=json.
type fakeRunner struct {
	t     *testing.T
	mu    sync.Mutex
	plays map[string][]outcome
	calls []string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if args[len(args)-1] != "--format=json" {
		f.t.Errorf("gcloud called without --format=json: %v", args)
	}
	key := strings.Join(args[:len(args)-1], " ")
	f.calls = append(f.calls, key)
	queue, ok := f.plays[key]
	if !ok || len(queue) == 0 {
		f.t.Errorf("unexpected gcloud call: %s", key)
		return nil, errors.New("unexpected call")
	}
	o := queue[0]
	if len(queue) > 1 {
		f.plays[key] = queue[1:]
	}
	if o.stderr != "" {
		return nil, &cli.Error{Cmd: "gcloud", Stderr: fixture(f.t, o.stderr), Err: errors.New("exit status 1")}
	}
	if o.stdout == "" {
		return nil, nil // gcloud printed nothing
	}
	return []byte(fixture(f.t, o.stdout)), nil
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type recorder struct{ httpxtest.Recorder }

func (r *recorder) byTitle(t *testing.T, sub string) finding.Finding {
	t.Helper()
	for _, match := range []func(string, string) bool{strings.HasSuffix, strings.Contains} {
		for _, f := range r.Findings {
			if match(f.Title, sub) {
				return f
			}
		}
	}
	t.Fatalf("no finding with title containing %q in:\n%s", sub, r.titles())
	return finding.Finding{}
}

func (r *recorder) titles() string {
	var b strings.Builder
	for _, f := range r.Findings {
		b.WriteString("  [" + string(f.Severity) + "] " + f.Title + "\n")
	}
	return b.String()
}

// fakeHome copies testdata/home into a temp dir with the permissions git cannot keep.
func fakeHome(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", "home")
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func testConnector(t *testing.T, home string, plays map[string][]outcome, env map[string]string) (*Connector, *fakeRunner) {
	r := &fakeRunner{t: t, plays: plays}
	return &Connector{
		runner: r,
		getenv: func(k string) string { return env[k] },
		home:   home,
		now:    func() time.Time { return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC) },
	}, r
}

const (
	owner = "--account=owner@example.com"
	work  = "--account=work@example.org"
	ci    = "--account=ci@demo-shop.iam.gserviceaccount.com"
)

func fullScenario() map[string][]outcome {
	shop, blog := "--project=demo-shop", "--project=demo-blog"
	return map[string][]outcome{
		"auth list":                      {{stdout: "auth_list.json"}},
		"projects list " + owner:         {{stdout: "projects_owner.json"}},
		"projects list " + work:          {{stderr: "reauth.txt"}},
		"billing accounts list " + owner: {{stdout: "billing_accounts_owner.json"}},

		"projects get-iam-policy demo-shop " + owner:      {{stdout: "iam_policy_shop.json"}},
		"iam service-accounts list " + shop + " " + owner: {{stdout: "sa_list_shop.json"}},
		"iam service-accounts keys list --iam-account=deployer@demo-shop.iam.gserviceaccount.com --managed-by=user " + shop + " " + owner: {{stdout: "sa_keys_deployer.json"}},
		"iam service-accounts keys list --iam-account=reader@demo-shop.iam.gserviceaccount.com --managed-by=user " + shop + " " + owner:   {{}},
		"services api-keys list " + shop + " " + owner: {{stdout: "api_keys_shop.json"}},
		"billing projects describe demo-shop " + owner: {{stdout: "billing_info_shop.json"}},

		"projects get-iam-policy demo-blog " + owner:      {{}},
		"iam service-accounts list " + blog + " " + owner: {{}},
		"services api-keys list " + blog + " " + owner:    {{stderr: "denied_apikeys.txt"}},
		"billing projects describe demo-blog " + owner:    {{stderr: "rate_limited.txt"}, {stdout: "billing_info_blog.json"}},

		"billing budgets list --billing-account=000000-AAAAAA-111111 " + owner: {{stdout: "budgets_main.json"}},
		"billing budgets list --billing-account=000000-BBBBBB-222222 " + owner: {{stderr: "budgets_denied.txt"}},
	}
}

func TestInventoryEndToEndWithRecordedGcloud(t *testing.T) {
	home := fakeHome(t)
	env := map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": filepath.Join(home, "keys", "sa.json")}
	c, runner := testConnector(t, home, fullScenario(), env)
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Protocol: 1}, rec); err != nil {
		t.Fatal(err)
	}

	want := map[string]finding.Severity{
		// local
		"Refresh token for a Google user on disk (ADC)":                                                                       finding.SevMedium,
		"Service account private key for ci@demo-shop.iam.gserviceaccount.com on disk (gcloud config folder)":                 finding.SevHigh,
		"Service account private key for deployer@demo-shop.iam.gserviceaccount.com on disk (GOOGLE_APPLICATION_CREDENTIALS)": finding.SevHigh,
		// broad roles
		"deployer@demo-shop.iam.gserviceaccount.com is editor and owner of project demo-shop": finding.SevHigh,
		"100000000001-compute@developer.gserviceaccount.com is editor of project demo-shop":   finding.SevHigh,
		"service-runner@demo-shop.iam.gserviceaccount.com is editor of project demo-shop":     finding.SevHigh,
		// service account keys
		"deployer@demo-shop.iam.gserviceaccount.com has a user-managed key 317 days old": finding.SevHigh,
		"deployer@demo-shop.iam.gserviceaccount.com has a user-managed key":              finding.SevMedium,
		"deployer@demo-shop.iam.gserviceaccount.com has a disabled user-managed key":     finding.SevLow,
		// API keys
		`"Maps (browser)" in demo-shop has no API restrictions and no application restrictions`: finding.SevHigh,
		`"Server geocoding" in demo-shop has no application restrictions`:                       finding.SevHigh,
		`"Android app" in demo-shop is restricted`:                                              finding.SevInfo,
		// billing
		"Billing account 000000-AAAAAA-111111 has 2 budgets: 'Blog only' 20 EUR/month, demo-blog; 'Silent' 100 EUR/month, all projects":                                                                                                 finding.SevInfo,
		"Budget 'Blog only' (20 EUR/month, demo-blog) has no forecasted threshold: add one at 100% to hear before the money is spent":                                                                                                   finding.SevLow,
		"Budgets on billing account 000000-AAAAAA-111111 only notify: none is wired to a Pub/Sub topic or a spend cap, so nothing stops spend; 2 unrestricted API keys and 2 user-managed service account keys in projects billed here": finding.SevMedium,
		"Budget 'Blog only' (20 EUR/month, demo-blog) leaves out demo-shop (2 unrestricted API keys and 2 user-managed service account keys)":                                                                                           finding.SevLow,
		"Project demo-shop is billed to billing account 000000-AAAAAA-111111 but no budget with alerts covers it":                                                                                                                       finding.SevHigh,
		// the projects each account sees, for attribution
		"owner@example.com sees 3 projects": finding.SevInfo,
	}
	if len(rec.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d:\n%s", len(rec.Findings), len(want), rec.titles())
	}
	for title, sev := range want {
		if f := rec.byTitle(t, title); f.Severity != sev {
			t.Errorf("%q: severity %s, want %s", title, f.Severity, sev)
		}
	}

	seen := rec.byTitle(t, "owner@example.com sees")
	if ps, _ := seen.Evidence["projects"].([]any); len(ps) != 3 || ps[0].(map[string]any)["number"] != "100000000001" || ps[0].(map[string]any)["id"] != "demo-shop" {
		t.Errorf("projects record: %+v", seen.Evidence)
	}
	key := rec.byTitle(t, "Maps (browser)")
	if key.Resource.ID != finding.Redact("11111111-2222-3333-4444-555555555555") || key.Resource.Name != "Maps (browser)" {
		t.Errorf("API key must show display name and redacted uid: %+v", key.Resource)
	}
	if key.CreatedAt == nil || key.CreatedAt.Format("2006-01-02") != "2026-01-22" {
		t.Errorf("API key created date: %v", key.CreatedAt)
	}
	old := rec.byTitle(t, "317 days old")
	if old.Evidence["valid_after_time"] != "2026-01-10T08:00:00Z" || old.Kind != finding.KindCredential {
		t.Errorf("old key evidence: %+v", old.Evidence)
	}
	adc := rec.byTitle(t, "(ADC)")
	if adc.Kind != finding.KindExposure || adc.Evidence["gcloud_default_client"] != true || adc.Evidence["quota_project_id"] != "demo-shop" {
		t.Errorf("ADC evidence: %+v", adc.Evidence)
	}
	for _, s := range []string{"myaccount.google.com/connections", "gcloud auth application-default revoke", "--client-id-file", "auth/drive.file", "auth/spreadsheets"} {
		if !strings.Contains(adc.Remediation.Summary+adc.Remediation.URL, s) {
			t.Errorf("ADC remediation lacks %q", s)
		}
	}
	if b := rec.byTitle(t, "no budget with alerts covers it"); b.Kind != finding.KindSpend {
		t.Errorf("budget finding kind %s", b.Kind)
	}

	for _, secret := range []string{"SYNTHETIC-NOT-A-KEY", "SYNTHETIC-refresh-token", "SYNTHETIC-client-secret", "11111111-2222-3333-4444-555555555555"} {
		rec.AssertNoSecret(t, secret)
	}

	statuses := map[string]finding.State{}
	for _, s := range rec.Statuses {
		statuses[s.Account+" | "+s.Detail] = s.State
	}
	wantStatus := []struct {
		account, detail string
		state           finding.State
	}{
		{"owner@example.com", "3 project(s) visible", finding.StateOK},
		{"work@example.org", "projects list: credentials expired", finding.StateReauth},
		{"owner@example.com", "project demo-blog: permission denied for api keys", finding.StateError},
		{"owner@example.com", "billing account 000000-BBBBBB-222222: cannot read budgets, so spend alerts are unknown for demo-blog: permission denied", finding.StateError},
	}
	for _, w := range wantStatus {
		found := false
		for k, st := range statuses {
			if strings.HasPrefix(k, w.account+" | "+w.detail) && st == w.state {
				found = true
			}
		}
		if !found {
			t.Errorf("missing status %s %q (%s); got %v", w.account, w.detail, w.state, statuses)
		}
	}
	if len(rec.Statuses) != len(wantStatus) {
		t.Errorf("got %d statuses, want %d: %v", len(rec.Statuses), len(wantStatus), statuses)
	}
	for k := range statuses {
		if strings.Contains(k, "Help Token") || strings.Contains(k, "authenticated as") {
			t.Errorf("status detail not summarized: %s", k)
		}
	}

	// Permission denied on demo-blog leaves only demo-blog's findings unresolved.
	var tally finding.Tally
	for _, s := range rec.Statuses {
		tally.Status(s)
	}
	end := tally.End(connectorName, "", time.Now(), time.Now(), nil)
	cov := finding.CoverageOf(&end)
	if key.Scope != "demo-shop" || adc.Scope != "" {
		t.Errorf("scopes: project finding %q, local finding %q", key.Scope, adc.Scope)
	}
	if b := rec.byTitle(t, "no budget with alerts covers it"); b.Scope != "billing:000000-AAAAAA-111111" {
		t.Errorf("billing finding scope %q", b.Scope)
	}
	for _, c := range []struct {
		f         finding.Finding
		unchecked bool
	}{
		{key, false},
		{adc, false},
		{finding.Finding{Account: "owner@example.com", Scope: "demo-blog"}, true},
		{finding.Finding{Account: "owner@example.com", Scope: "billing:000000-BBBBBB-222222"}, true},
		{finding.Finding{Account: "work@example.org", Scope: "any-project"}, true}, // reauth: the whole account
		{rec.byTitle(t, "has 2 budgets"), false},                                   // ci@ is a service account: not used, so no billing:* failure
	} {
		if _, got := cov.UncheckedFinding(c.f); got != c.unchecked {
			t.Errorf("%s %s: unchecked %v, want %v", c.f.Account, finding.ScopeOf(c.f), got, c.unchecked)
		}
	}

	for _, call := range runner.calls {
		if readOnly.Check(strings.Fields(call)) != nil {
			t.Errorf("non read-only call reached gcloud: %s", call)
		}
		if strings.Contains(call, "demo-old") {
			t.Errorf("project pending deletion inspected: %s", call)
		}
	}
	for key, rest := range runner.plays {
		if len(rest) > 1 {
			t.Errorf("recorded answers left unused for %s", key)
		}
	}
}

func TestConfiguredAccountsProjectsAndBillingProject(t *testing.T) {
	plays := map[string][]outcome{
		"auth list":                                                     {{stdout: "auth_list.json"}},
		"projects list " + owner:                                        {{stdout: "projects_owner.json"}},
		"billing accounts list " + owner:                                {{}},
		"projects get-iam-policy demo-blog " + owner:                    {{}},
		"iam service-accounts list --project=demo-blog " + owner:        {{}},
		"services api-keys list --project=demo-blog " + owner:           {{}},
		"billing projects describe demo-blog " + owner:                  {{stdout: "billing_info_blog.json"}},
		"projects get-iam-policy unlisted-project " + owner:             {{}},
		"iam service-accounts list --project=unlisted-project " + owner: {{}},
		"services api-keys list --project=unlisted-project " + owner:    {{}},
		"billing projects describe unlisted-project " + owner:           {{}},
		"billing budgets list --billing-account=000000-BBBBBB-222222 " + owner + " --billing-project=demo-quota": {{}},
	}
	c, _ := testConnector(t, t.TempDir(), plays, nil)
	rec := &recorder{}
	cfg := map[string]any{"accounts": []any{"owner@example.com"}, "projects": []any{"demo-blog", "unlisted-project"}, "billing_project": "demo-quota"}
	if err := c.Inventory(context.Background(), connector.Request{Protocol: 1, Config: cfg}, rec); err != nil {
		t.Fatal(err)
	}
	f := rec.byTitle(t, "Billing account 000000-BBBBBB-222222 has no budget with alerts")
	if f.Severity != finding.SevHigh || f.Kind != finding.KindSpend {
		t.Errorf("budgetless billing account: %+v", f)
	}
	if got := f.Evidence["units"]; len(got.([]string)) != 1 || got.([]string)[0] != "demo-blog" {
		t.Errorf("linked projects: %v", got)
	}
	// The person's account the config leaves out is declared skipped; the service account is not.
	if want := []finding.Skipped{{Scope: "work@example.org", Reason: "not in connectors.gcp.config.accounts"}}; !slices.Equal(rec.Skipped(), want) {
		t.Errorf("skipped %v, want the unwatched work@example.org only", rec.Skipped())
	}
}

func TestAnotherAccountCoversWhatTheFirstIsDeniedAndSkippedProjectsAreLeftOut(t *testing.T) {
	shop := "--project=demo-shop"
	plays := map[string][]outcome{
		"auth list":                      {{stdout: "auth_list.json"}},
		"projects list " + owner:         {{stdout: "projects_owner.json"}},
		"projects list " + work:          {{stdout: "projects_owner.json"}},
		"billing accounts list " + owner: {{}},
		"billing accounts list " + work:  {{}},

		"projects get-iam-policy demo-shop " + owner:      {{stderr: "denied_apikeys.txt"}},
		"projects get-iam-policy demo-shop " + work:       {{}},
		"iam service-accounts list " + shop + " " + owner: {{stderr: "denied_apikeys.txt"}},
		"iam service-accounts list " + shop + " " + work:  {{}},
		"services api-keys list " + shop + " " + owner:    {{stderr: "denied_apikeys.txt"}},
		"services api-keys list " + shop + " " + work:     {{stderr: "denied_apikeys.txt"}},
		"billing projects describe demo-shop " + owner:    {{}},
	}
	c, runner := testConnector(t, t.TempDir(), plays, nil)
	rec := &recorder{}
	cfg := map[string]any{"skip_projects": []any{"demo-blog"}}
	if err := c.Inventory(context.Background(), connector.Request{Protocol: 1, Config: cfg}, rec); err != nil {
		t.Fatal(err)
	}
	var projectStatuses []string
	for _, s := range rec.Statuses {
		if strings.HasPrefix(s.Detail, "project ") {
			projectStatuses = append(projectStatuses, s.Account+" | "+s.Detail)
		}
	}
	want := "owner@example.com | project demo-shop: permission denied for api keys (to every account that lists it: owner@example.com, work@example.org)"
	if len(projectStatuses) != 1 || projectStatuses[0] != want {
		t.Fatalf("project statuses %q, want only %q", projectStatuses, want)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "demo-blog") || strings.Contains(call, "iam.gserviceaccount.com") {
			t.Errorf("skipped project or service account used: %s", call)
		}
	}
	// The skipped project is declared, so findings earlier runs made there are not taken as
	// resolved. The service account is not: nothing is scoped to it, and declaring it would mark
	// every run partial.
	if want := []finding.Skipped{{Scope: "demo-blog", Reason: "in connectors.gcp.config.skip_projects"}}; !slices.Equal(rec.Skipped(), want) {
		t.Errorf("skipped scopes %v", rec.Skipped())
	}
}

func TestServiceAccountListedInConfigIsUsed(t *testing.T) {
	plays := map[string][]outcome{
		"auth list":                                           {{stderr: "reauth.txt"}}, // the configured accounts run all the same
		"projects list " + ci:                                 {{stdout: "projects_sa.json"}},
		"billing accounts list " + ci:                         {{stderr: "disabled_billing.txt"}},
		"projects get-iam-policy demo-shop " + ci:             {{}},
		"iam service-accounts list --project=demo-shop " + ci: {{}},
		"services api-keys list --project=demo-shop " + ci:    {{}},
		"billing projects describe demo-shop " + ci:           {{}},
	}
	c, _ := testConnector(t, t.TempDir(), plays, nil)
	rec := &recorder{}
	cfg := map[string]any{"accounts": []any{"ci@demo-shop.iam.gserviceaccount.com"}}
	if err := c.Inventory(context.Background(), connector.Request{Protocol: 1, Config: cfg}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Statuses) == 0 || rec.Statuses[0].Account != "ci@demo-shop.iam.gserviceaccount.com" || rec.Statuses[0].State != finding.StateOK {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
}

func TestBadConfigFailsToStart(t *testing.T) {
	c, _ := testConnector(t, t.TempDir(), nil, nil)
	err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"projects": "demo"}}, &recorder{})
	if err == nil {
		t.Fatal("a non-list projects setting must be rejected")
	}
}

func TestReadOnlyGuard(t *testing.T) {
	for _, ok := range []string{
		"auth list", "projects list --account=a", "projects get-iam-policy p --account=a",
		"iam service-accounts keys list --iam-account=x --managed-by=user", "billing budgets list --billing-account=b",
	} {
		if readOnly.Check(strings.Fields(ok)) != nil {
			t.Errorf("read-only command refused: %s", ok)
		}
	}
	for _, bad := range []string{
		"services api-keys get-key-string k", "services api-keys delete k", "iam service-accounts keys create f --iam-account=x",
		"config set account a", "services disable x", "auth application-default print-access-token", "auth revoke a",
		"projects delete p", "billing budgets create", "--account a projects list",
	} {
		if readOnly.Check(strings.Fields(bad)) == nil {
			t.Errorf("mutating or secret-revealing command allowed: %s", bad)
		}
	}
	g := &gcloud{run: &fakeRunner{t: t}}
	if err := g.json(context.Background(), &[]any{}, "services", "api-keys", "get-key-string", "k"); !errors.Is(err, cli.ErrRefused) {
		t.Fatalf("guard must refuse before running: %v", err)
	}
}

func TestRateLimitGivesUpAfterRetries(t *testing.T) {
	r := &fakeRunner{t: t, plays: map[string][]outcome{"billing accounts list": {{stderr: "rate_limited.txt"}}}}
	err := (&gcloud{run: r}).json(context.Background(), &[]any{}, "billing", "accounts", "list")
	if err == nil || len(r.calls) != attempts {
		t.Fatalf("err=%v calls=%d", err, len(r.calls))
	}
	if state, why := classify(err); state != finding.StateError || !strings.HasPrefix(why, "rate limited") {
		t.Errorf("classify: %s %s", state, why)
	}
}

func TestClassify(t *testing.T) {
	for stderr, want := range map[string]string{
		"ERROR: (gcloud.projects.list) Reauthentication failed. cannot prompt during non-interactive execution.": "credentials expired",
		"ERROR: (gcloud.services.api-keys.list) PERMISSION_DENIED: Permission denied on resource project p.":     deniedPrefix,
		"ERROR: (gcloud.billing.budgets.list) HttpError accessing <https://x>: response: <{'status': '403'}>":    deniedPrefix,
		"ERROR: (gcloud.projects.get-iam-policy) NOT_FOUND: project 1403777 was not found.":                      "NOT_FOUND",
		"ERROR: (gcloud.services.api-keys.list) SERVICE_DISABLED: API has not been used in project 4030.":        "API not enabled",
	} {
		_, why := classify(&cli.Error{Stderr: stderr, Err: errors.New("exit status 1")})
		if !strings.HasPrefix(why, want) {
			t.Errorf("%q: got %q, want prefix %q", stderr, why, want)
		}
	}
}

func TestGoogleManagedServiceAgentsAreSkipped(t *testing.T) {
	for email, managed := range map[string]bool{
		"123@cloudservices.gserviceaccount.com":                   true,
		"appsdev-apps-dev-script-auth@system.gserviceaccount.com": true,
		"service-123@gcp-sa-pubsub.iam.gserviceaccount.com":       true,
		"service-123@compute-system.iam.gserviceaccount.com":      true,
		"service-runner@demo.iam.gserviceaccount.com":             false,
		"123-compute@developer.gserviceaccount.com":               false,
		"demo@appspot.gserviceaccount.com":                        false,
		"firebase-adminsdk-x1@demo.iam.gserviceaccount.com":       false,
	} {
		if googleManaged(email) != managed {
			t.Errorf("googleManaged(%s) = %v", email, !managed)
		}
	}
}

func TestBudgetMapping(t *testing.T) {
	var bs []gcpBudget
	if err := json.Unmarshal([]byte(fixture(t, "budgets_quality.json")), &bs); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{"100000000001": "demo-shop"}
	got := make([]budget.Budget, len(bs))
	for i, b := range bs {
		got[i] = b.neutral("EUR", ids)
	}
	want := []budget.Budget{
		{ID: "q-1", Name: "Team total", Amount: 110, Currency: "EUR", Period: budget.PeriodMonth,
			Thresholds: []budget.Threshold{{Percent: 50}}, Notifies: []string{budget.NotifyAdmins}},
		{ID: "q-2", Name: "Auto map budget", Amount: 75.5, Currency: "EUR", Period: budget.PeriodQuarter,
			Thresholds: []budget.Threshold{{Percent: 100}, {Percent: 100, Forecast: true}},
			Scope: budget.Scope{Units: []string{"demo-shop"}, Filters: []string{"3 services"},
				Detail: "services/AAAA-BBBB,services/CCCC-DDDD,services/EEEE-FFFF"},
			Notifies: []string{budget.NotifyProject, budget.NotifyMonitoring}},
		{ID: "q-3", Name: "Follows last month", Currency: "EUR", Period: budget.PeriodMonth, LastPeriod: true,
			Thresholds: []budget.Threshold{{Percent: 100}},
			Scope:      budget.Scope{Filters: []string{"folders/123", "label env=[prod]"}},
			Notifies:   []string{budget.NotifyAdmins, budget.NotifyPubSub}, Actions: []string{budget.ActionPubSub}},
		{ID: "q-4", Name: "Capped", Amount: 30, Currency: "EUR", Period: budget.PeriodCustom,
			Thresholds: []budget.Threshold{{Percent: 100}}, Scope: budget.Scope{Units: []string{"unknown-project"}},
			Notifies: []string{budget.NotifyAdmins, budget.NotifyProject}, Actions: []string{budget.ActionSpendCap}},
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("budget %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

func TestProjectRisks(t *testing.T) {
	fs := []finding.Finding{
		{Resource: finding.Resource{Type: "api_key"}, Severity: finding.SevHigh},
		{Resource: finding.Resource{Type: "api_key"}, Severity: finding.SevInfo},
		{Resource: finding.Resource{Type: "service_account_key"}, Severity: finding.SevMedium},
		{Resource: finding.Resource{Type: "service_account_key"}, Severity: finding.SevLow}, // disabled
	}
	want := []budget.Risk{{Unit: "p", What: "unrestricted API key", Count: 1}, {Unit: "p", What: "user-managed service account key", Count: 1}}
	if got := projectRisks("p", fs); !reflect.DeepEqual(got, want) {
		t.Errorf("risks %+v", got)
	}
}

func TestLocalCredentialPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	home := fakeHome(t)
	adc := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	if err := os.Chmod(adc, 0o644); err != nil {
		t.Fatal(err)
	}
	fs := localFindings(func(string) string { return "" }, home)
	var got *finding.Finding
	for i := range fs {
		if fs[i].Resource.ID == adc {
			got = &fs[i]
		}
	}
	if got == nil || got.Severity != finding.SevHigh || got.Evidence["mode"] != "0644" ||
		!strings.HasSuffix(got.Title, "readable by other users") || !strings.Contains(got.Remediation.Summary, "chmod 600") {
		t.Fatalf("world-readable ADC must be high with chmod advice: %+v", got)
	}
	if len(fs) != 2 {
		t.Errorf("want ADC and the legacy service account key, virtenv skipped; got %d", len(fs))
	}
}

func TestLocalCredentialsHonourCloudsdkConfig(t *testing.T) {
	home := fakeHome(t)
	other := t.TempDir()
	fs := localFindings(func(k string) string {
		if k == "CLOUDSDK_CONFIG" {
			return other
		}
		return ""
	}, home)
	if len(fs) != 0 {
		t.Fatalf("CLOUDSDK_CONFIG points to an empty folder, got %d findings", len(fs))
	}
}

func TestParseSettingsGcloudPath(t *testing.T) {
	s, err := parseSettings(map[string]any{"gcloud_path": "/configured/gcloud"})
	if err != nil || s.gcloudPath != "/configured/gcloud" {
		t.Fatalf("gcloud_path: %q %v", s.gcloudPath, err)
	}
}
