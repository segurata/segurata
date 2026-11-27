package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

type recordingExec struct {
	ran    []string
	stdout string // printed by every step, as gcloud --format=value(name) would
}

func (r *recordingExec) Run(_ context.Context, s connector.Step, io connector.IO) error {
	r.ran = append(r.ran, s.String())
	_, _ = io.Out.Write([]byte(r.stdout))
	return nil
}

func quietIO() (connector.IO, *bytes.Buffer) {
	var out bytes.Buffer
	return connector.IO{In: strings.NewReader(""), Out: &out, Err: &out}, &out
}

// remediator resolves the connector's remediation the way the core does, with cfg as its config.
func remediatorFor(t *testing.T, c *Connector, f finding.Finding, cfg map[string]any) connector.Remediator {
	t.Helper()
	f.Connector = connectorName
	r, err := remediate.For(f, []connector.Connector{c}, func(finding.Finding) (connector.Credentials, error) {
		return connector.Credentials{Request: connector.Request{Config: cfg}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func jsonFixture(t *testing.T, name string, into any) error {
	t.Helper()
	return json.Unmarshal([]byte(fixture(t, name)), into)
}

func steps(p connector.Plan) (cmds, undo []string) {
	for _, s := range p.Commands {
		cmds = append(cmds, s.String())
	}
	for _, s := range p.Undo {
		undo = append(undo, s.String())
	}
	return cmds, undo
}

const keysList = "services api-keys list --project=demo-shop " + owner

// mapsKeyFinding is the inventory's finding for the "Maps (browser)" key of api_keys_shop.json.
func mapsKeyFinding(t *testing.T) finding.Finding {
	t.Helper()
	var keys []apiKey
	if err := jsonFixture(t, "api_keys_shop.json", &keys); err != nil {
		t.Fatal(err)
	}
	used := map[string]keyUsage{keys[0].uid(): {apis: []string{"maps-backend.googleapis.com"}}}
	f := apiKeyFindings("owner@example.com", "demo-shop", keys[:1], used)[0]
	if f.Remediation.Action != ActionRestrictKey {
		t.Fatalf("no restrict action: %+v", f.Remediation)
	}
	return f
}

func TestRestrictKeyPlansTheAPIsItUsedAndKeepsItsAppRestriction(t *testing.T) {
	c, runner := testConnector(t, t.TempDir(), map[string][]outcome{
		keysList:                           {{stdout: "api_keys_shop.json"}},
		"auth print-access-token " + owner: {{stdout: "access_token.txt"}},
	}, nil)
	srv := fakeGoogle(t, c, shopUsage(t))
	f := mapsKeyFinding(t)
	r := remediatorFor(t, c, f, nil)

	p, err := r.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gcloud services api-keys update 11111111-2222-3333-4444-555555555555 --location=global --project=demo-shop " +
		"--api-target=service=geocoding-backend.googleapis.com --api-target=service=maps-backend.googleapis.com --account=owner@example.com"}
	cmds, undo := steps(p)
	if !reflect.DeepEqual(cmds, want) || len(undo) != 0 || p.Action != ActionRestrictKey {
		t.Fatalf("plan\n got %v undo %v\nwant %v", cmds, undo, want)
	}
	effects := strings.Join(p.SideEffects, "\n")
	for _, w := range []string{"--check-existing-usage", "cannot be read from usage", "Don't restrict key", "more than 30 days ago"} {
		if !strings.Contains(effects, w) {
			t.Errorf("side effects lack %q:\n%s", w, effects)
		}
	}
	if !strings.Contains(p.Summary, "to the 2 APIs it called in the last 30 days") {
		t.Errorf("summary %q", p.Summary)
	}
	if got := srv.Hits[timeSeriesPath("demo-shop")]; got != 1 {
		t.Errorf("the plan reads usage afresh: %d reads", got)
	}

	ex := &recordingExec{}
	c.exec = ex
	io, out := quietIO()
	if err := r.Apply(context.Background(), f, p, io); err != nil || !reflect.DeepEqual(ex.ran, want) {
		t.Fatalf("apply: %v ran %v", err, ex.ran)
	}
	if strings.Contains(out.String()+strings.Join(cmds, " ")+effects, accessToken) {
		t.Error("the access token leaked into the plan or its output")
	}
	for _, call := range runner.calls {
		if readOnly.Check(strings.Fields(call)) != nil {
			t.Errorf("a plan ran a non read-only gcloud command: %s", call)
		}
	}

	// After the fix the key has API targets: the fresh finding no longer offers the action.
	var keys []apiKey
	_ = jsonFixture(t, "api_keys_shop.json", &keys)
	keys[0].Restrictions = &restrictions{APITargets: []struct {
		Service string `json:"service"`
	}{{Service: "maps-backend.googleapis.com"}}}
	if fresh := apiKeyFindings("owner@example.com", "demo-shop", keys[:1], nil)[0]; fresh.ID != f.ID || fresh.Remediation.Action != "" {
		t.Errorf("fixed key: %s %+v", fresh.ID, fresh.Remediation)
	}
}

func TestRestrictKeyRefusals(t *testing.T) {
	f := mapsKeyFinding(t)
	cases := []struct {
		name   string
		keys   string
		routes map[string]httpxtest.Route
		want   string
	}{
		{"unused", "api_keys_shop.json", map[string]httpxtest.Route{timeSeriesPath("demo-shop"): usageRoute(t, map[string][]string{
			"11111111-2222-3333-4444-555555555555": nil})}, "nothing to restrict it to"},
		{"monitoring unreadable", "api_keys_shop.json", map[string]httpxtest.Route{
			timeSeriesPath("demo-shop"): httpxtest.Fail(http.StatusForbidden, "Cloud Monitoring API has not been used in project demo-shop before or it is disabled.")},
			"Cloud Monitoring could not be read"},
		{"gone", "api_keys_restricted.json", nil, "no longer exists"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testConnector(t, t.TempDir(), map[string][]outcome{
				keysList:                           {{stdout: tc.keys}},
				"auth print-access-token " + owner: {{stdout: "access_token.txt"}},
			}, nil)
			fakeGoogle(t, c, tc.routes)
			_, err := remediatorFor(t, c, f, nil).Plan(context.Background(), f)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want refusal %q, got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), accessToken) {
				t.Fatal("the access token leaked into the refusal")
			}
		})
	}
}

// The core plans again after the confirmation and refuses a plan that changed since it was shown.
func TestRestrictKeyStalePlanIsRefused(t *testing.T) {
	c, _ := testConnector(t, t.TempDir(), map[string][]outcome{
		keysList:                           {{stdout: "api_keys_shop.json"}},
		"auth print-access-token " + owner: {{stdout: "access_token.txt"}},
	}, nil)
	calls := 0
	fakeGoogle(t, c, map[string]httpxtest.Route{timeSeriesPath("demo-shop"): func(url.Values) (int, any) {
		calls++
		services := []string{"maps-backend.googleapis.com"}
		if calls > 1 { // the key started calling another API between the plan and the confirmation
			services = append(services, "places.googleapis.com")
		}
		var series []any
		for _, s := range services {
			series = append(series, map[string]any{"resource": map[string]any{"labels": map[string]any{"service": s}}})
		}
		return http.StatusOK, map[string]any{"timeSeries": series}
	}})
	ex := &recordingExec{}
	c.exec = ex
	f := mapsKeyFinding(t)
	io, _ := quietIO()
	err := remediate.Execute(context.Background(), f, remediatorFor(t, c, f, nil), remediate.Options{Apply: true, Yes: true, IO: io}, nil)
	if err == nil || !strings.Contains(err.Error(), "the plan changed since it was shown") || len(ex.ran) != 0 {
		t.Fatalf("stale plan: %v ran %v", err, ex.ran)
	}
}

// The inventory's allowlist refuses every write a remediation makes; those run only as the exact
// steps of a confirmed plan.
func TestInventoryRefusesRemediationWrites(t *testing.T) {
	for _, w := range []string{
		"services api-keys update k --location=global --project=p --api-target=service=s --account=a",
		"quotas preferences create --service=s --quota-id=q --preferred-value=1 --project=p",
		"quotas preferences update id --service=s --quota-id=q --preferred-value=1 --project=p",
		"billing budgets create --billing-account=b --display-name=d --budget-amount=1",
		"billing budgets update billingAccounts/b/budgets/x --add-threshold-rule=percent=1.0",
		"billing budgets delete billingAccounts/b/budgets/x",
	} {
		args := strings.Fields(w)
		if err := readOnly.Check(args); !errors.Is(err, cli.ErrRefused) {
			t.Errorf("inventory allowlist lets through %q: %v", w, err)
		}
		g := &gcloud{run: &fakeRunner{t: t}}
		if err := g.json(context.Background(), &[]any{}, args...); !errors.Is(err, cli.ErrRefused) {
			t.Errorf("gcloud.json ran %q: %v", w, err)
		}
	}
	// And a confirmed plan's allowlist holds only its own exact steps.
	allow := connector.Allowlist{ActionRestrictKey: {{Argv: []string{"gcloud", "services", "api-keys", "update", "k", "--api-target=service=a"}}}}
	if err := allow.Check(ActionRestrictKey, connector.Step{Argv: []string{"gcloud", "services", "api-keys", "update", "k", "--api-target=service=b"}}); !errors.Is(err, connector.ErrRefused) {
		t.Errorf("a step outside the plan ran: %v", err)
	}
}

var shopTarget = target{accounts: []string{"owner@example.com"}, project: "demo-shop", number: "100000000001"}

func quotaPlays() map[string][]outcome {
	return map[string][]outcome{
		"services list --enabled --project=demo-shop " + owner: {{stdout: "services_shop.json"}},
		"auth print-access-token " + owner:                     {{stdout: "access_token.txt"}},
	}
}

// geocodingQuotaFinding is the inventory's finding for demo-shop's uncapped Geocoding API.
func geocodingQuotaFinding(t *testing.T, routes map[string]httpxtest.Route) (*Connector, finding.Finding) {
	t.Helper()
	c, _ := testConnector(t, t.TempDir(), quotaPlays(), nil)
	fakeGoogle(t, c, routes)
	g, err := c.gcloud(settings{})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	c.quotaInventory(context.Background(), g, shopTarget, rec)
	if len(rec.Statuses) > 0 {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
	f := rec.byTitle(t, "geocoding-backend.googleapis.com in demo-shop")
	f.Connector = connectorName
	f.Fill(time.Now())
	return c, f
}

var capConfig = map[string]any{"quota_caps": map[string]any{"geocoding-backend.googleapis.com": 4000.0}}

func TestCapQuotaCreatesAPreferenceAndUndoesToTheOldLimit(t *testing.T) {
	c, f := geocodingQuotaFinding(t, shopQuotaRoutes(t))
	r := remediatorFor(t, c, f, capConfig)
	p, err := r.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	cmds, undo := steps(p)
	want := []string{"gcloud quotas preferences create --service=geocoding-backend.googleapis.com --quota-id=RequestsPerDayPerProject " +
		"--preferred-value=4000 --project=demo-shop --preference-id=segurata-requestsperdayperproject --allow-high-percentage-quota-decrease --account=owner@example.com"}
	wantUndo := []string{"gcloud quotas preferences update segurata-requestsperdayperproject --service=geocoding-backend.googleapis.com " +
		"--quota-id=RequestsPerDayPerProject --preferred-value=-1 --project=demo-shop --account=owner@example.com"}
	if !reflect.DeepEqual(cmds, want) || !reflect.DeepEqual(undo, wantUndo) {
		t.Fatalf("plan\n got %v\n undo %v\nwant %v\n undo %v", cmds, undo, want, wantUndo)
	}
	if p.Summary != "Cap geocoding-backend.googleapis.com in demo-shop at 4000 requests per day: RequestsPerDayPerProject (now unlimited)." {
		t.Errorf("summary %q", p.Summary)
	}
	if effects := strings.Join(p.SideEffects, "\n"); !strings.Contains(effects, "cannot delete a quota preference") || !strings.Contains(effects, "midnight Pacific") {
		t.Errorf("side effects:\n%s", effects)
	}
	ex := &recordingExec{}
	c.exec = ex
	io, out := quietIO()
	if err := r.Apply(context.Background(), f, p, io); err != nil || !reflect.DeepEqual(ex.ran, want) {
		t.Fatalf("apply: %v ran %v", err, ex.ran)
	}
	if strings.Contains(out.String()+strings.Join(cmds, " "), accessToken) {
		t.Error("the access token leaked")
	}

	// Once Google holds the preference the quota is capped: the fresh finding has no action.
	capped := quotaLimit{id: "RequestsPerDayPerProject", interval: "day", value: "4000", pref: &quotaPreference{Name: "x/segurata-requestsperdayperproject"}}
	capped.pref.QuotaConfig.PreferredValue = "4000"
	fresh := quotaFindings(f.Account, "demo-shop", "100000000001", []serviceQuotas{{service: "geocoding-backend.googleapis.com", daily: true, limits: []quotaLimit{capped}}})[0]
	fresh.Connector = connectorName
	fresh.Fill(time.Now())
	if fresh.ID != f.ID || fresh.Remediation.Action != "" || fresh.Severity != finding.SevInfo {
		t.Errorf("capped quota: %s %s %+v", fresh.ID, fresh.Severity, fresh.Remediation)
	}
}

// An increase the owner asked for earlier is a preference too: the cap updates it, and the undo
// puts the raised value back.
func TestCapQuotaUpdatesAnIncreasePreference(t *testing.T) {
	routes := shopQuotaRoutes(t)
	routes[shopQuotas+"/quotaPreferences"] = httpxtest.Static(map[string]any{"quotaPreferences": []any{map[string]any{
		"name": "projects/100000000001/locations/global/quotaPreferences/raise-geocoding", "service": "geocoding-backend.googleapis.com",
		"quotaId": "RequestsPerDayPerProject", "quotaConfig": map[string]any{"preferredValue": "100000", "traceId": "t-1"}}}})
	c, f := geocodingQuotaFinding(t, routes)
	p, err := remediatorFor(t, c, f, capConfig).Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	cmds, undo := steps(p)
	if want := "gcloud quotas preferences update raise-geocoding --service=geocoding-backend.googleapis.com --quota-id=RequestsPerDayPerProject " +
		"--preferred-value=4000 --project=demo-shop --allow-high-percentage-quota-decrease --account=owner@example.com"; len(cmds) != 1 || cmds[0] != want {
		t.Fatalf("commands %v, want %s", cmds, want)
	}
	if len(undo) != 1 || !strings.Contains(undo[0], "update raise-geocoding") || !strings.Contains(undo[0], "--preferred-value=100000 ") {
		t.Fatalf("undo %v", undo)
	}
}

func TestCapQuotaRefusals(t *testing.T) {
	_, f := geocodingQuotaFinding(t, shopQuotaRoutes(t))
	low := shopQuotaRoutes(t)
	low[quotaInfosPath("geocoding-backend.googleapis.com")] = httpxtest.Static(map[string]any{"quotaInfos": []any{map[string]any{
		"quotaId": "RequestsPerDayPerProject", "metric": "geocoding-backend.googleapis.com/billable_requests", "refreshInterval": "day",
		"dimensionsInfos": []any{map[string]any{"dimensions": map[string]any{}, "details": map[string]any{"value": "1000"}}}}}})
	cases := []struct {
		name   string
		cfg    map[string]any
		routes map[string]httpxtest.Route
		want   string
	}{
		{"no cap configured", nil, shopQuotaRoutes(t), `set connectors.gcp.config.quota_caps."geocoding-backend.googleapis.com"`},
		{"cap for another API", map[string]any{"quota_caps": map[string]any{"maps-backend.googleapis.com": 10.0}}, shopQuotaRoutes(t), "segurata never guesses an amount"},
		{"limit already below", capConfig, low, "already at or below 4000"},
		{"quotas unreadable", capConfig, map[string]httpxtest.Route{}, "Cloud Quotas in demo-shop"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testConnector(t, t.TempDir(), quotaPlays(), nil)
			fakeGoogle(t, c, tc.routes)
			_, err := remediatorFor(t, c, f, tc.cfg).Plan(context.Background(), f)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("want refusal %q, got %v", tc.want, err)
			}
		})
	}
}

func TestUnreadableQuotasAreAStatusOfTheirOwnScope(t *testing.T) {
	c, _ := testConnector(t, t.TempDir(), quotaPlays(), nil)
	fakeGoogle(t, c, map[string]httpxtest.Route{
		shopQuotas + "/quotaPreferences": httpxtest.Fail(http.StatusForbidden, "Cloud Quotas API has not been used in project demo-shop before or it is disabled."),
	})
	g, _ := c.gcloud(settings{})
	rec := &recorder{}
	c.quotaInventory(context.Background(), g, shopTarget, rec)
	if len(rec.Findings) != 0 || len(rec.Statuses) != 1 || rec.Statuses[0].Scope != quotaScope("demo-shop") ||
		!strings.Contains(rec.Statuses[0].Detail, "API not enabled") {
		t.Fatalf("findings %v statuses %+v", rec.titles(), rec.Statuses)
	}
	rec.AssertNoSecret(t, accessToken)
}
