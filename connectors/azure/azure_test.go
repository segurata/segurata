package azure

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// fakeRunner answers by command (the args before the common output flags) and records every call.
type fakeRunner struct {
	replies map[string]string
	errs    map[string]error
	calls   []string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	cmd := strings.TrimSuffix(strings.Join(args, " "), " --output json --only-show-errors")
	f.calls = append(f.calls, cmd)
	if err, ok := f.errs[cmd]; ok {
		return nil, err
	}
	if out, ok := f.replies[cmd]; ok {
		return []byte(out), nil
	}
	return nil, fmt.Errorf("az %s: unexpected command", cmd)
}

const appQuery = "ad app list --all --query [].{appId:appId,displayName:displayName,passwordCredentials:passwordCredentials}"

func fixture() *fakeRunner {
	return &fakeRunner{replies: map[string]string{
		"account show": `{"id":"00000000-0000-0000-0000-000000000001","name":"Example","state":"Enabled","tenantId":"00000000-0000-0000-0000-0000000000aa","tenantDefaultDomain":"example.onmicrosoft.com"}`,
		"account list": `[
			{"id":"00000000-0000-0000-0000-000000000001","name":"Example","state":"Enabled"},
			{"id":"00000000-0000-0000-0000-000000000002","name":"Old","state":"Disabled"},
			{"id":"00000000-0000-0000-0000-000000000003","name":"Watched","state":"Enabled"}]`,
		"consumption budget list --subscription 00000000-0000-0000-0000-000000000001": `[]`,
		"consumption budget list --subscription 00000000-0000-0000-0000-000000000003": `[{"name":"monthly","amount":50,"timeGrain":"Monthly","notifications":{"a":{"enabled":true},"b":{"enabled":false}}}]`,
		appQuery: `[{"appId":"11111111-1111-1111-1111-111111111111","displayName":"ci","passwordCredentials":[
			{"keyId":"k1","hint":"abc","endDateTime":"2299-12-31T00:00:00Z","startDateTime":"2024-01-01T00:00:00Z"},
			{"keyId":"k2","hint":"def","endDateTime":"2026-12-01T00:00:00.123Z"}]}]`,
	}}
}

func TestInventory(t *testing.T) {
	rec := &httpxtest.Recorder{}
	c := &Connector{Run: fixture(), Now: func() time.Time { return now }}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	got := map[string]finding.Severity{}
	for _, f := range rec.Findings {
		got[f.Resource.ID] = f.Severity
	}
	want := map[string]finding.Severity{
		"00000000-0000-0000-0000-000000000001/none":    finding.SevHigh,
		"00000000-0000-0000-0000-000000000003/monthly": finding.SevInfo,
		"11111111-1111-1111-1111-111111111111/k1":      finding.SevHigh,
		"11111111-1111-1111-1111-111111111111/k2":      finding.SevMedium,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	if len(rec.Statuses) != 3 { // two enabled subscriptions and the tenant
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
	for _, f := range rec.Findings {
		if f.Resource.Type == "azure_app_secret" && f.Account != "example.onmicrosoft.com" {
			t.Fatalf("app secrets belong to the tenant: %+v", f)
		}
		// Graph's hint (the first characters) in secretrisk.Redact's format, length unknown.
		if f.Resource.ID == "11111111-1111-1111-1111-111111111111/k1" && f.Evidence["hint"] != "abc…(?)" {
			t.Errorf("hint %v", f.Evidence["hint"])
		}
	}
}

func TestInventoryTurnsFailuresIntoStatuses(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want finding.State
	}{
		{"cli missing", fmt.Errorf("az: %w", exec.ErrNotFound), finding.StateUnsupported},
		{"signed out", errors.New("ERROR: Please run 'az login' to setup account."), finding.StateSignedOut},
		{"token expired", errors.New("AADSTS700082: The refresh token has expired due to inactivity."), finding.StateReauth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &httpxtest.Recorder{}
			fr := &fakeRunner{errs: map[string]error{"account show": tc.err}}
			if err := (&Connector{Run: fr, Now: time.Now}).Inventory(context.Background(), connector.Request{}, rec); err != nil {
				t.Fatal(err)
			}
			if len(rec.Statuses) != 1 || rec.Statuses[0].State != tc.want {
				t.Fatalf("statuses: %+v", rec.Statuses)
			}
		})
	}
}

func TestBudgetErrorIsPerSubscription(t *testing.T) {
	fr := fixture()
	fr.errs = map[string]error{"consumption budget list --subscription 00000000-0000-0000-0000-000000000001": errors.New("(422) Cost management data is unavailable for this offer")}
	rec := &httpxtest.Recorder{}
	if err := (&Connector{Run: fr, Now: func() time.Time { return now }}).Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	if rec.Statuses[0].State != finding.StateError || !strings.HasPrefix(rec.Statuses[0].Detail, "budgets:") {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
	if len(rec.Findings) != 3 {
		t.Fatalf("the other subscription and the apps should still be inspected: %+v", rec.Findings)
	}
}

func TestSecretFinding(t *testing.T) {
	at := func(d time.Duration) *time.Time { x := now.Add(d); return &x }
	day := 24 * time.Hour
	date := func(t *time.Time) string { return t.UTC().Format(time.DateOnly) }
	cases := []struct {
		name  string
		end   *time.Time
		want  finding.Severity
		title string
	}{
		{"no end date", nil, finding.SevHigh, `Client secret of app "ci" has no expiry date`},
		{"far future", at(3 * 365 * day), finding.SevHigh, `Client secret of app "ci" never expires in practice (expires ` + date(at(3*365*day)) + ")"},
		{"healthy", at(200 * day), finding.SevInfo, `Client secret of app "ci" expires ` + date(at(200*day))},
		{"expiring", at(10 * day), finding.SevMedium, `Client secret of app "ci" expires ` + date(at(10*day)) + ", in 10 days"},
		{"expired", at(-day), finding.SevLow, `Client secret of app "ci" expired on ` + date(at(-day)) + " and is still registered"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := secretFinding(app{AppID: "a", DisplayName: "ci"}, passwordCredential{KeyID: "k", Hint: "abc", EndDateTime: tc.end}, now)
			if f.Severity != tc.want || f.Title != tc.title {
				t.Fatalf("got %s %q, want %s %q", f.Severity, f.Title, tc.want, tc.title)
			}
		})
	}
}

func TestBudgetWithoutEnabledAlerts(t *testing.T) {
	b := budget{Name: "quiet", Notifications: map[string]struct {
		Enabled bool `json:"enabled"`
	}{"x": {Enabled: false}}}
	if f := budgetFindings("s", []budget{b}); f[0].Severity != finding.SevMedium {
		t.Fatalf("got %+v", f)
	}
}

func TestEveryCommandRunIsReadOnly(t *testing.T) {
	fr := fixture()
	if err := (&Connector{Run: fr, Now: func() time.Time { return now }}).Inventory(context.Background(), connector.Request{}, &httpxtest.Recorder{}); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 5 { // account show, account list, two enabled subscriptions, app list
		t.Fatalf("calls: %v", fr.calls)
	}
	for _, call := range fr.calls {
		if err := readOnly.Check(strings.Fields(call)); err != nil {
			t.Errorf("call outside the allowlist: %v", err)
		}
	}
}

func TestMutatingCommandIsRefusedBeforeTheCLI(t *testing.T) {
	for _, args := range [][]string{
		{"ad", "app", "credential", "reset", "--id", "11111111-1111-1111-1111-111111111111"},
		{"ad", "app", "delete", "--id", "x"},
		{"account", "set", "--subscription", "x"},
		{"consumption", "budget", "delete", "--budget-name", "monthly"},
	} {
		fr := &fakeRunner{}
		err := (&Connector{Run: fr, Now: time.Now}).call(context.Background(), &struct{}{}, args...)
		if !errors.Is(err, cli.ErrRefused) {
			t.Errorf("%v: want refusal, got %v", args, err)
		}
		if len(fr.calls) != 0 {
			t.Errorf("%v reached the CLI", args)
		}
	}
}
