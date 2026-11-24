package googlepersonal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// fakeBrowser serves canned page values by URL and records what was opened.
type fakeBrowser struct {
	mu     sync.Mutex
	pages  map[string]any
	fail   map[string]error
	opened []string
}

func (b *fakeBrowser) load(_ context.Context, url, _ string, ready func(json.RawMessage) bool, _ int) (json.RawMessage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.opened = append(b.opened, url)
	if err := b.fail[url]; err != nil {
		return nil, err
	}
	v, ok := b.pages[url]
	if !ok {
		v = map[string]any{"mail": "", "text": "", "apps": []any{}}
	}
	raw, _ := json.Marshal(v)
	ready(raw) // exercised for coverage of the readiness predicates
	return raw, nil
}

type recorder struct {
	findings []finding.Finding
	statuses []finding.Status
	logs     []string
	skipped  []string
}

func (r *recorder) Finding(f finding.Finding) { r.findings = append(r.findings, f) }
func (r *recorder) Status(s finding.Status)   { r.statuses = append(r.statuses, s) }
func (r *recorder) Scope(id string, inspected bool, reason string) {
	if !inspected {
		r.skipped = append(r.skipped, id+": "+reason)
	}
}
func (r *recorder) Log(m string) { r.logs = append(r.logs, m) }

const base = "https://myaccount.google.com/u/0/linkedapps/"

func conns(mail, text string, apps ...appLink) map[string]any {
	return map[string]any{"mail": mail, "text": text, "apps": apps}
}

func page(text string, details ...string) map[string]any {
	return map[string]any{"text": text, "details": details}
}

var now = time.Date(2026, 11, 23, 21, 0, 0, 0, time.UTC)

func TestInventoryWalksAccountsUntilTheEmailRepeats(t *testing.T) {
	b := &fakeBrowser{pages: map[string]any{
		connectionsURL(0): conns("a@example.test", "Third-party apps",
			appLink{Name: "Acme Sync\nSign in with Google", Href: base + "overview/ACME?hl=en"},
			appLink{Name: "example.test", Href: base + "overview/EXAMPLE"},
		),
		base + "overview/ACME?hl=en": page(overviewENAccess, base+"details/X/oauth/1", base+"details/X/siwg/2"),
		base + "details/X/oauth/1":   page(detailENOAuth),
		base + "details/X/siwg/2":    page(detailENSignIn),
		base + "overview/EXAMPLE":    page(overviewENSignIn, base+"details/Y/siwg/3"),
		base + "details/Y/siwg/3":    page(strings.Replace(detailENSignIn, "May 15, 7:37 PM", "sometime", 1)),
		connectionsURL(1):            conns("b@example.test", reauthES),
		connectionsURL(2):            conns("a@example.test", "Third-party apps"), // fallback to the default account
		connectionsURL(3):            conns("never@example.test", "must not be reached"),
	}}
	rec := &recorder{}
	if err := inventory(context.Background(), b, rec, now, nil); err != nil {
		t.Fatal(err)
	}

	for _, u := range b.opened {
		if u == connectionsURL(3) {
			t.Fatal("kept going after the email repeated")
		}
	}
	if len(rec.findings) != 2 {
		t.Fatalf("%d findings, want 2", len(rec.findings))
	}

	acme := rec.findings[0]
	if acme.Account != "a@example.test" || acme.Kind != finding.KindGrant || acme.Severity != finding.SevHigh || acme.Blast != finding.BlastMailAndFiles {
		t.Errorf("acme: %+v", acme)
	}
	if acme.Resource != (finding.Resource{Type: "oauth_grant", ID: "ACME", Name: "Acme Sync"}) {
		t.Errorf("acme resource %+v", acme.Resource)
	}
	if acme.Title != "Acme Sync can read and send email from your Gmail" {
		t.Errorf("acme title %q", acme.Title)
	}
	if acme.CreatedAt == nil || !acme.CreatedAt.Equal(time.Date(2020, 3, 24, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("acme created_at %v, want the earliest details date", acme.CreatedAt)
	}
	if acme.LastUsedAt != nil {
		t.Error("last_used_at must stay nil: Google does not show it")
	}
	scopes := acme.Evidence["scopes"].([]string)
	if len(scopes) != 4 || scopes[3] != "Allow this application to run when you are not present" {
		t.Errorf("scopes should merge overview and details: %q", scopes)
	}
	if acme.Evidence["cross_account_protection"] != true || len(acme.Evidence["detail_urls"].([]string)) != 2 {
		t.Errorf("acme evidence %+v", acme.Evidence)
	}
	if acme.Remediation.URL != base+"overview/ACME?hl=en" || acme.Remediation.Automatable ||
		!strings.Contains(acme.Remediation.Summary, "also removes the app's Sign in with Google link") {
		t.Errorf("acme remediation %+v", acme.Remediation)
	}

	ex := rec.findings[1]
	if ex.Resource.Type != "sign_in_with_google_summary" || ex.Severity != finding.SevInfo || ex.Account != "a@example.test" {
		t.Errorf("sign-in summary: %+v", ex)
	}
	if ex.Title != "a@example.test is the Sign in with Google login for 1 app" || fmt.Sprint(ex.Evidence["services"]) != "[example.test]" {
		t.Errorf("sign-in summary %q %v", ex.Title, ex.Evidence)
	}
	if ex.Remediation.URL != connectionsURL(0) {
		t.Errorf("summary points to %q", ex.Remediation.URL)
	}
	if len(rec.logs) != 1 || !strings.Contains(rec.logs[0], `unparsed access date "sometime"`) {
		t.Errorf("logs %q", rec.logs)
	}

	wantStates := []finding.State{finding.StateOK, finding.StateReauth}
	if len(rec.statuses) != len(wantStates) {
		t.Fatalf("statuses %+v", rec.statuses)
	}
	for i, s := range rec.statuses {
		if s.State != wantStates[i] {
			t.Errorf("status %d = %+v, want %s", i, s, wantStates[i])
		}
	}
	if rec.statuses[1].Account != "b@example.test" {
		t.Errorf("reauth account %q", rec.statuses[1].Account)
	}
}

func TestInventoryReportsSignedOutBrowser(t *testing.T) {
	rec := &recorder{}
	if err := inventory(context.Background(), &fakeBrowser{}, rec, now, nil); err != nil {
		t.Fatal(err)
	}
	if len(rec.statuses) != 1 || rec.statuses[0].State != finding.StateSignedOut || len(rec.findings) != 0 {
		t.Fatalf("got %+v %+v", rec.statuses, rec.findings)
	}
}

func TestInventoryReportsUnreadableAppsAndKeepsTheRest(t *testing.T) {
	b := &fakeBrowser{
		pages: map[string]any{
			connectionsURL(0): conns("a@example.test", "",
				appLink{Name: "Broken", Href: base + "overview/BROKEN"},
				appLink{Name: "Walled", Href: base + "overview/WALLED"},
				appLink{Name: "example.test", Href: base + "overview/EXAMPLE"},
			),
			base + "overview/WALLED":  page(reauthEN),
			base + "overview/EXAMPLE": page(overviewENSignIn, base+"details/gone"),
		},
		fail: map[string]error{
			base + "overview/BROKEN": errors.New("target crashed"),
			base + "details/gone":    errors.New("timeout"),
			connectionsURL(1):        errors.New("connection closed"),
		},
	}
	rec := &recorder{}
	if err := inventory(context.Background(), b, rec, now, nil); err != nil {
		t.Fatal(err)
	}
	if len(rec.findings) != 1 || fmt.Sprint(rec.findings[0].Evidence["services"]) != "[example.test]" {
		t.Fatalf("findings %+v", rec.findings)
	}
	var details []string
	for _, s := range rec.statuses {
		details = append(details, string(s.State)+": "+s.Detail)
	}
	got := strings.Join(details, "\n")
	for _, want := range []string{"error: Broken: target crashed", "error: Walled: Google asked to verify", "ok: 1 linked apps, 2 unreadable", "error: connection closed"} {
		if !strings.Contains(got, want) {
			t.Errorf("statuses missing %q:\n%s", want, got)
		}
	}
	if len(rec.logs) != 1 || !strings.Contains(rec.logs[0], "details page: timeout") {
		t.Errorf("logs %q", rec.logs)
	}
}

func TestFindingIDIgnoresGoogleTokensAndSeparatesRepeatedNames(t *testing.T) {
	run := func(token string) []string {
		b := &fakeBrowser{pages: map[string]any{
			connectionsURL(0): conns("a@example.test", "",
				appLink{Name: "Acme Sync", Href: base + "overview/" + token + "1"},
				appLink{Name: "Acme Sync", Href: base + "overview/" + token + "2"},
				appLink{Name: "example.test", Href: base + "overview/" + token + "3"},
			),
			base + "overview/" + token + "1": page(overviewENAccess),
			base + "overview/" + token + "2": page(overviewENAccess),
			base + "overview/" + token + "3": page(overviewENSignIn),
		}}
		rec := &recorder{}
		inventory(context.Background(), b, rec, now, nil)
		var ids []string
		for _, f := range rec.findings {
			ids = append(ids, f.ID)
		}
		return ids
	}
	first, second := run("tokenA"), run("tokenB")
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("ids changed with Google's tokens: %v vs %v", first, second)
	}
	if len(first) != 3 || first[0] == first[1] || first[1] == first[2] {
		t.Fatalf("ids must be distinct: %v", first)
	}
}

func TestAccountsFilterSkipsOtherAccountsWithoutStatus(t *testing.T) {
	b := &fakeBrowser{pages: map[string]any{
		connectionsURL(0):   conns("me@example.test", "", appLink{Name: "example.test", Href: base + "overview/E"}),
		base + "overview/E": page(overviewENSignIn),
		connectionsURL(1):   conns("shared@example.test", reauthEN),
	}}
	only, err := accountFilter(map[string]any{"accounts": []any{"Me@example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	if err := inventory(context.Background(), b, rec, now, only); err != nil {
		t.Fatal(err)
	}
	if len(rec.statuses) != 1 || rec.statuses[0].Account != "me@example.test" {
		t.Fatalf("statuses %+v", rec.statuses)
	}
	if len(rec.skipped) != 1 || rec.skipped[0] != "shared@example.test: not in connectors.google-personal.config.accounts" {
		t.Fatalf("an account the config leaves out is a skipped scope: %q", rec.skipped)
	}
	if _, err := accountFilter(map[string]any{"accounts": "me@example.test"}); err == nil {
		t.Fatal("a non-list accounts setting must be rejected")
	}
}

func TestLoginDependencyNamesFinancialAndCloudServices(t *testing.T) {
	app := func(n string) finding.Finding { return finding.Finding{Resource: finding.Resource{Name: n}} }
	cases := []struct {
		apps     []string
		want     []string
		severity finding.Severity
	}{
		{[]string{"binance.com", "Bybit", "Spotify", "Wise", "Crowdcube", "Otherwise Ltd"}, []string{"binance.com", "Bybit", "Wise", "Crowdcube"}, finding.SevHigh},
		{[]string{"Amazon Web Services", "Cloudflare Dashboard", "Wefunder"}, []string{"Amazon Web Services", "Cloudflare Dashboard", "Wefunder"}, finding.SevMedium},
		{[]string{"Stripe", "Claude"}, []string{"Stripe"}, finding.SevHigh},
		{[]string{"Spotify", "Chess.com"}, nil, ""},
	}
	for _, tc := range cases {
		var apps []finding.Finding
		for _, n := range tc.apps {
			apps = append(apps, app(n))
		}
		f, ok := loginDependency("me@example.test", apps)
		if !ok {
			if tc.want != nil {
				t.Errorf("%v: no finding", tc.apps)
			}
			continue
		}
		if fmt.Sprint(f.Evidence["services"]) != fmt.Sprint(tc.want) || f.Severity != tc.severity || f.Blast != finding.BlastLogin {
			t.Errorf("%v: services %v severity %s", tc.apps, f.Evidence["services"], f.Severity)
		}
		want := fmt.Sprintf("Google account me@example.test is the login for %d financial/cloud services: use a passkey/security key and consider Advanced Protection", len(tc.want))
		if len(tc.want) == 1 {
			want = strings.Replace(want, "services", "service", 1)
		}
		if f.Title != want || f.Remediation.URL != urlPasskeys || !strings.Contains(f.Remediation.Summary, urlAdvancedProtection) {
			t.Errorf("finding %q %+v", f.Title, f.Remediation)
		}
	}
}

func TestOverviewID(t *testing.T) {
	cases := map[string]string{
		base + "overview/AbC-1_x":        "AbC-1_x",
		base + "overview/AbC?hl=es":      "AbC",
		base + "overview/AbC/extra#frag": "AbC",
		"https://elsewhere.test/":        "https://elsewhere.test/",
	}
	for in, want := range cases {
		if got := overviewID(in); got != want {
			t.Errorf("overviewID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegisteredAsBuiltin(t *testing.T) {
	for _, c := range connector.Builtins() {
		if d := c.Describe(); d.Name == "google-personal" {
			if len(d.Needs) != 1 || d.Needs[0] != "cdp" || d.Protocol != connector.ProtocolVersion {
				t.Fatalf("describe %+v", d)
			}
			return
		}
	}
	t.Fatal("google-personal not registered")
}

func TestInventoryFailsToStartWithoutBrowser(t *testing.T) {
	err := GooglePersonal{}.Inventory(context.Background(), connector.Request{CDPURL: "http://127.0.0.1:1"}, &recorder{})
	if err == nil {
		t.Fatal("expected an error when CDP is unreachable")
	}
}

func TestGcloudGrantIsADependencyNotARevocation(t *testing.T) {
	b := &fakeBrowser{pages: map[string]any{
		connectionsURL(0):   conns("a@example.test", "", appLink{Name: "Google Cloud SDK", Href: base + "overview/G"}),
		base + "overview/G": page(overviewENAccess),
	}}
	rec := &recorder{}
	if err := inventory(context.Background(), b, rec, now, nil); err != nil {
		t.Fatal(err)
	}
	f := rec.findings[0]
	if !strings.HasSuffix(f.Title, "(segurata depends on it)") || f.Evidence["dependency"] != "segurata depends on it" ||
		!strings.Contains(f.Remediation.Summary, "gcloud auth revoke") || strings.Contains(f.Remediation.Summary, "Remove all access") {
		t.Errorf("gcloud grant: %q %q", f.Title, f.Remediation.Summary)
	}
}

// A page that fails to load stops the walk before accounts whose address is unknown: the status
// leaves every scope uninspected, so none of their findings look resolved.
func TestUnreadableAccountPageLeavesEverythingUninspected(t *testing.T) {
	b := &fakeBrowser{pages: map[string]any{connectionsURL(0): conns("a@example.test", "Third-party apps")},
		fail: map[string]error{connectionsURL(1): errors.New("target closed")}}
	rec := &recorder{}
	if err := inventory(context.Background(), b, rec, now, nil); err != nil {
		t.Fatal(err)
	}
	last := rec.statuses[len(rec.statuses)-1]
	if last.Account != "authuser 1" || last.State != finding.StateError || last.Scope != finding.ScopeAll {
		t.Fatalf("status %+v", last)
	}
}
