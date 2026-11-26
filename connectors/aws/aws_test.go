package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/budget"
	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/statefile"
)

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func ago(d int) time.Time { return now.AddDate(0, 0, -d) }

func byType(r *httpxtest.Recorder, t string) []finding.Finding {
	var out []finding.Finding
	for _, f := range r.Findings {
		if f.Resource.Type == t {
			out = append(out, f)
		}
	}
	return out
}

// fakeRunner answers by command (the args before --profile) and records every call.
type fakeRunner struct {
	replies map[string]string
	errs    map[string]error
	calls   []string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	if i := strings.Index(cmd, " --profile "); i >= 0 {
		cmd = cmd[:i]
	}
	f.calls = append(f.calls, cmd)
	if err, ok := f.errs[cmd]; ok {
		return nil, err
	}
	if out, ok := f.replies[cmd]; ok {
		return []byte(out), nil
	}
	return nil, fmt.Errorf("aws %s: unexpected command", cmd)
}

func newTest(fr *fakeRunner, credFile string) *Connector {
	return &Connector{Run: fr, Now: func() time.Time { return now }, CredentialsFile: func() string { return credFile }, ConfigFile: func() string { return "" }}
}

func healthyAccount() *fakeRunner {
	return &fakeRunner{replies: map[string]string{
		"configure list-profiles":                "dev\nprod\n",
		"sts get-caller-identity":                `{"Account":"111122223333","Arn":"arn:aws:iam::111122223333:user/alice"}`,
		"iam list-account-aliases":               `{"AccountAliases":["example-alias"]}`,
		"iam get-account-summary":                `{"SummaryMap":{"AccountMFAEnabled":0,"AccountAccessKeysPresent":1}}`,
		"iam list-users":                         `{"Users":[{"UserName":"alice","CreateDate":"2020-01-01T00:00:00Z"}]}`,
		"iam list-access-keys --user-name alice": `{"AccessKeyMetadata":[{"UserName":"alice","AccessKeyId":"AKIAIOSFODNN7EXAMPLE","Status":"Active","CreateDate":"2024-01-01T00:00:00+00:00"}]}`,
		"iam get-access-key-last-used --access-key-id AKIAIOSFODNN7EXAMPLE": `{"UserName":"alice","AccessKeyLastUsed":{"Region":"N/A","ServiceName":"N/A"}}`,
		"iam get-login-profile --user-name alice":                           `{"LoginProfile":{"UserName":"alice","CreateDate":"2020-01-01T00:00:00Z"}}`,
		"iam list-mfa-devices --user-name alice":                            `{"MFADevices":[]}`,
		"budgets describe-budgets --account-id 111122223333":                `{"Budgets":[]}`,
	}}
}

func TestInventoryGradesAnAccountAndSkipsDuplicateProfiles(t *testing.T) {
	fr := healthyAccount()
	rec := &httpxtest.Recorder{}
	if err := newTest(fr, "").Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	want := map[string]finding.Severity{
		"aws_root_mfa":         finding.SevCritical,
		"aws_root_access_keys": finding.SevCritical,
		"aws_access_key":       finding.SevHigh, // never used, older than 90 days
		"aws_user_mfa":         finding.SevHigh,
		"aws_budget":           finding.SevHigh,
		"aws_account":          finding.SevInfo, // the id behind the alias, for attribution
	}
	if len(rec.Findings) != len(want) {
		t.Fatalf("got %d findings: %+v", len(rec.Findings), rec.Findings)
	}
	for _, f := range rec.Findings {
		if want[f.Resource.Type] != f.Severity || f.Account != "example-alias" || f.Evidence["profile"] != "dev" || f.Scope != "profile dev" {
			t.Errorf("unexpected finding %s %s %s %v", f.Resource.Type, f.Severity, f.Account, f.Evidence)
		}
	}
	for _, f := range rec.Findings {
		if f.Resource.Type == "aws_account" && (f.Resource.ID != "111122223333" || f.Evidence["account_id"] != "111122223333") {
			t.Errorf("account id record: %+v", f)
		}
	}
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateOK {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
	if len(rec.Logs) != 1 || !strings.Contains(rec.Logs[0], "prod") {
		t.Fatalf("the second profile reaches the same account and should be skipped: %v", rec.Logs)
	}
	for _, c := range fr.calls {
		if strings.HasPrefix(c, "ce ") || strings.Contains(c, "generate-credential-report") {
			t.Fatalf("billed or report-generating call made by default: %s", c)
		}
	}
}

func TestCostExplorerIsOptIn(t *testing.T) {
	fr := healthyAccount()
	fr.replies["configure list-profiles"] = "dev\n"
	fr.replies["ce get-cost-and-usage --time-period Start=2026-11-01,End=2026-11-24 --granularity MONTHLY --metrics UnblendedCost"] = `{"ResultsByTime":[{"Total":{"UnblendedCost":{"Amount":"12.34","Unit":"USD"}}}]}`
	fr.replies["ce get-anomaly-monitors"] = `{"AnomalyMonitors":[]}`
	rec := &httpxtest.Recorder{}
	req := connector.Request{Config: map[string]any{"cost_explorer": true}}
	if err := newTest(fr, "").Inventory(context.Background(), req, rec); err != nil {
		t.Fatal(err)
	}
	if got := byType(rec, "aws_spend_month_to_date"); len(got) != 1 || got[0].Evidence["amount"] != "12.34" {
		t.Fatalf("month to date: %+v", got)
	}
	if got := byType(rec, "aws_anomaly_monitor"); len(got) != 1 || got[0].Severity != finding.SevMedium {
		t.Fatalf("anomaly monitor: %+v", got)
	}
}

func TestInventoryTurnsFailuresIntoStatuses(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want finding.State
	}{
		{"cli missing", fmt.Errorf("aws: %w", exec.ErrNotFound), finding.StateUnsupported},
		{"sso expired", errors.New("Error when retrieving token from sso: Token has expired and refresh failed"), finding.StateReauth},
		{"no credentials", errors.New("Unable to locate credentials. You can configure credentials by running \"aws configure\"."), finding.StateMissingCredentials},
		{"deleted key", errors.New("An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation"), finding.StateReauth},
		{"other", errors.New("Could not connect to the endpoint URL"), finding.StateError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{
				replies: map[string]string{"configure list-profiles": "dev\n"},
				errs:    map[string]error{"sts get-caller-identity": tc.err},
			}
			rec := &httpxtest.Recorder{}
			if err := newTest(fr, "").Inventory(context.Background(), connector.Request{}, rec); err != nil {
				t.Fatal(err)
			}
			if len(rec.Statuses) != 1 || rec.Statuses[0].State != tc.want || rec.Statuses[0].Account != "profile dev" {
				t.Fatalf("statuses: %+v", rec.Statuses)
			}
		})
	}
}

func TestAccessDeniedOnOneCheckKeepsTheOthers(t *testing.T) {
	fr := healthyAccount()
	fr.replies["configure list-profiles"] = "dev\n"
	fr.errs = map[string]error{"budgets describe-budgets --account-id 111122223333": errors.New("AccessDeniedException")}
	rec := &httpxtest.Recorder{}
	if err := newTest(fr, "").Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	if len(byType(rec, "aws_root_mfa")) != 1 || len(byType(rec, "aws_budget")) != 0 {
		t.Fatalf("findings: %+v", rec.Findings)
	}
	want := "user alice may not call budgets:ViewBudget: attach the AWS managed policies AWSBudgetsReadOnlyAccess (budgets:ViewBudget)"
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateNoScope || rec.Statuses[0].Detail != want {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
}

func TestAccessDeniedNamesTheExactActionsAndPolicies(t *testing.T) {
	denied := func(action string) error {
		return fmt.Errorf("An error occurred (AccessDenied) when calling the X operation: User: arn:aws:iam::111122223333:user/alice is not authorized to perform: %s on resource: * because no identity-based policy allows the %s action", action, action)
	}
	fr := healthyAccount()
	fr.replies["configure list-profiles"] = "dev\n"
	fr.errs = map[string]error{
		"iam get-account-summary": denied("iam:GetAccountSummary"),
		"iam list-users":          denied("iam:ListUsers"),
		"budgets describe-budgets --account-id 111122223333": denied("budgets:ViewBudget"),
	}
	rec := &httpxtest.Recorder{}
	if err := newTest(fr, "").Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	want := "user alice may not call iam:GetAccountSummary, iam:ListUsers, budgets:ViewBudget: attach the AWS managed policies SecurityAudit (iam:GetAccountSummary, iam:ListUsers) and AWSBudgetsReadOnlyAccess (budgets:ViewBudget)"
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateNoScope || rec.Statuses[0].Detail != want {
		t.Fatalf("statuses: %+v", rec.Statuses)
	}
}

func TestOtherFailuresStayErrorsAndKeepTheDenialHint(t *testing.T) {
	fr := healthyAccount()
	fr.replies["configure list-profiles"] = "dev\n"
	fr.errs = map[string]error{
		"iam get-account-summary":                            errors.New("Could not connect to the endpoint URL"),
		"budgets describe-budgets --account-id 111122223333": errors.New("AccessDeniedException"),
	}
	rec := &httpxtest.Recorder{}
	_ = newTest(fr, "").Inventory(context.Background(), connector.Request{}, rec)
	st := rec.Statuses[0]
	if st.State != finding.StateError || !strings.Contains(st.Detail, "root user: Could not connect") || !strings.Contains(st.Detail, "AWSBudgetsReadOnlyAccess") {
		t.Fatalf("status: %+v", st)
	}
}

func TestPolicyHintAllowsCostExplorerByName(t *testing.T) {
	got := policyHint("user bob", []string{"ce:GetCostAndUsage"})
	if got != "user bob may not call ce:GetCostAndUsage: allow ce:GetCostAndUsage in an inline policy" {
		t.Fatal(got)
	}
	got = policyHint("user bob", []string{"iam:ListUsers", "ce:GetAnomalyMonitors"})
	if got != "user bob may not call iam:ListUsers, ce:GetAnomalyMonitors: attach the AWS managed policies SecurityAudit (iam:ListUsers), and allow ce:GetAnomalyMonitors in an inline policy" {
		t.Fatal(got)
	}
}

func TestPrincipalName(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:iam::111122223333:user/alice":                   "user alice",
		"arn:aws:iam::111122223333:root":                         "root",
		"arn:aws:sts::111122223333:assumed-role/Admin/session-1": "arn:aws:sts::111122223333:assumed-role/Admin/session-1",
		"": "the profile",
	} {
		if got := principalName(arn); got != want {
			t.Errorf("%q: got %q, want %q", arn, got, want)
		}
	}
}

func TestR2ProfileIsReportedAsR2AndSkipsSTS(t *testing.T) {
	dir := t.TempDir()
	cred := filepath.Join(dir, "credentials")
	conf := filepath.Join(dir, "config")
	creds := "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = x\n[r2]\naws_access_key_id = ab2665aaaabbbbccccddddeeeeffff00\naws_secret_access_key = y\n"
	if err := statefile.Write(cred, []byte(creds)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte("[default]\nregion = eu-west-1\n[profile r2]\nregion = auto\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr := healthyAccount()
	fr.replies["configure list-profiles"] = "default\nr2\n"
	c := newTest(fr, cred)
	c.ConfigFile = func() string { return conf }
	rec := &httpxtest.Recorder{}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	r2 := byType(rec, "r2_local_credentials")
	if len(r2) != 1 || r2[0].Resource.Name != "r2" || !strings.Contains(r2[0].Title, "Cloudflare R2 API token") || r2[0].Remediation.URL != urlR2Tokens {
		t.Fatalf("r2 findings: %+v", rec.Findings)
	}
	if got := byType(rec, "aws_local_credentials"); len(got) != 1 || got[0].Resource.Name != "default" {
		t.Fatalf("aws findings: %+v", got)
	}
	stsCalls := 0
	for _, call := range fr.calls {
		if call == "sts get-caller-identity" {
			stsCalls++
		}
	}
	if stsCalls != 1 || len(rec.Statuses) != 1 || strings.Contains(rec.Statuses[0].Account, "r2") {
		t.Fatalf("the R2 profile must not reach STS or get a status: calls %v statuses %+v", fr.calls, rec.Statuses)
	}

	// doctor does not sign in with it either, nor tell the owner to.
	fr.calls = nil
	checks := c.Doctor(context.Background(), connector.Request{})
	if len(checks) != 2 || checks[1].What != "profile r2" || checks[1].Level != connector.OK || checks[1].Fix != "" ||
		!strings.Contains(checks[1].Detail, "Cloudflare R2 token, not an AWS identity") {
		t.Fatalf("doctor: %+v", checks)
	}
	if len(fr.calls) != 2 { // list-profiles, and STS for default only
		t.Fatalf("doctor calls: %v", fr.calls)
	}
}

func TestProfilesFromConfigSkipTheCLIListing(t *testing.T) {
	fr := &fakeRunner{errs: map[string]error{"sts get-caller-identity": errors.New("Unable to locate credentials")}}
	rec := &httpxtest.Recorder{}
	req := connector.Request{Config: map[string]any{"profiles": []any{"only"}}}
	if err := newTest(fr, "").Inventory(context.Background(), req, rec); err != nil {
		t.Fatal(err)
	}
	if fr.calls[0] != "sts get-caller-identity" || rec.Statuses[0].Account != "profile only" {
		t.Fatalf("calls %v statuses %+v", fr.calls, rec.Statuses)
	}
}

// A malformed setting stops the run before any aws call: a bad "profiles" never falls back to every
// profile, and a bad "cost_explorer" never silently turns the billed calls off.
func TestMalformedConfigFailsToStart(t *testing.T) {
	for _, tc := range []struct {
		cfg  map[string]any
		want string
	}{
		{map[string]any{"profiles": "only"}, `aws config: "profiles" must be a list of non-empty strings`},
		{map[string]any{"profiles": []any{"only", 3}}, `aws config: "profiles" must be a list of non-empty strings`},
		{map[string]any{"profiles": []any{""}}, `aws config: "profiles" must be a list of non-empty strings`},
		{map[string]any{"profiles": []any{}}, `aws config: "profiles" must name at least one entry; leave it out for all`},
		{map[string]any{"cost_explorer": "yes"}, `aws config: "cost_explorer" must be true or false`},
	} {
		fr := &fakeRunner{}
		err := newTest(fr, "").Inventory(context.Background(), connector.Request{Config: tc.cfg}, &httpxtest.Recorder{})
		if err == nil || err.Error() != tc.want || len(fr.calls) != 0 {
			t.Errorf("%v: %v, calls %v, want %s", tc.cfg, err, fr.calls, tc.want)
		}
		checks := newTest(fr, "").Doctor(context.Background(), connector.Request{Config: tc.cfg})
		if len(checks) != 1 || checks[0].Level != connector.Fail || checks[0].Detail != tc.want || len(fr.calls) != 0 {
			t.Errorf("doctor %v: %+v, calls %v", tc.cfg, checks, fr.calls)
		}
	}
}

func TestRootProfileIsCritical(t *testing.T) {
	fr := healthyAccount()
	fr.replies["configure list-profiles"] = "dev\n"
	fr.replies["sts get-caller-identity"] = `{"Account":"111122223333","Arn":"arn:aws:iam::111122223333:root"}`
	rec := &httpxtest.Recorder{}
	_ = newTest(fr, "").Inventory(context.Background(), connector.Request{}, rec)
	if got := byType(rec, "aws_root_profile"); len(got) != 1 || got[0].Severity != finding.SevCritical {
		t.Fatalf("root profile: %+v", got)
	}
}

func TestKeyFinding(t *testing.T) {
	used := func(d int) *time.Time { u := ago(d); return &u }
	cases := []struct {
		name     string
		status   string
		created  int
		lastUsed *time.Time
		want     finding.Severity
		title    string
	}{
		{"fresh and used", "Active", 30, used(1), finding.SevInfo, "(30 days old)"},
		{"old but used", "Active", 400, used(1), finding.SevHigh, "is 400 days old"},
		{"idle", "Active", 60, nil, finding.SevInfo, "(60 days old)"},
		{"never used and old", "Active", 120, nil, finding.SevHigh, "never been used"},
		{"unused for long", "Active", 200, used(100), finding.SevHigh, "unused for 100 days"},
		{"inactive", "Inactive", 400, used(300), finding.SevLow, "Inactive access key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := accessKey{AccessKeyId: "AKIAIOSFODNN7EXAMPLE", Status: tc.status, CreateDate: ago(tc.created)}
			f := keyFinding("alice", k, tc.lastUsed, now)
			if f.Severity != tc.want || !strings.Contains(f.Title, tc.title) {
				t.Fatalf("got %s %q", f.Severity, f.Title)
			}
			if f.Evidence["key_id"] != "AKIA…MPLE(20)" || f.LastUsedAt != tc.lastUsed {
				t.Fatalf("evidence must redact the key id and keep the provider's last use: %+v", f)
			}
		})
	}
}

func TestUserMFAFinding(t *testing.T) {
	cases := []struct {
		console bool
		devices int
		want    bool
	}{{true, 0, true}, {true, 1, false}, {false, 0, false}}
	for _, tc := range cases {
		if _, got := userMFAFinding("bob", tc.console, tc.devices); got != tc.want {
			t.Errorf("console=%v devices=%d: got %v", tc.console, tc.devices, got)
		}
	}
}

func TestBudgetMapping(t *testing.T) {
	b := awsBudget{BudgetName: "monthly", BudgetType: "COST", TimeUnit: "MONTHLY",
		BudgetLimit: &struct{ Amount, Unit string }{"200.0", "USD"},
		CostFilters: map[string][]string{"Service": {"Amazon Simple Storage Service"}}}
	got := b.neutral([]notification{
		{NotificationType: "ACTUAL", ComparisonOperator: "GREATER_THAN", Threshold: 80, ThresholdType: "PERCENTAGE"},
		{NotificationType: "FORECASTED", ComparisonOperator: "GREATER_THAN", Threshold: 200, ThresholdType: "ABSOLUTE_VALUE"},
		{NotificationType: "ACTUAL", ComparisonOperator: "LESS_THAN", Threshold: 10, ThresholdType: "PERCENTAGE"},
	})
	want := budget.Budget{ID: "monthly", Name: "monthly", Amount: 200, Currency: "USD", Period: budget.PeriodMonth,
		Thresholds: []budget.Threshold{{Percent: 80}, {Percent: 100, Forecast: true}},
		Scope:      budget.Scope{Filters: []string{"Service: Amazon Simple Storage Service"}},
		Notifies:   []string{budget.NotifySubscribers}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %+v\nwant %+v", got, want)
	}
	if quiet := (awsBudget{BudgetName: "q", TimeUnit: "CUSTOM"}).neutral(nil); quiet.Alerting() || quiet.Period != budget.PeriodCustom {
		t.Errorf("a budget without notifications alerts nobody: %+v", quiet)
	}
}

func budgetAccount() *fakeRunner {
	fr := healthyAccount()
	fr.replies["configure list-profiles"] = "dev\n"
	fr.replies["budgets describe-budgets --account-id 111122223333"] = `{"Budgets":[
		{"BudgetName":"Monthly cap","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"50.0","Unit":"USD"}},
		{"BudgetName":"Monthly copy","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"50.0","Unit":"USD"}},
		{"BudgetName":"RI use","BudgetType":"RI_UTILIZATION","TimeUnit":"MONTHLY"}]}`
	fr.replies["budgets describe-notifications-for-budget --account-id 111122223333 --budget-name Monthly cap"] = `{"Notifications":[
		{"NotificationType":"ACTUAL","ComparisonOperator":"GREATER_THAN","Threshold":50,"ThresholdType":"PERCENTAGE"}]}`
	fr.replies["budgets describe-notifications-for-budget --account-id 111122223333 --budget-name Monthly copy"] = `{"Notifications":[]}`
	fr.replies["budgets describe-budget-actions-for-account --account-id 111122223333"] = `{"Actions":[]}`
	return fr
}

func TestBudgetsGoThroughTheSharedRules(t *testing.T) {
	fr := budgetAccount()
	rec := &httpxtest.Recorder{}
	if err := newTest(fr, "").Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	want := map[string]finding.Severity{
		"Account example-alias has 2 budgets: 'Monthly cap' 50 USD/month, whole account; 'Monthly copy' 50 USD/month, whole account":                                                 finding.SevInfo,
		"Budget 'Monthly cap' (50 USD/month, whole account) alerts only at 50%: add 90%, 100% and a forecasted threshold":                                                            finding.SevMedium,
		"Budgets 'Monthly cap' and 'Monthly copy' on account example-alias are the same (50 USD/month, whole account): delete one":                                                   finding.SevLow,
		"Budgets on account example-alias only notify: none is wired to a budget action, so nothing stops spend; 1 active IAM user access key and 1 root access key in this account": finding.SevMedium,
	}
	got := map[string]finding.Finding{}
	for _, f := range rec.Findings {
		if f.Kind == finding.KindSpend {
			got[f.Title] = f
		}
	}
	for title, sev := range want {
		if f, ok := got[title]; !ok || f.Severity != sev || f.Account != "example-alias" || f.Scope != "profile dev" {
			t.Errorf("%q: %+v", title, f)
		}
	}
	if len(got) != len(want) {
		t.Errorf("spend findings: %v", got)
	}

	fr = budgetAccount()
	fr.replies["budgets describe-budget-actions-for-account --account-id 111122223333"] = `{"Actions":[{"BudgetName":"Monthly cap","ActionType":"APPLY_IAM_POLICY"}]}`
	rec = &httpxtest.Recorder{}
	if err := newTest(fr, "").Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	if len(byType(rec, "budget_enforcement")) != 0 {
		t.Errorf("a budget action caps spend")
	}
}

func TestDeniedBudgetActionsKeepTheOtherBudgetFindings(t *testing.T) {
	fr := budgetAccount()
	delete(fr.replies, "budgets describe-budget-actions-for-account --account-id 111122223333")
	fr.errs = map[string]error{"budgets describe-budget-actions-for-account --account-id 111122223333": errors.New("AccessDeniedException")}
	rec := &httpxtest.Recorder{}
	if err := newTest(fr, "").Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	if len(byType(rec, "budget_enforcement")) != 0 || len(byType(rec, "budget_thresholds")) != 1 {
		t.Errorf("unknown actions are not reported missing; thresholds still are: %+v", rec.Findings)
	}
	st := rec.Statuses[0]
	if st.State != finding.StateNoScope || !strings.Contains(st.Detail, "AWSBudgetsReadOnlyAccess (budgets:DescribeBudgetActionsForAccount)") {
		t.Errorf("status %+v", st)
	}
}

const credentialsFixture = `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

; a comment
[session]
aws_access_key_id=ASIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token=FwoGZXIvYXdzEXAMPLE

[sso-only]
sso_session = corp
`

func TestCredentialsFileReportsLongLivedKeysWithoutSecrets(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		want finding.Severity
	}{{0o600, finding.SevMedium}, {0o644, finding.SevHigh}} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials")
			if err := statefile.Write(path, []byte(credentialsFixture)); err != nil {
				t.Fatal(err)
			}
			if tc.mode == 0o644 {
				fileacltest.Expose(t, path)
			}
			fr := &fakeRunner{errs: map[string]error{"configure list-profiles": fmt.Errorf("aws: %w", exec.ErrNotFound)}}
			rec := &httpxtest.Recorder{}
			if err := newTest(fr, path).Inventory(context.Background(), connector.Request{}, rec); err != nil {
				t.Fatal(err)
			}
			got := byType(rec, "aws_local_credentials")
			if len(got) != 1 || got[0].Resource.Name != "default" || got[0].Severity != tc.want || got[0].Kind != finding.KindExposure {
				t.Fatalf("findings: %+v", rec.Findings)
			}
			dump := fmt.Sprintf("%+v", got[0])
			if strings.Contains(dump, "wJalrXUtnFEMI") || strings.Contains(dump, "AKIAIOSFODNN7EXAMPLE") {
				t.Fatalf("secret or full key id leaked: %s", dump)
			}
			if rec.Statuses[0].State != finding.StateUnsupported {
				t.Fatalf("missing CLI should be a status: %+v", rec.Statuses)
			}
			if fix := connector.MakePrivateCommand(runtime.GOOS, path, false); strings.Contains(got[0].Remediation.Summary, fix) != (tc.mode == 0o644) {
				t.Errorf("this platform's make-private command only for an exposed file: %s", got[0].Remediation.Summary)
			}
		})
	}
}

func TestEveryCommandRunIsReadOnly(t *testing.T) {
	fr := healthyAccount()
	if err := newTest(fr, "").Inventory(context.Background(), connector.Request{Config: map[string]any{"cost_explorer": true}}, &httpxtest.Recorder{}); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) == 0 {
		t.Fatal("no aws command ran")
	}
	for _, call := range fr.calls {
		if err := readOnly.Check(strings.Fields(call)); err != nil {
			t.Errorf("call outside the allowlist: %v", err)
		}
	}
}

func TestMutatingCommandIsRefusedBeforeTheCLI(t *testing.T) {
	for _, args := range [][]string{
		{"iam", "delete-access-key", "--access-key-id", "AKIAEXAMPLE"},
		{"iam", "create-access-key"},
		{"budgets", "delete-budget", "--account-id", "1"},
		{"configure", "set", "region", "eu-west-1"},
		{"--profile", "p", "iam", "list-users"},
	} {
		fr := &fakeRunner{}
		_, err := newTest(fr, "").aws(context.Background(), args...)
		if !errors.Is(err, cli.ErrRefused) {
			t.Errorf("%v: want refusal, got %v", args, err)
		}
		if len(fr.calls) != 0 {
			t.Errorf("%v reached the CLI", args)
		}
	}
}

// A plain-text key says, after the profile is inspected, that STS accepted it and for which
// account, the account its id encodes, and the fingerprint local-secrets gives its leaked copies:
// what lets the tracker merge it with the rotate item of the same key.
func TestPlainTextKeyNamesItsFingerprintAccountAndLiveness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("[dev]\naws_access_key_id = AKIASP2TPHJSQH3FJXYZ\naws_secret_access_key = x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := fingerprint.FromBytes([]byte("0123456789abcdef0123456789abcdef"))
	c := newTest(healthyAccount(), path)
	c.Fingerprint = func() (fingerprint.Key, bool) { return key, true }
	rec := &httpxtest.Recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"profiles": []any{"dev"}}}, rec); err != nil {
		t.Fatal(err)
	}
	got := byType(rec, "aws_local_credentials")
	if len(got) != 1 {
		t.Fatalf("findings: %+v", rec.Findings)
	}
	ev := got[0].Evidence
	if ev["fingerprint"] != key.Of("AKIASP2TPHJSQH3FJXYZ") || ev["aws_account"] != "171436882533" || ev["sts_account"] != "111122223333" {
		t.Errorf("evidence: %v", ev)
	}
	if !strings.HasSuffix(got[0].Title, "; aws sts says it works for account 111122223333") {
		t.Errorf("title: %s", got[0].Title)
	}
	if strings.Contains(fmt.Sprintf("%+v", got[0]), "AKIASP2TPHJSQH3FJXYZ") {
		t.Error("the full key id leaked")
	}
}
