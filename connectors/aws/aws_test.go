package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
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
	}
	if len(rec.Findings) != len(want) {
		t.Fatalf("got %d findings: %+v", len(rec.Findings), rec.Findings)
	}
	for _, f := range rec.Findings {
		if want[f.Resource.Type] != f.Severity || f.Account != "example-alias" || f.Evidence["profile"] != "dev" {
			t.Errorf("unexpected finding %s %s %s %v", f.Resource.Type, f.Severity, f.Account, f.Evidence)
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

func TestProviderOf(t *testing.T) {
	r2ID := "ab2665aaaabbbbccccddddeeeeffff00"
	cases := []struct {
		name string
		key  string
		cfg  profileConfig
		want provider
	}{
		{"aws long-lived", "AKIAIOSFODNN7EXAMPLE", profileConfig{Region: "eu-west-1"}, providerAWS},
		{"aws temporary", "ASIAIOSFODNN7EXAMPLE", profileConfig{}, providerAWS},
		{"sso profile without key", "", profileConfig{}, providerAWS},
		{"r2 by key id shape", r2ID, profileConfig{}, providerR2},
		{"r2 by region auto", "SOMEKEY", profileConfig{Region: "auto"}, providerR2},
		{"r2 by endpoint", "AKIAIOSFODNN7EXAMPLE", profileConfig{Endpoint: "https://0123.r2.cloudflarestorage.com"}, providerR2},
		{"other s3-compatible", "0025a1b2c3d4e5f60000000001", profileConfig{Endpoint: "https://s3.eu-central-003.backblazeb2.com"}, providerS3Compatible},
	}
	for _, tc := range cases {
		if got := providerOf(credentialProfile{Name: "p", KeyID: tc.key}, tc.cfg); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestR2ProfileIsReportedAsR2AndSkipsSTS(t *testing.T) {
	dir := t.TempDir()
	cred := filepath.Join(dir, "credentials")
	conf := filepath.Join(dir, "config")
	creds := "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = x\n[r2]\naws_access_key_id = ab2665aaaabbbbccccddddeeeeffff00\naws_secret_access_key = y\n"
	if err := os.WriteFile(cred, []byte(creds), 0o600); err != nil {
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
			if f.Evidence["key_id"] == k.AccessKeyId || f.LastUsedAt != tc.lastUsed {
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

func TestBudgetFinding(t *testing.T) {
	b := budget{BudgetName: "monthly", BudgetLimit: &struct{ Amount, Unit string }{"100.0", "USD"}}
	if f := budgetFinding(b, 0); f.Severity != finding.SevMedium {
		t.Fatalf("budget without alerts: %s", f.Severity)
	}
	if f := budgetFinding(b, 2); f.Severity != finding.SevInfo || f.Evidence["limit"] != "100.0 USD" {
		t.Fatalf("budget with alerts: %+v", f)
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
			if err := os.WriteFile(path, []byte(credentialsFixture), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil { // umask may have narrowed it
				t.Fatal(err)
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
