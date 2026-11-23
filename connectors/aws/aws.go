// Package aws inventories AWS accounts through the installed `aws` CLI: root user MFA and keys,
// IAM access keys (age, last use), console users without MFA, budgets and their alerts, and
// long-lived keys left in the local shared credentials file. Read-only. See docs/cloud-connectors.md.
package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// staleAfter is the age or idle time past which an access key is a liability.
const staleAfter = 90 * 24 * time.Hour

// Runner runs a CLI and returns its stdout. Tests replace it with canned output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner runs the real binary with a timeout, folding stderr into the error.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args[:min(2, len(args))], " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

type Connector struct {
	Run Runner
	Now func() time.Time
	// CredentialsFile returns the shared credentials file path to scan for long-lived keys.
	CredentialsFile func() string
}

func New() *Connector {
	return &Connector{Run: execRunner, Now: time.Now, CredentialsFile: defaultCredentialsFile}
}

func init() { connector.Register(New()) }

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     "aws",
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Root user MFA and keys, IAM access key age and use, console users without MFA, budgets, local credentials file",
		Needs:    []string{"cli:aws"},
	}
}

func defaultCredentialsFile() string {
	if p := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".aws", "credentials")
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	now := c.Now()
	c.scanCredentialsFile(emit)

	profiles, err := c.profiles(ctx, req.Config)
	if err != nil {
		emit.Status(finding.Status{Account: "aws", State: classify(err), Detail: err.Error()})
		return nil
	}
	if len(profiles) == 0 {
		emit.Status(finding.Status{Account: "aws", State: finding.StateMissingCredentials,
			Detail: "no AWS CLI profiles: run `aws configure sso` or set connectors.aws.config.profiles"})
		return nil
	}
	costExplorer, _ := req.Config["cost_explorer"].(bool)
	seen := map[string]bool{}
	for _, p := range profiles {
		c.inspectProfile(ctx, p, now, costExplorer, seen, emit)
	}
	return nil
}

// profiles comes from config `profiles` when set, otherwise from `aws configure list-profiles`.
func (c *Connector) profiles(ctx context.Context, cfg map[string]any) ([]string, error) {
	if raw, ok := cfg["profiles"].([]any); ok {
		var out []string
		for _, p := range raw {
			if s, ok := p.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	}
	out, err := c.Run(ctx, "aws", "configure", "list-profiles")
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// call runs one read-only aws command for a profile and decodes its JSON output.
// us-east-1 hosts the global IAM, STS, Budgets and Cost Explorer endpoints of the aws partition.
func (c *Connector) call(ctx context.Context, profile string, out any, args ...string) error {
	args = append(args, "--profile", profile, "--region", "us-east-1", "--output", "json", "--no-cli-pager")
	raw, err := c.Run(ctx, "aws", args...)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// classify maps an aws CLI failure to the status the owner has to act on.
func classify(err error) finding.State {
	if errors.Is(err, exec.ErrNotFound) {
		return finding.StateUnsupported
	}
	msg := err.Error()
	switch {
	case containsAny(msg, "Unable to locate credentials", "could not be found", "NoCredentialProviders"):
		return finding.StateMissingCredentials
	case containsAny(msg, "xpired", "sso login", "SSO session", "InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch"):
		return finding.StateReauth
	}
	return finding.StateError
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// audit inspects one account through one profile and collects the checks that failed.
type audit struct {
	c          *Connector
	ctx        context.Context
	profile    string
	accountID  string
	account    string
	now        time.Time
	emitter    connector.Emitter
	failedWith []string
}

func (a *audit) emit(f finding.Finding) {
	f.Account = a.account
	if f.Evidence == nil {
		f.Evidence = map[string]any{}
	}
	f.Evidence["profile"] = a.profile
	a.emitter.Finding(f)
}

// call runs one read-only aws command through the audited profile.
func (a *audit) call(out any, args ...string) error {
	return a.c.call(a.ctx, a.profile, out, args...)
}

func (a *audit) check(name string, fn func() error) {
	if err := fn(); err != nil {
		a.failedWith = append(a.failedWith, fmt.Sprintf("%s: %v", name, err))
	}
}

func (c *Connector) inspectProfile(ctx context.Context, profile string, now time.Time, costExplorer bool, seen map[string]bool, emit connector.Emitter) {
	var id struct{ Account, Arn string }
	if err := c.call(ctx, profile, &id, "sts", "get-caller-identity"); err != nil {
		emit.Status(finding.Status{Account: "profile " + profile, State: classify(err), Detail: err.Error()})
		return
	}
	if seen[id.Account] {
		emit.Log(fmt.Sprintf("profile %s reaches an account already inspected, skipped", profile))
		return
	}
	seen[id.Account] = true

	a := &audit{c: c, ctx: ctx, profile: profile, accountID: id.Account, account: id.Account, now: now, emitter: emit}
	var aliases struct{ AccountAliases []string }
	if err := c.call(ctx, profile, &aliases, "iam", "list-account-aliases"); err == nil && len(aliases.AccountAliases) > 0 {
		a.account = aliases.AccountAliases[0]
	}
	if strings.HasSuffix(id.Arn, ":root") {
		a.emit(rootProfileFinding(profile))
	}
	a.check("root user", a.root)
	a.check("IAM users", a.users)
	a.check("budgets", a.budgets)
	if costExplorer {
		a.check("cost explorer", a.costExplorer)
	}

	st := finding.Status{Account: a.account, State: finding.StateOK}
	if len(a.failedWith) > 0 {
		st.State, st.Detail = finding.StateError, strings.Join(a.failedWith, "; ")
	}
	emit.Status(st)
}

func (a *audit) root() error {
	var s struct{ SummaryMap map[string]int }
	if err := a.call(&s, "iam", "get-account-summary"); err != nil {
		return err
	}
	for _, f := range rootFindings(s.SummaryMap) {
		a.emit(f)
	}
	return nil
}

type iamUser struct {
	UserName   string
	CreateDate time.Time
}

type accessKey struct {
	UserName    string
	AccessKeyId string
	Status      string
	CreateDate  time.Time
}

func (a *audit) users() error {
	var list struct{ Users []iamUser }
	if err := a.call(&list, "iam", "list-users"); err != nil {
		return err
	}
	for _, u := range list.Users {
		if err := a.user(u); err != nil {
			return fmt.Errorf("user %s: %w", u.UserName, err)
		}
	}
	return nil
}

func (a *audit) user(u iamUser) error {
	var keys struct{ AccessKeyMetadata []accessKey }
	if err := a.call(&keys, "iam", "list-access-keys", "--user-name", u.UserName); err != nil {
		return err
	}
	for _, k := range keys.AccessKeyMetadata {
		var used struct {
			AccessKeyLastUsed struct{ LastUsedDate *time.Time }
		}
		if err := a.call(&used, "iam", "get-access-key-last-used", "--access-key-id", k.AccessKeyId); err != nil {
			return err
		}
		a.emit(keyFinding(u.UserName, k, used.AccessKeyLastUsed.LastUsedDate, a.now))
	}

	console := true
	var login struct{}
	if err := a.call(&login, "iam", "get-login-profile", "--user-name", u.UserName); err != nil {
		if !strings.Contains(err.Error(), "NoSuchEntity") {
			return err
		}
		console = false
	}
	var mfa struct {
		MFADevices []struct{ SerialNumber string }
	}
	if err := a.call(&mfa, "iam", "list-mfa-devices", "--user-name", u.UserName); err != nil {
		return err
	}
	if f, ok := userMFAFinding(u.UserName, console, len(mfa.MFADevices)); ok {
		a.emit(f)
	}
	return nil
}

type budget struct {
	BudgetName  string
	BudgetType  string
	TimeUnit    string
	BudgetLimit *struct{ Amount, Unit string }
}

func (a *audit) budgets() error {
	var list struct{ Budgets []budget }
	if err := a.call(&list, "budgets", "describe-budgets", "--account-id", a.accountID); err != nil {
		return err
	}
	if len(list.Budgets) == 0 {
		a.emit(noBudgetFinding())
		return nil
	}
	for _, b := range list.Budgets {
		var n struct {
			Notifications []struct{ NotificationType string }
		}
		if err := a.call(&n, "budgets", "describe-notifications-for-budget", "--account-id", a.accountID, "--budget-name", b.BudgetName); err != nil {
			return err
		}
		a.emit(budgetFinding(b, len(n.Notifications)))
	}
	return nil
}

// costExplorer is opt-in: every Cost Explorer API request is billed (USD 0.01 each).
func (a *audit) costExplorer() error {
	start := time.Date(a.now.Year(), a.now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(a.now.Year(), a.now.Month(), a.now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	var cost struct {
		ResultsByTime []struct {
			Total map[string]struct{ Amount, Unit string }
		}
	}
	period := fmt.Sprintf("Start=%s,End=%s", start.Format(time.DateOnly), end.Format(time.DateOnly))
	if err := a.call(&cost, "ce", "get-cost-and-usage", "--time-period", period, "--granularity", "MONTHLY", "--metrics", "UnblendedCost"); err != nil {
		return err
	}
	for _, r := range cost.ResultsByTime {
		if t, ok := r.Total["UnblendedCost"]; ok {
			a.emit(monthToDateFinding(t.Amount, t.Unit, start))
		}
	}
	var mon struct {
		AnomalyMonitors []struct{ MonitorName string }
	}
	if err := a.call(&mon, "ce", "get-anomaly-monitors"); err != nil {
		return err
	}
	if len(mon.AnomalyMonitors) == 0 {
		a.emit(noAnomalyMonitorFinding())
	}
	return nil
}
