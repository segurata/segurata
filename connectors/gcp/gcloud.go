package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

// readOnly is every gcloud command path the inventory and the plans may run; a bug cannot create,
// delete, disable, print a key string or change gcloud config. The writes a confirmed remediation
// makes never go through it: they are connector.Steps on a per-plan connector.Allowlist
// (remediate.go). print-access-token hands the REST reads (Cloud Monitoring, Cloud Quotas) a token
// that is never logged, stored or put in an error.
var readOnly = cli.Allowlist{
	"auth list",
	"auth print-access-token",
	"services list",
	"projects list",
	"projects get-iam-policy",
	"iam service-accounts list",
	"iam service-accounts keys list",
	"services api-keys list",
	"billing accounts list",
	"billing projects describe",
	"billing budgets list",
}

type gcloud struct {
	run            cli.Runner
	path           string        // argv[0] of a remediation step
	backoff        time.Duration // doubles each attempt
	apiBase        func(host string) string
	billingProject string // configured quota project, else each request bills the project it reads

	mu     sync.Mutex
	tokens map[string]string // account -> access token, for this run only
}

const attempts = 3

func (g *gcloud) json(ctx context.Context, into any, args ...string) error {
	if err := readOnly.Check(args); err != nil {
		return fmt.Errorf("gcloud: %w", err)
	}
	args = append(args, "--format=json")
	delay := g.backoff
	var err error
	for i := 0; i < attempts; i++ {
		var out []byte
		if out, err = g.run.Run(ctx, args...); err == nil {
			if len(bytes.TrimSpace(out)) == 0 {
				return nil
			}
			return json.Unmarshal(out, into)
		}
		if !rateLimited(err) || i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
	return err
}

// token is an access token for account, read once per run. A failure says what gcloud printed on
// stderr; the token is on stdout and never part of an error.
func (g *gcloud) token(ctx context.Context, account string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t, ok := g.tokens[account]; ok {
		return t, nil
	}
	args := []string{"auth", "print-access-token", "--account=" + account}
	if err := readOnly.Check(args); err != nil {
		return "", fmt.Errorf("gcloud: %w", err)
	}
	out, err := g.run.Run(ctx, args...)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(out))
	if t == "" || strings.ContainsAny(t, " \t\r\n") {
		return "", errors.New("gcloud auth print-access-token printed no token")
	}
	if g.tokens == nil {
		g.tokens = map[string]string{}
	}
	g.tokens[account] = t
	return t, nil
}

// api is a GET client for one Google REST API (host such as monitoring.googleapis.com) as account.
// userProject goes in X-Goog-User-Project: gcloud's own OAuth client has no quota for these APIs,
// so requests are billed to that project (gcloud auth print-access-token, "Note that token itself
// may not be enough").
func (g *gcloud) api(ctx context.Context, host, account, userProject string) (*httpx.Client, error) {
	t, err := g.token(ctx, account)
	if err != nil {
		return nil, err
	}
	base := "https://" + host
	if g.apiBase != nil {
		base = g.apiBase(host)
	}
	h := http.Header{"Authorization": {"Bearer " + t}}
	if userProject != "" {
		h.Set("X-Goog-User-Project", userProject)
	}
	return httpx.New(base, h), nil
}

func (g *gcloud) userProject(project string) string {
	if g.billingProject != "" {
		return g.billingProject
	}
	return project
}

func rateLimited(err error) bool {
	return textfmt.ContainsAny(printed(err), "'status': 429", "RESOURCE_EXHAUSTED", "Quota exceeded", "rateLimitExceeded", "RATE_LIMIT_EXCEEDED")
}

const deniedPrefix = "permission denied: "

// http403 matches the status code alone, not a project number that happens to contain 403.
var http403 = regexp.MustCompile(`\b403\b`)

// printed is what gcloud wrote on stderr, or the exit error when it wrote nothing. Never the
// command line, which cli.Stderr falls back to: it holds project ids, and an id such as acme-403
// must not read as a refusal.
func printed(err error) string {
	ce, ok := errors.AsType[*cli.Error](err)
	switch {
	case !ok:
		return err.Error()
	case strings.TrimSpace(ce.Stderr) == "" && ce.Err != nil:
		return ce.Err.Error()
	}
	return ce.Stderr
}

func classify(err error) (finding.State, string) {
	s := printed(err)
	switch {
	case textfmt.ContainsAny(s, "Reauthentication failed", "gcloud auth login", "invalid_grant", "Please run:\n\n  $ gcloud auth"):
		return finding.StateReauth, "credentials expired: run gcloud auth login for this account"
	case textfmt.ContainsAny(s, "has not been used in project", "SERVICE_DISABLED", "it is disabled"):
		return finding.StateError, "API not enabled: " + summarize(s)
	case textfmt.ContainsAny(s, "PERMISSION_DENIED", "does not have permission", "USER_PROJECT_DENIED") || http403.MatchString(s):
		return finding.StateError, deniedPrefix + summarize(s)
	case rateLimited(err):
		return finding.StateError, "rate limited: " + summarize(s)
	}
	return finding.StateError, summarize(s)
}

func summarize(stderr string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(stderr), "\n")
	if strings.HasPrefix(line, "ERROR: (") {
		if i := strings.Index(line, ") "); i >= 0 {
			line = line[i+2:]
		}
	}
	for _, cut := range []string{" Help Token", " Remediate access", " This command is authenticated as", " Enable it by visiting"} {
		if i := strings.Index(line, cut); i >= 0 {
			line = line[:i]
		}
	}
	return textfmt.Truncate(strings.TrimSpace(line), 221)
}
