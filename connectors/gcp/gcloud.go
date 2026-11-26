package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

// readOnly is every gcloud command path the connector may run; a bug cannot create, delete,
// disable, print a key string or change gcloud config.
var readOnly = cli.Allowlist{
	"auth list",
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
	run     cli.Runner
	backoff time.Duration // doubles each attempt
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

func rateLimited(err error) bool {
	return textfmt.ContainsAny(errText(err), "'status': 429", "RESOURCE_EXHAUSTED", "Quota exceeded", "rateLimitExceeded", "RATE_LIMIT_EXCEEDED")
}

func errText(err error) string {
	var ce *cli.Error
	if errors.As(err, &ce) {
		return ce.Stderr
	}
	return err.Error()
}

const deniedPrefix = "permission denied: "

// http403 matches the status code alone, not a project number that happens to contain 403.
var http403 = regexp.MustCompile(`\b403\b`)

func classify(err error) (finding.State, string) {
	s := errText(err)
	switch {
	case textfmt.ContainsAny(s, "Reauthentication failed", "gcloud auth login", "invalid_grant", "Please run:\n\n  $ gcloud auth"):
		return finding.StateReauth, "credentials expired: run gcloud auth login for this account"
	case textfmt.ContainsAny(s, "has not been used in project", "SERVICE_DISABLED", "it is disabled"):
		return finding.StateError, "API not enabled: " + summarize(s, err)
	case textfmt.ContainsAny(s, "PERMISSION_DENIED", "does not have permission", "USER_PROJECT_DENIED") || http403.MatchString(s):
		return finding.StateError, deniedPrefix + summarize(s, err)
	case rateLimited(err):
		return finding.StateError, "rate limited: " + summarize(s, err)
	}
	return finding.StateError, summarize(s, err)
}

func summarize(stderr string, err error) string {
	line := strings.TrimSpace(stderr)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if line == "" && err != nil {
		var ce *cli.Error
		if errors.As(err, &ce) && ce.Err != nil {
			return ce.Err.Error()
		}
		return err.Error()
	}
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
