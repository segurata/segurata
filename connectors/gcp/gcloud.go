package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// Runner executes one gcloud command and returns its stdout. Tests inject a fake.
type Runner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

// readOnly lists the only gcloud command paths this connector may run. Anything else is refused
// before it reaches the CLI, so a bug cannot create, delete, disable, print a key string or change
// gcloud config.
var readOnly = [][]string{
	{"auth", "list"},
	{"projects", "list"},
	{"projects", "get-iam-policy"},
	{"iam", "service-accounts", "list"},
	{"iam", "service-accounts", "keys", "list"},
	{"services", "api-keys", "list"},
	{"billing", "accounts", "list"},
	{"billing", "projects", "describe"},
	{"billing", "budgets", "list"},
}

func allowed(args []string) bool {
	var path []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			break
		}
		path = append(path, a)
	}
	for _, cmd := range readOnly {
		if len(path) >= len(cmd) && slices.Equal(path[:len(cmd)], cmd) {
			return true
		}
	}
	return false
}

// gcloud wraps a Runner with the read-only guard, JSON output and retries on rate limits.
type gcloud struct {
	run     Runner
	backoff time.Duration // first retry delay; doubles each attempt
}

const attempts = 3

func (g *gcloud) json(ctx context.Context, into any, args ...string) error {
	if !allowed(args) {
		return fmt.Errorf("refused non read-only gcloud command: %s", strings.Join(args, " "))
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

// cliError carries gcloud's stderr, which is where it explains failures.
type cliError struct {
	stderr string
	err    error
}

func (e *cliError) Error() string { return summarize(e.stderr, e.err) }

func rateLimited(err error) bool {
	return containsAny(errText(err), "'status': 429", "RESOURCE_EXHAUSTED", "Quota exceeded", "rateLimitExceeded", "RATE_LIMIT_EXCEEDED")
}

func errText(err error) string {
	var ce *cliError
	if errors.As(err, &ce) {
		return ce.stderr
	}
	return err.Error()
}

const deniedPrefix = "permission denied: "

// classify turns a gcloud failure into a status state and a short reason without secrets.
func classify(err error) (finding.State, string) {
	s := errText(err)
	switch {
	case containsAny(s, "Reauthentication failed", "gcloud auth login", "invalid_grant", "Please run:\n\n  $ gcloud auth"):
		return finding.StateReauth, "credentials expired: run gcloud auth login for this account"
	case containsAny(s, "has not been used in project", "SERVICE_DISABLED", "it is disabled"):
		return finding.StateError, "API not enabled: " + summarize(s, err)
	case containsAny(s, "PERMISSION_DENIED", "does not have permission", "USER_PROJECT_DENIED", "403"):
		return finding.StateError, deniedPrefix + summarize(s, err)
	case rateLimited(err):
		return finding.StateError, "rate limited: " + summarize(s, err)
	}
	return finding.StateError, summarize(s, err)
}

func containsAny(s string, subs ...string) bool {
	for _, p := range subs {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// summarize keeps the first meaningful line of gcloud's stderr, without help tokens or links.
func summarize(stderr string, err error) string {
	line := strings.TrimSpace(stderr)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if line == "" && err != nil {
		var ce *cliError
		if errors.As(err, &ce) && ce.err != nil {
			return ce.err.Error()
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
	const max = 220
	if len(line) > max {
		line = line[:max] + "…"
	}
	return strings.TrimSpace(line)
}

// execRunner runs the real gcloud binary with prompts disabled and a timeout per command.
type execRunner struct {
	path    string
	timeout time.Duration
}

func (e execRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.path, args...)
	cmd.Env = append(os.Environ(), "CLOUDSDK_CORE_DISABLE_PROMPTS=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("gcloud %s timed out after %s", strings.Join(args[:min(3, len(args))], " "), e.timeout)
		}
		return nil, &cliError{stderr: stderr.String(), err: err}
	}
	return out, nil
}

// findGcloud resolves the CLI: explicit config, then PATH, then the usual SDK install folders.
func findGcloud(configured, home string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if p, err := exec.LookPath("gcloud"); err == nil {
		return p, nil
	}
	for _, p := range []string{
		filepath.Join(home, "src", "utils", "google-cloud-sdk", "bin", "gcloud"),
		filepath.Join(home, "google-cloud-sdk", "bin", "gcloud"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("gcloud CLI not found in PATH or the usual install folders")
}
