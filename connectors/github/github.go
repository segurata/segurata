// Package github inventories the security settings of a GitHub account through the authenticated
// `gh` CLI: the account's two-factor authentication, the organizations it owns (2FA requirement and
// members without it, default permissions, Actions permissions, code security defaults) and the
// repositories it administers (secret scanning, push protection, Dependabot security updates,
// webhooks, deploy keys, Actions defaults, optionally branch protection). Read-only: every request
// is a GET on an allowlisted path. OAuth apps, GitHub Apps, sessions and the account's own keys are
// covered by the connected-apps connector. Remediations (remediate.go) write through `gh api`
// only after a confirmed plan, with their own allowlist.
package github

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

const (
	defaultMaxRepos = 500
	// rateReserve is how many requests of the hourly quota the connector leaves for the owner's
	// other tools; it stops before going below it.
	rateReserve = 300
	concurrency = 4
	web         = "https://github.com"
)

type Connector struct {
	// Run executes gh commands after the read-only guard. Tests replace it with canned output.
	Run cli.Runner
	// Exec runs a confirmed remediation's allowlisted commands; nil is remediate.System. Tests
	// replace it with a recorder.
	Exec remediate.Executor
}

func New() *Connector {
	return &Connector{
		Run: cli.Exec{Path: "gh", Timeout: time.Minute, Env: []string{"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "NO_COLOR=1"}},
	}
}

func init() { connector.Register(New()) }

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     "github",
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "GitHub account 2FA, organization security settings, and the webhooks, deploy keys and code security of repositories you administer",
		Needs:    []string{"cli:gh"},
	}
}

type settings struct {
	maxRepos         int
	branchProtection bool
}

func parseSettings(m map[string]any) (settings, error) {
	s := settings{maxRepos: defaultMaxRepos}
	if v, ok := m["max_repos"]; ok && v != nil {
		n, ok := v.(float64)
		if !ok || n < 1 || n != float64(int(n)) {
			return s, errors.New(`github config: "max_repos" must be a whole number above 0`)
		}
		s.maxRepos = int(n)
	}
	if v, ok := m["branch_protection"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return s, errors.New(`github config: "branch_protection" must be true or false`)
		}
		s.branchProtection = b
	}
	return s, nil
}

// run is one inventory: the connector, the emitter, the token's scopes and the request budget.
type run struct {
	c      *Connector
	emit   connector.Emitter
	cfg    settings
	scopes scopes
	budget atomic.Int64 // requests left before the reserve
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	cfg, err := parseSettings(req.Config)
	if err != nil {
		emit.Status(finding.Status{Account: "github", State: finding.StateError, Detail: err.Error()})
		return nil
	}
	r := &run{c: c, emit: emit, cfg: cfg}
	if !r.start(ctx) {
		return nil
	}
	u, ok := r.user(ctx)
	if !ok {
		return nil
	}
	ms, msOK := r.memberships(ctx, u.Login)
	r.account2FA(u, ownsAny(ms))
	if msOK {
		r.orgs(ctx, ms)
	}
	r.repos(ctx, u.Login)
	return nil
}

// start reads the token's scopes and the rate limit in one request that does not count against
// the quota. It reports and returns false when nothing else can run.
func (r *run) start(ctx context.Context) bool {
	out, err := r.gh(ctx, "--include", "/rate_limit")
	if err != nil {
		r.status("github", stateOf(err), "%s", describe(err, "check `gh auth status`"))
		return false
	}
	head, body := splitInclude(out)
	r.scopes = parseScopes(head)
	var rl struct {
		Resources struct {
			Core struct {
				Limit, Remaining int
				Reset            int64
			} `json:"core"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(body, &rl); err != nil {
		r.status("github", finding.StateError, "gh api /rate_limit: unexpected output: %v", err)
		return false
	}
	core := rl.Resources.Core
	r.budget.Store(int64(core.Remaining - rateReserve))
	if r.budget.Load() <= 0 {
		r.status("github", finding.StateError, "GitHub API rate limit low: %d of %d requests left until %s; run again after that",
			core.Remaining, core.Limit, time.Unix(core.Reset, 0).Local().Format("15:04"))
		return false
	}
	return true
}

// splitInclude separates the headers `gh api --include` prints from the body after them.
func splitInclude(out []byte) (textproto.MIMEHeader, []byte) {
	rd := textproto.NewReader(bufio.NewReader(bytes.NewReader(out)))
	if _, err := rd.ReadLine(); err != nil { // status line
		return nil, nil
	}
	head, _ := rd.ReadMIMEHeader()
	body, _ := io.ReadAll(rd.R)
	return head, body
}

func (r *run) status(account string, state finding.State, format string, args ...any) {
	r.scopedStatus(account, "", state, format, args...)
}

// scopedStatus is a status about one part of an account; see finding.Status.
func (r *run) scopedStatus(account, scope string, state finding.State, format string, args ...any) {
	r.emit.Status(finding.Status{Account: account, Scope: scope, State: state, Detail: fmt.Sprintf(format, args...)})
}

func account(name string) string { return "github:" + name }

// errBudget is returned instead of running a request once the budget is spent.
var errBudget = errors.New("rate limit budget spent")

// gh runs one read-only `gh api` request, with an optional flag (--include or --paginate), and
// returns its stdout. Each call costs one unit of the budget, except /rate_limit, which GitHub
// does not count; a paginated call counts once, which the reserve absorbs.
func (r *run) gh(ctx context.Context, flag, path string) ([]byte, error) {
	if path != "/rate_limit" && r.budget.Add(-1) < 0 {
		return nil, errBudget
	}
	args := []string{"api", "--method", "GET"}
	if flag != "" {
		args = append(args, flag)
	}
	out, err := cli.Guard(readOnly, r.c.Run).Run(ctx, append(args, path)...)
	if err != nil {
		return nil, wrapError(path, err)
	}
	return out, nil
}

// get decodes one object; list decodes every page of a paginated array.
func (r *run) get(ctx context.Context, path string, out any) error {
	raw, err := r.gh(ctx, "", path)
	if err != nil {
		return err
	}
	return decodeJSON(path, raw, out)
}

func list[T any](ctx context.Context, r *run, path string) ([]T, error) {
	raw, err := r.gh(ctx, "--paginate", path)
	if err != nil {
		return nil, err
	}
	// gh --paginate prints one JSON array per page, one after the other.
	var all []T
	dec := json.NewDecoder(bytes.NewReader(raw))
	for dec.More() {
		var page []T
		if err := dec.Decode(&page); err != nil {
			return nil, fmt.Errorf("gh api %s: unexpected output: %w", path, err)
		}
		all = append(all, page...)
	}
	return all, nil
}

func decodeJSON(path string, raw []byte, out any) error {
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("gh api %s: unexpected output: %w", path, err)
	}
	return nil
}

// apiError is a request GitHub answered with an error status.
type apiError struct {
	path   string
	code   int
	reason string
	err    error
}

func (e *apiError) Error() string {
	return fmt.Sprintf("gh api %s: HTTP %d: %s", e.path, e.code, e.reason)
}

func (e *apiError) Unwrap() error { return e.err }

var (
	httpCodeRE  = regexp.MustCompile(`^gh: (.*) \(HTTP (\d{3})\)\s*$`)
	signedOutRE = regexp.MustCompile(`(?i)gh auth login|not logged in`)
	rateLimitRE = regexp.MustCompile(`(?i)rate limit`)
)

// wrapError names the path in a failure, and reads gh's last stderr line, "gh: <message> (HTTP
// <code>)", into an *apiError when there is one.
func wrapError(path string, err error) error {
	var ce *cli.Error
	if errors.As(err, &ce) {
		lines := strings.Split(strings.TrimSpace(ce.Stderr), "\n")
		if m := httpCodeRE.FindStringSubmatch(lines[len(lines)-1]); m != nil {
			code, _ := strconv.Atoi(m[2])
			return &apiError{path: path, code: code, reason: m[1], err: err}
		}
	}
	return fmt.Errorf("gh api %s: %w", path, err)
}

func asAPIError(err error) (*apiError, bool) {
	var e *apiError
	ok := errors.As(err, &e)
	return e, ok
}

func rateLimited(err error) bool {
	if errors.Is(err, errBudget) {
		return true
	}
	e, ok := asAPIError(err)
	return ok && (e.code == 429 || e.code == 403 && rateLimitRE.MatchString(e.reason))
}

// denied is GitHub refusing a resource the token cannot see: 403, or 404, which GitHub returns for
// things that exist but are hidden from the caller.
func denied(err error) bool {
	e, ok := asAPIError(err)
	return ok && (e.code == 403 || e.code == 404) && !rateLimited(err)
}

func notFound(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.code == 404
}

// stateOf maps a failure to the status the owner acts on.
func stateOf(err error) finding.State {
	var ce *cli.Error
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return finding.StateUnsupported
	case errors.As(err, &ce) && signedOutRE.MatchString(ce.Stderr):
		return finding.StateSignedOut
	}
	if e, ok := asAPIError(err); ok && e.code == 401 {
		return finding.StateReauth
	}
	return finding.StateError
}

// describe turns a failure into a detail that says what to do next.
func describe(err error, fallback string) string {
	switch stateOf(err) {
	case finding.StateUnsupported:
		return "the gh CLI is not installed: install it (https://cli.github.com) and run `gh auth login`"
	case finding.StateSignedOut:
		return "gh is not signed in: run `gh auth login -h github.com`"
	case finding.StateReauth:
		return "gh's token was rejected: run `gh auth login -h github.com` again"
	}
	if rateLimited(err) {
		return "GitHub API rate limit reached: run again after the hourly reset"
	}
	if e, ok := asAPIError(err); ok {
		return fmt.Sprintf("gh api %s returned HTTP %d (%s): %s", e.path, e.code, e.reason, fallback)
	}
	return fmt.Sprintf("%v: %s", err, fallback)
}
