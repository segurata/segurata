// Package github inventories, through the authenticated `gh` CLI and only GETs on allowlisted
// paths, the account's 2FA, the organizations it owns and the repositories it administers. OAuth
// apps, GitHub Apps, sessions and the account's keys belong to the connected-apps connector.
// Remediations write through `gh api` only after a confirmed plan, with their own allowlist.
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
)

const (
	defaultMaxRepos = 500
	// rateReserve is the part of the hourly quota left for the owner's other tools.
	rateReserve = 300
	concurrency = 4
	web         = "https://github.com"
)

type Connector struct {
	Run  cli.Runner         // gh, behind the read-only guard
	Exec connector.Executor // runs a confirmed remediation; nil is connector.System
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
		Theme:    finding.ThemeGitHub,
		Covers:   []finding.Area{{ID: "github-owner-2fa", Scope: "user:"}},
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

// start reads the token's scopes and the rate limit in one request GitHub does not count. It
// returns false when nothing else can run.
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

func (r *run) scopedStatus(account, scope string, state finding.State, format string, args ...any) {
	r.emit.Status(finding.Status{Account: account, Scope: scope, State: state, Detail: fmt.Sprintf(format, args...)})
}

func account(name string) string { return "github:" + name }

var errBudget = errors.New("rate limit budget spent")

// gh spends one unit of the budget per call, except on /rate_limit, which GitHub does not count;
// the reserve absorbs the extra pages of a paginated call.
func (r *run) gh(ctx context.Context, flag, path string) ([]byte, error) {
	if path != "/rate_limit" && r.budget.Add(-1) < 0 {
		return nil, errBudget
	}
	return ghGet(ctx, r.c.Run, flag, path)
}

func ghGet(ctx context.Context, run cli.Runner, flag, path string) ([]byte, error) {
	args := []string{"api", "--method", "GET"}
	if flag != "" {
		args = append(args, flag)
	}
	out, err := cli.Guard(readOnly, run).Run(ctx, append(args, path)...)
	if err != nil {
		return nil, wrapError(path, err)
	}
	return out, nil
}

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
	// gh --paginate prints one JSON array per page.
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

// wrapError reads gh's last stderr line, "gh: <message> (HTTP <code>)", into an *apiError.
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

// denied counts 404 too: GitHub answers it for resources hidden from the caller.
func denied(err error) bool {
	e, ok := asAPIError(err)
	return ok && (e.code == 403 || e.code == 404) && !rateLimited(err)
}

func notFound(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.code == 404
}

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
