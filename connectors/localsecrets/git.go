package localsecrets

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/gitlocal"
	"github.com/segurata/segurata/internal/secretrisk"
)

type gitCache struct {
	mu     sync.Mutex
	roots  map[string]string          // dir -> repository root ("" when none)
	files  map[string]map[string]bool // root -> tracked absolute paths
	remote map[string]bool
}

// rootOf is the closest folder holding .git, from dir up to the home folder.
func (s *scan) rootOf(dir string) string {
	if !strings.HasPrefix(dir, s.home+string(filepath.Separator)) {
		return ""
	}
	if r, ok := s.git.roots[dir]; ok {
		return r
	}
	r := ""
	if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
		r = dir
	} else {
		r = s.rootOf(filepath.Dir(dir))
	}
	s.git.roots[dir] = r
	return r
}

func (s *scan) repoRoot(abs string) string {
	s.git.mu.Lock()
	defer s.git.mu.Unlock()
	return s.rootOf(filepath.Dir(abs))
}

// trackedFile says whether git tracks the file and the repository has a remote. A repository git
// cannot list is reported failed once, not taken for one that tracks nothing.
func (s *scan) trackedFile(abs string) (tracked, remote bool) {
	s.git.mu.Lock()
	defer s.git.mu.Unlock()
	root := s.rootOf(filepath.Dir(abs))
	if root == "" {
		return false, false
	}
	files, ok := s.git.files[root]
	if !ok {
		var err error
		if files, err = s.lsFiles(root); err != nil {
			s.emit.Status(finding.Status{Account: s.tilde(root), Scope: filesScope, State: finding.StateError,
				Detail: "git ls-files: " + err.Error() + ": whether its files are tracked is unknown"})
		}
		s.git.files[root] = files // nil after a failure: asked once per run
	}
	if !files[abs] {
		return false, false
	}
	return true, s.hasRemoteLocked(root)
}

func (s *scan) lsFiles(root string) (map[string]bool, error) {
	out, err := guardGit(s.c.Git).Run(s.ctx, append([]string{gitDirArg(root), "--work-tree=" + root, "ls-files", "-z"}, gitlocal.WholeTree()...)...)
	if err != nil {
		return nil, err
	}
	files := map[string]bool{}
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files[filepath.Join(root, f)] = true
		}
	}
	return files, nil
}

func (s *scan) hasRemote(root string) bool {
	s.git.mu.Lock()
	defer s.git.mu.Unlock()
	return s.hasRemoteLocked(root)
}

func (s *scan) hasRemoteLocked(root string) bool {
	if r, ok := s.git.remote[root]; ok {
		return r
	}
	r := configHasRemote(gitConfigPath(root))
	s.git.remote[root] = r
	return r
}

// gitConfigPath follows the .git file of worktrees and submodules to the common git directory.
func gitConfigPath(root string) string {
	dotgit := filepath.Join(root, ".git")
	st, err := os.Stat(dotgit)
	if err != nil {
		return ""
	}
	dir := dotgit
	if !st.IsDir() {
		raw, err := os.ReadFile(dotgit)
		if err != nil {
			return ""
		}
		gd := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "gitdir:"))
		if !filepath.IsAbs(gd) {
			gd = filepath.Join(root, gd)
		}
		dir = gd
		if c, err := os.ReadFile(filepath.Join(gd, "commondir")); err == nil {
			cd := strings.TrimSpace(string(c))
			if !filepath.IsAbs(cd) {
				cd = filepath.Join(gd, cd)
			}
			dir = cd
		}
	}
	return filepath.Join(dir, "config")
}

func configHasRemote(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(strings.TrimSpace(sc.Text()), "[remote ") {
			return true
		}
	}
	return false
}

// repos are the git repositories under repos_root (a .git directory at most six levels down),
// skipping dependency folders, plus ~/.claude when it is one. The tree is walked once per run.
func (s *scan) repos() []string {
	s.repoOnce.Do(func() { s.repoList = s.findRepos() })
	return s.repoList
}

func (s *scan) findRepos() []string {
	var out []string
	_ = filepath.WalkDir(s.src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(s.src, p)
		depth := len(strings.Split(rel, string(filepath.Separator)))
		switch d.Name() {
		case ".git":
			out = append(out, filepath.Dir(p))
			return filepath.SkipDir
		case "node_modules", "deps":
			return filepath.SkipDir
		}
		if rel != "." && depth >= 6 {
			return filepath.SkipDir
		}
		return nil
	})
	if st, err := os.Stat(s.h(".claude/.git")); err == nil && st.IsDir() {
		out = append(out, s.h(".claude"))
	}
	sort.Strings(out)
	return out
}

// leak is the part of a gitleaks finding this connector reads.
type leak struct {
	RuleID    string
	File      string
	StartLine int
	Secret    string
	Match     string
	Line      string // in gitleaks versions that report it
	Commit    string
	Date      string
	Email     string // the commit's author
}

// gitleaksRules maps gitleaks rules onto this connector's types; others keep their id.
var gitleaksRules = map[string]string{
	"aws-access-token":        "aws-access-key-id",
	"gcp-api-key":             "google-api-key",
	"stripe-access-token":     "stripe-live",
	"openai-api-key":          "openai-legacy",
	"anthropic-api-key":       "anthropic",
	"anthropic-admin-api-key": "anthropic",
	"slack-webhook-url":       "slack-webhook",
	"slack-bot-token":         "slack-token",
	"slack-user-token":        "slack-token",
	"slack-app-token":         "slack-token",
	"slack-legacy-token":      "slack-token",
	"notion-api-token":        "notion",
	"cloudflare-api-key":      "cloudflare-token",
	"telegram-bot-api-token":  "telegram-bot",
	"github-pat":              "github",
	"github-oauth":            "github",
	"github-app-token":        "github",
	"github-refresh-token":    "github",
	"github-fine-grained-pat": "github-pat",
	"gitlab-pat":              "gitlab",
	"sendgrid-api-token":      "sendgrid",
	"npm-access-token":        "npm-token",
	"sentry-access-token":     "sentry-token",
	"jwt":                     "jwt",
}

// eachRepo runs fn on every repository, gitleaks_workers at a time, until the run is cancelled.
func (s *scan) eachRepo(fn func(repo string)) {
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range s.cfg.workers {
		wg.Go(func() {
			for repo := range jobs {
				fn(repo)
			}
		})
	}
	for _, r := range s.repos() {
		if s.ctx.Err() != nil {
			break
		}
		jobs <- r
	}
	close(jobs)
	wg.Wait()
}

// gitleaksAll scans every repository's history, each with its own timeout.
func (s *scan) gitleaksAll() (repos, failed int) {
	s.emit.Log(fmt.Sprintf("gitleaks: %d repositories, %d at a time", len(s.repos()), s.cfg.workers))
	var n atomic.Int64
	s.eachRepo(func(repo string) {
		if err := s.gitleaks(repo); err != nil {
			n.Add(1)
			s.emit.Status(finding.Status{Account: s.tilde(repo), Scope: historyScope(s.tilde(repo)), State: finding.StateError, Detail: "gitleaks: " + err.Error()})
		}
	})
	return len(s.repos()), int(n.Load())
}

// runGitleaks scans the commits logOpts names (all when empty), the report piped to this process
// so values never reach a file or the terminal. It returns the prepared leaks and how many were omitted.
func (s *scan) runGitleaks(repo, logOpts string) ([]cachedLeak, int, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.timeout)
	defer cancel()
	secs := strconv.Itoa(int(s.cfg.timeout.Seconds()))
	if logOpts == "" {
		logOpts = gitleaksDefaultLogOpts
	}
	args := []string{"git", "--no-banner", "--log-level", "error", "--no-color", "--exit-code", "0",
		"--timeout", secs, "--report-format", "json", "--report-path", "-", "--log-opts", gitLogSafety + " " + logOpts}
	out, err := guardGitleaks(s.c.Gitleaks).Run(ctx, append(args, repo)...)
	if ctx.Err() == context.DeadlineExceeded {
		return nil, 0, fmt.Errorf("timed out after %s (raise gitleaks_timeout)", s.cfg.timeout)
	}
	if err != nil {
		return nil, 0, err
	}
	var leaks []leak
	if err := json.Unmarshal(out, &leaks); err != nil {
		return nil, 0, fmt.Errorf("unreadable report: %v", err)
	}
	markAWSSecretLeaks(leaks)
	var found []cachedLeak
	omitted := 0
	for _, l := range leaks {
		c, ok, dropped := s.prepareLeak(repo, l)
		switch {
		case dropped:
			omitted++
		case ok:
			found = append(found, c)
		}
	}
	return found, omitted, nil
}

// prepareLeak turns one gitleaks finding into evidence: ok is false for a non-secret, dropped true
// when the evidence would have held the value.
func (s *scan) prepareLeak(repo string, l leak) (c cachedLeak, ok, dropped bool) {
	ev := secretrisk.Evidence{Source: "gitleaks", Kind: "repo", Line: l.StartLine, Tracked: true,
		Repo: s.tilde(repo), Commit: leading(l.Commit, 10), Date: leading(l.Date, 10)}
	value := l.Secret
	if value == "" || value == "REDACTED" {
		return c, false, false
	}
	p := classifyValue(value)
	if p == nil && l.RuleID == awsSecretType {
		p = awsSecretKey
	}
	switch {
	case l.RuleID == "private-key" || strings.Contains(value, "PRIVATE KEY-----"):
		body := pemBody(value)
		if len(body) < 40 {
			return c, false, false
		}
		label := pemLabel(value)
		ev.Type, ev.Redacted, ev.Note, ev.Encrypted = privateKeyType, "PEM", label, pemEncrypted(label, value, body)
		value = body
	case p != nil:
		v, ok := judge(p, value, "", s.now)
		if !ok {
			return c, false, false
		}
		ev.Type, ev.Redacted, ev.Note, ev.Public = p.typ, secretrisk.Redact(p.typ, p.prefix, value), v.note, v.public
		ev.Sample = sampleValue(value)
		c.Expires = v.expires
	default:
		if placeholder.MatchString(value) {
			return c, false, false
		}
		ev.Type = l.RuleID
		if t, ok := gitleaksRules[l.RuleID]; ok {
			ev.Type = t
		}
		ev.Redacted = secretrisk.Redact(ev.Type, "", value)
		ev.Note, ev.Public = publicValue(value)
		ev.Sample = sampleValue(value)
	}
	ev.Claims = leakClaims(l, ev)
	ev, ok = s.prepare(filepath.Join(repo, l.File), ev, value)
	if !ok {
		return c, false, true
	}
	c.Evidence = ev
	return c, true, false
}

var leakKeyName = regexp.MustCompile(`^["'\s]*([A-Za-z0-9_.-]+)`)

// markAWSSecretLeaks makes aws-secret-key the generic-api-key leaks the working-tree scan would
// call one (gitleaks has no rule): a secret_access_key name, or a secret-ish one near a key id of
// the same file and commit.
func markAWSSecretLeaks(leaks []leak) {
	for i, l := range leaks {
		if l.RuleID != "generic-api-key" || !awsSecretShaped(l.Secret) {
			continue
		}
		var name string
		if m := leakKeyName.FindStringSubmatch(l.Match); m != nil {
			name = m[1]
		}
		if awsSecretNamed.MatchString(name) || awsSecretNearKeyID(name, l.Secret) && keyIDLeakNear(leaks, l) {
			leaks[i].RuleID = awsSecretType
		}
	}
}

func keyIDLeakNear(leaks []leak, l leak) bool {
	for _, k := range leaks {
		if k.File == l.File && k.Commit == l.Commit && pairableKeyID(k.Secret) && nearKeyID([]int{k.StartLine}, l.StartLine) {
			if p := classifyValue(k.Secret); p != nil && p.typ == "aws-access-key-id" {
				return true
			}
		}
	}
	return false
}

var errGitUnderGitleaks = errors.New("git failed under gitleaks")

// gitleaksStderr fails a run that exited 0 after the git under it failed (a bad revision, a
// corrupt object), which gitleaks only logs: caching it would mark the commits scanned.
func gitleaksStderr(stderr string) error {
	for _, l := range strings.Split(stderr, "\n") {
		if _, msg, ok := strings.Cut(l, " ERR [git] "); ok && (strings.HasPrefix(msg, "fatal:") || strings.HasPrefix(msg, "error:")) {
			return errGitUnderGitleaks
		}
	}
	return nil
}

const gitleaksDefaultLogOpts = "--full-history --all"

func leading(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
