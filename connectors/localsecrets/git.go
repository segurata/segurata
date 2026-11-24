package localsecrets

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// gitCache remembers repository roots, their tracked files and whether they have a remote.
type gitCache struct {
	mu     sync.Mutex
	roots  map[string]string          // dir -> repository root ("" when none)
	files  map[string]map[string]bool // root -> tracked absolute paths
	remote map[string]bool
}

// rootOf walks up from dir, inside the home directory, to the closest folder holding .git.
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

// trackedFile says whether git tracks the file, and whether that repository has a remote.
func (s *scan) trackedFile(abs string) (tracked, remote bool) {
	s.git.mu.Lock()
	defer s.git.mu.Unlock()
	root := s.rootOf(filepath.Dir(abs))
	if root == "" {
		return false, false
	}
	files, ok := s.git.files[root]
	if !ok {
		files = map[string]bool{}
		out, err := guardGit(s.c.Git).Run(s.ctx, "--git-dir="+filepath.Join(root, ".git"), "--work-tree="+root, "ls-files", "-z")
		if err != nil {
			s.emit.Log("git ls-files " + s.tilde(root) + ": " + err.Error())
		}
		for _, f := range strings.Split(string(out), "\x00") {
			if f != "" {
				files[filepath.Join(root, f)] = true
			}
		}
		s.git.files[root] = files
	}
	if !files[abs] {
		return false, false
	}
	return true, s.hasRemoteLocked(root)
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

// gitConfigPath finds a repository's config file, following the .git file of worktrees and
// submodules to the common git directory.
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

// configHasRemote reads a git config file for a [remote "…"] section, without running git.
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

// repos finds git repositories under repos_root (a .git directory at most six levels down, as
// `find -maxdepth 6`), skipping dependency folders, plus ~/.claude when it is one.
func (s *scan) repos() []string {
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

// leak is the part of a gitleaks finding this connector reads. Match is left out on purpose.
type leak struct {
	RuleID    string
	File      string
	StartLine int
	Secret    string
	Commit    string
	Date      string
}

// gitleaksRules maps gitleaks rule ids onto this connector's types, for secrets its own patterns
// do not recognise whole. Other rules keep their gitleaks id.
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

// gitleaksAll scans every repository's history, a few at a time, each with its own timeout.
func (s *scan) gitleaksAll() (repos, failed int) {
	list := s.repos()
	s.emit.Log(fmt.Sprintf("gitleaks: %d repositories, %d at a time", len(list), s.cfg.workers))
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for range s.cfg.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repo := range jobs {
				if err := s.gitleaks(repo); err != nil {
					mu.Lock()
					failed++
					mu.Unlock()
					s.emit.Status(finding.Status{Account: s.tilde(repo), State: finding.StateError, Detail: "gitleaks: " + err.Error()})
				}
			}
		}()
	}
	for _, r := range list {
		if s.ctx.Err() != nil {
			break
		}
		jobs <- r
	}
	close(jobs)
	wg.Wait()
	return len(list), failed
}

// gitleaks runs one repository with the JSON report on stdout, so raw values only travel through
// a pipe into this process (never a file, never the terminal): each is fingerprinted and dropped.
func (s *scan) gitleaks(repo string) error {
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.timeout)
	defer cancel()
	secs := strconv.Itoa(int(s.cfg.timeout.Seconds()))
	out, err := guardGitleaks(s.c.Gitleaks).Run(ctx, "git", "--no-banner", "--log-level", "fatal", "--exit-code", "0",
		"--timeout", secs, "--report-format", "json", "--report-path", "-", repo)
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("timed out after %s (raise gitleaks_timeout)", s.cfg.timeout)
	}
	if err != nil {
		return err
	}
	var leaks []leak
	if err := json.Unmarshal(out, &leaks); err != nil {
		return fmt.Errorf("unreadable report: %v", err)
	}
	remote := s.hasRemote(repo)
	for _, l := range leaks {
		s.leak(repo, remote, l)
	}
	return nil
}

func (s *scan) leak(repo string, remote bool, l leak) {
	ev := secretrisk.Evidence{Source: "gitleaks", Kind: "repo", Line: l.StartLine, Tracked: true, Remote: remote,
		Repo: s.tilde(repo), Commit: truncate(l.Commit, 10), Date: truncate(l.Date, 10)}
	abs := filepath.Join(repo, l.File)
	value := l.Secret
	if value == "" || value == "REDACTED" {
		return
	}
	switch p := classifyValue(value); {
	case l.RuleID == "private-key" || strings.Contains(value, "PRIVATE KEY-----"):
		body := pemBody(value)
		if len(body) < 40 {
			return
		}
		label := pemLabel(value)
		ev.Type, ev.Redacted, ev.Note, ev.Encrypted = privateKeyType, "PEM", label, pemEncrypted(label, value, body)
		value = body
	case p != nil:
		v, ok := judge(p, value, "", s.now)
		if !ok {
			return
		}
		ev.Type, ev.Redacted, ev.Note, ev.Public = p.typ, secretrisk.Redact(p.typ, p.prefix, value), v.note, v.public
	default:
		if placeholder.MatchString(value) {
			return
		}
		ev.Type = l.RuleID
		if t, ok := gitleaksRules[l.RuleID]; ok {
			ev.Type = t
		}
		ev.Redacted = secretrisk.Redact(ev.Type, "", value)
	}
	s.add(abs, ev, value)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
