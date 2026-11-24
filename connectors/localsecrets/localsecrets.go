// Package localsecrets inventories plaintext secrets on this machine: .env and credential files,
// shell and agent config, shell histories, logs, agent transcripts, git history (gitleaks) and SSH
// keys without a passphrase. Read-only. See docs/secrets.md for what to do with each finding and
// docs/architecture.md, "Rotation ledger", for how findings become rotation items.
//
// No secret value ever leaves the process: findings carry a redacted hint and an HMAC fingerprint
// (internal/fingerprint), and each one is checked not to contain the value before it is emitted.
package localsecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/secretrisk"
)

const (
	name           = "local-secrets"
	localAccount   = "local"
	fixDoc         = "docs/secrets.md"
	defaultWorkers = 6
	defaultTimeout = 10 * time.Minute
)

type Connector struct {
	// The tools this connector runs, each behind its own read-only guard (guards.go). Tests
	// replace them with canned output.
	RG, Gitleaks, Git, SSHKeygen cli.Runner
	LookPath                     func(string) (string, error)
	Home                         func() (string, error)
	// KeyPath is the fingerprint key file for a home directory.
	KeyPath func(home string) string
	// CacheDir holds the per-repository git history caches for a home directory (historycache.go);
	// the data-dump caches live in a sibling datadumps directory.
	CacheDir func(home string) string
	Now      func() time.Time

	// GitHead reads the first bytes of a blob (headExec) and GH asks GitHub a repository's
	// visibility, both for the data-dump check (dumpscan.go). Either may be nil: no peek, no gh.
	GitHead, GH cli.Runner
}

func New() *Connector {
	return &Connector{
		RG:        cli.Exec{Path: "rg", Timeout: time.Hour},
		Gitleaks:  cli.Exec{Path: "gitleaks", Timeout: 24 * time.Hour}, // bounded per repo by the context
		Git:       cli.Exec{Path: "git", Timeout: 2 * time.Minute},
		SSHKeygen: cli.Exec{Path: "ssh-keygen", Timeout: 30 * time.Second},
		GitHead:   headExec{Path: "git", Limit: dumpPeekSize, Timeout: 30 * time.Second},
		GH:        cli.Exec{Path: "gh", Timeout: 30 * time.Second, Env: []string{"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "NO_COLOR=1"}},
		LookPath:  exec.LookPath,
		Home:      os.UserHomeDir,
		KeyPath:   fingerprint.DefaultPath,
		CacheDir:  DefaultCacheDir,
		Now:       time.Now,
	}
}

func init() { connector.Register(New()) }

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     name,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Plaintext secrets in config, .env files, histories, logs, agent transcripts, git history; database dumps committed to git; SSH keys without a passphrase",
		Needs:    []string{"cli:rg", "cli:gitleaks (optional)", "cli:git", "cli:ssh-keygen", "cli:gh (optional)"},
	}
}

// settings is the connector's config block.
type settings struct {
	reposRoot   string        // repos_root, default ~/src
	skipHistory bool          // skip_git_history
	workers     int           // gitleaks_workers
	timeout     time.Duration // gitleaks_timeout, per repository
	gitCache    bool          // git_cache: scan only commits added since the last run
	dumps       dumpMode      // data_dumps: true, false or "only"
	emitNoise   bool          // emit_noise: emit noise findings too, not only their counts
	ownedOwners []string      // owned_owners: GitHub users and organizations that are the owner's
}

func parseSettings(cfg map[string]any, home string) (settings, error) {
	s := settings{reposRoot: filepath.Join(home, "src"), workers: defaultWorkers, timeout: defaultTimeout, gitCache: true}
	if v, ok := cfg["repos_root"].(string); ok && v != "" {
		s.reposRoot = expandHome(v, home)
	}
	if v, ok := cfg["skip_git_history"].(bool); ok {
		s.skipHistory = v
	}
	if v, ok := cfg["git_cache"].(bool); ok {
		s.gitCache = v
	}
	if v, ok := cfg["emit_noise"].(bool); ok {
		s.emitNoise = v
	}
	if v, ok := cfg["owned_owners"]; ok {
		errOwners := fmt.Errorf("owned_owners must be a list of GitHub user or organization names")
		list, _ := v.([]any)
		if list == nil {
			return s, errOwners
		}
		for _, o := range list {
			name, ok := o.(string)
			if !ok || name == "" {
				return s, errOwners
			}
			s.ownedOwners = append(s.ownedOwners, name)
		}
	}
	var err error
	if s.dumps, err = parseDumpMode(cfg["data_dumps"]); err != nil {
		return s, err
	}
	if v, ok := cfg["gitleaks_workers"].(float64); ok && v >= 1 {
		s.workers = int(v)
	}
	if v, ok := cfg["gitleaks_timeout"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return s, fmt.Errorf("gitleaks_timeout %q is not a duration such as \"10m\"", v)
		}
		s.timeout = d
	}
	return s, nil
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	home, err := c.Home()
	if err != nil {
		return err
	}
	cfg, err := parseSettings(req.Config, home)
	if err != nil {
		return err
	}
	fp, err := fingerprint.Load(c.KeyPath(home))
	if err != nil {
		return fmt.Errorf("fingerprint key: %w", err)
	}
	if cfg.dumps == dumpsOnly {
		emit.Scope(filesScope, false, `data_dumps is "only"`)
		emit.Scope(historyScope("*"), false, `data_dumps is "only"`)
		s := newScan(ctx, c, home, cfg, fp, emit)
		s.dumpsAll()
		return s.emitDumps(finding.Status{Account: localAccount, State: finding.StateOK, Detail: "data_dumps only"})
	}
	if _, err := c.LookPath("rg"); err != nil {
		emit.Status(finding.Status{Account: localAccount, State: finding.StateUnsupported,
			Detail: "rg (ripgrep) is required: install it, respecting the 4-day quarantine"})
		return nil
	}
	_, glErr := c.LookPath("gitleaks")
	history := !cfg.skipHistory && glErr == nil
	switch {
	case cfg.skipHistory:
		emit.Scope(historyScope("*"), false, "skip_git_history is set")
	case glErr != nil:
		emit.Scope(historyScope("*"), false, "gitleaks is not installed")
	}
	if cfg.dumps == dumpsOff {
		emit.Scope(dumpsScope("*"), false, "data_dumps is false")
	}

	s := newScan(ctx, c, home, cfg, fp, emit)
	var wg sync.WaitGroup
	for _, pass := range s.passes(history) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.rg(pass)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.byName()
	}()
	if cfg.dumps == dumpsOn {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.dumpsAll()
		}()
	}
	var repos, failed int
	if history {
		wg.Add(1)
		go func() {
			defer wg.Done()
			repos, failed = s.gitleaksAll()
		}()
	}
	wg.Wait()
	s.sshKeys()
	if ctx.Err() != nil {
		return ctx.Err()
	}

	findings, noise := s.findings()
	for _, f := range findings {
		emit.Finding(f)
	}
	if sum, ok := noise.summary(); ok {
		emit.Finding(sum)
	}
	detail := fmt.Sprintf("%d findings", len(findings))
	switch {
	case history:
		detail += fmt.Sprintf("; gitleaks: %d repositories (%s), %d failed", repos, s.stats.String(), failed)
	case cfg.skipHistory:
		detail += "; git history skipped (skip_git_history)"
	default:
		detail += "; gitleaks is not installed: no git history scan, the whole working tree under repos_root was scanned instead"
	}
	if s.omitted > 0 {
		detail += fmt.Sprintf("; %d omitted because the value appeared in the path or note", s.omitted)
	}
	if s.selfSkipped > 0 {
		detail += fmt.Sprintf("; %d in segurata's own repositories skipped (test corpus)", s.selfSkipped)
	}
	detail += noise.String()
	if cfg.dumps == dumpsOff {
		emit.Status(finding.Status{Account: localAccount, State: finding.StateOK, Detail: detail})
		return nil
	}
	return s.emitDumps(finding.Status{Account: localAccount, State: finding.StateOK, Detail: detail})
}

// row is one secret at one location, aggregated over repeated matches.
type row struct{ ev secretrisk.Evidence }

// scan holds the state of one inventory run.
type scan struct {
	ctx  context.Context
	c    *Connector
	home string
	src  string
	cfg  settings
	fp   fingerprint.Key
	now  time.Time
	emit connector.Emitter

	mu          sync.Mutex
	rows        map[string]*row
	omitted     int
	selfSkipped int

	git   gitCache
	own   ownership
	nb    notebooks
	stats historyStats
	historyOnce
	dumps dumpState
}

func newScan(ctx context.Context, c *Connector, home string, cfg settings, fp fingerprint.Key, emit connector.Emitter) *scan {
	return &scan{ctx: ctx, c: c, home: home, src: cfg.reposRoot, cfg: cfg, fp: fp, now: c.Now(), emit: emit,
		rows: map[string]*row{}, git: gitCache{roots: map[string]string{}, files: map[string]map[string]bool{}, remote: map[string]bool{}}}
}

func (s *scan) h(p string) string { return filepath.Join(s.home, p) }

func (s *scan) tilde(p string) string {
	if p == s.home || strings.HasPrefix(p, s.home+string(filepath.Separator)) {
		return "~" + p[len(s.home):]
	}
	return p
}

var transcriptDirs = []string{".claude/projects", ".claude/history.jsonl", ".codex/sessions", ".codex/history.jsonl", ".cursor/projects", ".gemini/tmp"}
var historyFiles = []string{".zsh_history", ".bash_history", ".zsh_sessions", ".python_history", ".node_repl_history", ".psql_history", ".mysql_history", ".irb_history", ".sqlite_history", ".lesshst"}

func (s *scan) under(p string, rels []string) bool {
	for _, r := range rels {
		if strings.HasPrefix(p, s.h(r)) {
			return true
		}
	}
	return false
}

// kindOf classifies a path: agent transcript, shell history, log, file in a repository, or config.
func (s *scan) kindOf(p string) string {
	switch {
	case s.under(p, transcriptDirs):
		return "transcript"
	case s.under(p, historyFiles):
		return "history"
	case strings.HasSuffix(p, ".log") || s.under(p, []string{"Library/Logs", ".local/log"}):
		return "log"
	case strings.HasPrefix(p, s.src+string(filepath.Separator)):
		return "repo"
	}
	return "config"
}

// modeOf is the file's effective permissions for other accounts: the group and other read bits
// count only if every parent directory lets that class through (execute bit). A 644 file inside
// a 700 home folder is closed to everyone else. The walk stops at root (the home folder): above it
// are system folders that every account can traverse. fileMode is the file's own mode, set when
// the two differ so the evidence shows both.
func modeOf(p, root string) (effective, fileMode string) {
	st, err := os.Stat(p)
	if err != nil {
		return "", ""
	}
	perm := st.Mode().Perm()
	eff := perm
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		if ds, err := os.Stat(d); err == nil {
			if ds.Mode().Perm()&0o010 == 0 {
				eff &^= 0o070
			}
			if ds.Mode().Perm()&0o001 == 0 {
				eff &^= 0o007
			}
		}
		if d == root || filepath.Dir(d) == d {
			break
		}
	}
	effective = fmt.Sprintf("%o", eff)
	if eff != perm {
		fileMode = fmt.Sprintf("%o", perm)
	}
	return effective, fileMode
}

func bucketOf(ev secretrisk.Evidence) string {
	switch {
	case ev.Source == "ssh" && ev.Encrypted:
		return "ok"
	case ev.Tracked:
		return "0-git"
	case IsTrail(ev.Kind):
		return "2-trail"
	case secretrisk.Where("", "", ev.Mode, false, false).Level == secretrisk.Shared:
		return "1-readable"
	}
	return "3-local"
}

// fixFor is the docs/secrets.md anchor with the recommended fix.
func fixFor(ev secretrisk.Evidence) string {
	t, p := ev.Type, ev.Path
	hasAny := func(subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(p, x) {
				return true
			}
		}
		return false
	}
	pre := func(prefixes ...string) bool {
		for _, x := range prefixes {
			if strings.HasPrefix(t, x) {
				return true
			}
		}
		return false
	}
	rc := secretrisk.IsShellRC(p)
	var a string
	switch {
	case ev.Tracked:
		a = "in-git-always-rotate"
	case ev.Kind == "transcript":
		a = "agent-transcripts"
	case ev.Kind == "history":
		a = "shell-history"
	case ev.Kind == "log":
		a = "logs"
	case t == "ssh-key":
		a = "ssh-keys"
	case pre("aws") || hasAny("/.aws/"):
		a = "aws"
	case hasAny("gcloud", ".gemini") || pre("google", "oauth", "gcp"):
		a = "google-cloud-and-oauth"
	case pre("github", "gitlab") || strings.HasSuffix(p, ".netrc") || hasAny("/gh/"):
		a = "github-and-git"
	case pre("npm", "pypi", "rubygems", "docker") || strings.HasSuffix(p, ".npmrc") || hasAny(".docker/"):
		a = "package-registries-and-docker"
	case rc:
		a = "shell-variables-from-the-keychain"
	case hasAny(".claude", ".mcp", ".codex", ".cursor", ".config/opencode"):
		a = "mcp-servers-and-agents"
	case t == privateKeyType || t == "keystore" || t == "rails-master-key":
		a = "files-that-must-live-in-the-repo"
	default:
		a = "env-files"
	}
	return fixDoc + "#" + a
}

// add records one secret at one location. value is what gets fingerprinted (the raw secret, or the
// body of a PEM key); it never leaves this function.
func (s *scan) add(abs string, ev secretrisk.Evidence, value string) {
	if root := s.repoRoot(abs); root != "" && s.isSelf(root) {
		s.mu.Lock()
		s.selfSkipped++
		s.mu.Unlock()
		return
	}
	ev, ok := s.prepare(abs, ev, value)
	if !ok {
		s.omit(1)
		return
	}
	s.store(ev)
}

func (s *scan) omit(n int) {
	s.mu.Lock()
	s.omitted += n
	s.mu.Unlock()
}

// prepare completes the evidence of one secret at one location: kind, permissions, git status,
// fingerprint, bucket and fix. It reports false when the evidence would contain the value itself,
// so the caller drops it. value never leaves this function.
func (s *scan) prepare(abs string, ev secretrisk.Evidence, value string) (secretrisk.Evidence, bool) {
	if ev.Kind == "" {
		ev.Kind = s.kindOf(abs)
	}
	if ev.Source != "gitleaks" {
		ev.Mode, ev.FileMode = modeOf(abs, s.home)
		if !strings.Contains(abs, "/.git/") {
			ev.Tracked, ev.Remote = s.trackedFile(abs)
		}
		if ev.Tracked {
			ev.Origin = s.originOf(s.repoRoot(abs)).origin
		}
		if st, err := os.Stat(abs); err == nil {
			secretrisk.ExpireTemporaryAWS(&ev, st.ModTime(), s.now)
		}
	} else {
		secretrisk.ExpireTemporaryAWS(&ev, commitDay(ev.Date), s.now)
	}
	ev.Path = s.tilde(abs)
	ev.Fingerprint = s.fp.Of(value)
	ev.Bucket = bucketOf(ev)
	ev.Fix = fixFor(ev)
	if len(value) >= 6 {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), value) {
			return ev, false
		}
	}
	return ev, true
}

// store aggregates prepared evidence: the same secret at the same location counts once more.
func (s *scan) store(ev secretrisk.Evidence) {
	key := strings.Join([]string{ev.Source, ev.Path, ev.Type, ev.Fingerprint}, "\x00")
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[key]; ok {
		r.ev.Count++
		return
	}
	ev.Count = 1
	s.rows[key] = &row{ev: ev}
}

// findings turns the aggregated rows into findings, sorted by path, after the steps that need
// every row at once (rows.go): a private-key row is dropped when the same key in the same file was
// already reported as a GCP service account key; a fork's working copy of an inherited secret is
// the upstream's too; a third-party copy of a value the owner also holds counts as the owner's;
// temporary AWS credentials collapse to one finding per file. Noise findings are only counted
// unless emit_noise is set.
func (s *scan) findings() ([]finding.Finding, noiseCounts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa := map[string]bool{}
	for _, r := range s.rows {
		if r.ev.Type == "gcp-service-account" {
			sa[fileValueKey(r.ev)] = true
		}
	}
	var evs []secretrisk.Evidence
	for _, r := range s.rows {
		if r.ev.Type == privateKeyType && sa[fileValueKey(r.ev)] {
			continue
		}
		evs = append(evs, r.ev)
	}
	evs = collapseTemporaryAWS(markReused(inheritForkUpstream(evs)))
	noise := noiseCounts{}
	var out []finding.Finding
	for _, ev := range evs {
		f := toFinding(ev)
		if !s.cfg.emitNoise && f.Severity == finding.SevInfo && f.Kind == finding.KindExposure {
			noise.add(ev)
			continue
		}
		noise.emitted(ev)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource.ID < out[j].Resource.ID })
	return out, noise
}

func toFinding(ev secretrisk.Evidence) finding.Finding {
	t := secretrisk.TypeFor(ev.Type, ev.Redacted)
	spot := secretrisk.WhereEvidence(ev)
	prio := secretrisk.PriorityOf(secretrisk.ImpactOf(ev), spot.Level)
	where := ev.Path
	if ev.Line > 0 {
		where = fmt.Sprintf("%s:%d", ev.Path, ev.Line)
	}
	title := fmt.Sprintf("%s in %s", t.Label, where)
	if ev.Source == "gitleaks" {
		title = fmt.Sprintf("%s in the git history of %s (%s)", t.Label, ev.Repo, strings.TrimPrefix(ev.Path, ev.Repo+"/"))
	}
	kind := finding.KindExposure
	summary := remediation(prio, spot, ev)
	if ev.Source == "ssh" {
		if ev.Encrypted {
			kind, title = finding.KindSetting, fmt.Sprintf("SSH key %s has a passphrase", ev.Path)
		}
		summary = fmt.Sprintf("Add a passphrase (ssh-keygen -p -f %s) or replace the key with one that has it; see %s.", ev.Path, ev.Fix)
	}
	var evidence map[string]any
	raw, _ := json.Marshal(ev)
	_ = json.Unmarshal(raw, &evidence)
	return finding.Finding{
		Account:     localAccount,
		Scope:       secretScope(ev),
		Resource:    finding.Resource{Type: "secret", ID: ev.Source + ":" + ev.Path + "#" + ev.Fingerprint, Name: t.Label},
		Kind:        kind,
		Severity:    secretrisk.SeverityOf(prio),
		Title:       title,
		Evidence:    evidence,
		Remediation: finding.Remediation{Summary: summary, URL: t.RotateURL, Action: action(ev)},
	}
}

// Scopes of local-secrets findings, so a run that leaves part of the machine unread says which
// part: the files ripgrep and the name scan read, one repository's git history, one repository's
// data dumps. A failed gitleaks or dump scan names its repository's scope in its status.
const filesScope = "files"

func historyScope(repo string) string { return "history:" + repo }
func dumpsScope(repo string) string   { return "dumps:" + repo }

func secretScope(ev secretrisk.Evidence) string {
	if ev.Source == "gitleaks" {
		return historyScope(ev.Repo)
	}
	return filesScope
}

// action offers `segurata remediate` a chmod 600 for a working file other users can read. It
// closes the file; it does not make rotation unnecessary.
func action(ev secretrisk.Evidence) string {
	// Noise (generic matches, public or encrypted values) gets no fix: closing a third-party
	// source file because it contains `password=` buys nothing.
	if ev.Source == "gitleaks" || ev.Mode == "" || secretrisk.ImpactOf(ev) == secretrisk.Noise {
		return ""
	}
	if secretrisk.Where("", "", ev.Mode, false, false).Level != secretrisk.Shared {
		return ""
	}
	return remediate.ActionChmod600
}

func remediation(p secretrisk.Priority, spot secretrisk.Spot, ev secretrisk.Evidence) string {
	switch {
	case p == "":
		return fmt.Sprintf("Probably not a usable secret (generic match, public, expired or encrypted). If it is one, see %s.", ev.Fix)
	case spot.Level == secretrisk.Remote:
		return fmt.Sprintf("It left this machine: rotate it at the provider, then keep the new value out of plain files (%s).", ev.Fix)
	case spot.Level == secretrisk.Shared:
		return fmt.Sprintf("Rotate it, then move the new value to the Keychain or 1Password (%s). `segurata remediate` can close the file (chmod 600) meanwhile.", ev.Fix)
	}
	return fmt.Sprintf("Move it to the Keychain or 1Password and delete the plaintext copy (%s).", ev.Fix)
}
