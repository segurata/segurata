// Package localsecrets inventories plaintext secrets on this machine: credential and .env files,
// shell and agent config, histories, logs, agent transcripts, git history (gitleaks), committed
// database dumps and SSH keys without a passphrase. Read-only. No value leaves the process:
// findings carry a redacted hint and an HMAC fingerprint, and each is checked not to contain it.
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

	"github.com/segurata/segurata/connectors/internal/awsfiles"
	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/liveness"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
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
	// Every runner goes through its read-only guard (guards.go).
	RG, Gitleaks, Git, SSHKeygen cli.Runner
	LookPath                     func(string) (string, error)
	Home                         func() (string, error)
	KeyPath                      func(home string) string
	// CacheDir holds the git history caches; the other caches sit beside it.
	CacheDir func(home string) string
	Now      func() time.Time

	// GitHead peeks at blobs and GH reads repository visibility and owners; nil skips them.
	GitHead, GH cli.Runner

	// AWS and SSH run the liveness lookups of lone key ids and private keys; nil skips them.
	AWS, SSH cli.Runner
	// AWSIssuers names the aws profiles that hold a non-AWS key (R2), which the lookups skip.
	AWSIssuers func() map[string]awsfiles.Provider

	// NewChecker replaces the real liveness checker in tests.
	NewChecker func(home string, cfg liveness.Config) *liveness.Checker
}

func New() *Connector {
	return &Connector{
		RG:         cli.Exec{Path: "rg", Timeout: time.Hour},
		Gitleaks:   cli.Exec{Path: "gitleaks", Timeout: 24 * time.Hour, Env: gitEnv, StderrCheck: gitleaksStderr}, // gitleaks_timeout bounds each repository
		Git:        cli.Exec{Path: "git", Timeout: 2 * time.Minute, Env: gitEnv},
		SSHKeygen:  cli.Exec{Path: "ssh-keygen", Timeout: 30 * time.Second},
		GitHead:    headExec{Path: "git", Limit: dumpPeekSize, Timeout: 30 * time.Second, Env: gitEnv},
		GH:         cli.Exec{Path: "gh", Timeout: 30 * time.Second, Env: []string{"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "NO_COLOR=1"}},
		AWS:        cli.Exec{Path: "aws", Timeout: 2 * time.Minute, Env: []string{"AWS_PAGER="}},
		AWSIssuers: awsfiles.Issuers,
		SSH:        cli.Exec{Path: "ssh", Timeout: 30 * time.Second},
		LookPath:   exec.LookPath,
		Home:       os.UserHomeDir,
		KeyPath:    fingerprint.DefaultPath,
		CacheDir:   defaultCacheDir,
		Now:        time.Now,
	}
}

func init() { connector.Register(New()) }

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     name,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Plaintext secrets in config, .env files, histories, logs, agent transcripts, git history; database dumps committed to git; SSH keys without a passphrase",
		Needs:    []string{"cli:rg", "cli:gitleaks (optional)", "cli:git", "cli:ssh-keygen", "cli:gh (optional)", "cli:aws (optional)", "cli:ssh (optional)"},
		Timeout:  "6h", // an hour per ripgrep pass, gitleaks_timeout per repository
	}
}

type settings struct {
	reposRoot   string          // repos_root, default ~/src
	skipHistory bool            // skip_git_history
	workers     int             // gitleaks_workers
	timeout     time.Duration   // gitleaks_timeout, per repository
	gitCache    bool            // git_cache
	dumps       dumpMode        // data_dumps
	emitNoise   bool            // emit_noise
	ownedOwners []string        // owned_owners
	liveness    liveness.Config // liveness
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
	if s.liveness, err = liveness.ParseConfig(cfg["liveness"]); err != nil {
		return s, err
	}
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
		wg.Go(func() { s.rg(pass) })
	}
	wg.Go(s.byName)
	if cfg.dumps == dumpsOn {
		wg.Go(s.dumpsAll)
	}
	var repos, failed int
	if history {
		wg.Go(func() { repos, failed = s.gitleaksAll() })
	}
	wg.Wait()
	s.sshKeys()
	if ctx.Err() != nil {
		return ctx.Err()
	}

	findings, noise := s.findings()
	live := s.checkLiveness(ctx, findings, req.Known)
	// Emitted even when the run ends during the liveness check: the sink marks it interrupted.
	for _, f := range findings {
		emit.Finding(f)
	}
	if sum, ok := noise.summary(); ok {
		emit.Finding(sum)
	}
	if ctx.Err() != nil {
		return ctx.Err()
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
	if n := len(s.unreadable); n > 0 {
		detail += fmt.Sprintf("; %d unreadable paths skipped", n)
	}
	detail += noise.String() + live
	if cfg.dumps == dumpsOff {
		emit.Status(finding.Status{Account: localAccount, State: finding.StateOK, Detail: detail})
		return nil
	}
	return s.emitDumps(finding.Status{Account: localAccount, State: finding.StateOK, Detail: detail})
}

type scan struct {
	ctx  context.Context
	c    *Connector
	home string
	src  string
	cfg  settings
	fp   fingerprint.Key
	now  time.Time
	emit connector.Emitter

	mu         sync.Mutex
	rows       map[string]*secretrisk.Evidence // one secret at one location
	omitted    int
	unreadable map[string]bool // paths ripgrep was not allowed to read

	held heldValues

	git   gitCache
	own   ownership
	nb    notebooks
	stats historyStats
	dumps dumpState

	repoOnce sync.Once
	repoList []string

	glOnce    sync.Once // the gitleaks version, shared by every repository
	glVersion string
	glErr     error
}

func newScan(ctx context.Context, c *Connector, home string, cfg settings, fp fingerprint.Key, emit connector.Emitter) *scan {
	return &scan{ctx: ctx, c: c, home: home, src: cfg.reposRoot, cfg: cfg, fp: fp, now: c.Now(), emit: emit,
		rows: map[string]*secretrisk.Evidence{}, git: gitCache{roots: map[string]string{}, files: map[string]map[string]bool{}, remote: map[string]bool{}}}
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

// modeOf is the file's mode for other accounts: a class reads it only if every parent folder up
// to root lets that class through, so a 644 file in a 700 home is closed. fileMode is the file's
// own mode, set only when it differs.
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
	case isTrail(ev.Kind):
		return "2-trail"
	case othersCanRead(ev.Mode):
		return "1-readable"
	}
	return "3-local"
}

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

// add records one secret at one location. value is fingerprinted, never stored.
func (s *scan) add(abs string, ev secretrisk.Evidence, value string) {
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

// prepare completes the evidence of one secret at one location, or reports false when it would
// contain the value itself.
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
	s.attribute(abs, &ev, value)
	if len(value) >= 6 {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), value) {
			return ev, false
		}
	}
	s.mu.Lock()
	s.hold(abs, ev, value)
	s.mu.Unlock()
	return ev, true
}

func (s *scan) store(ev secretrisk.Evidence) {
	key := strings.Join([]string{ev.Source, ev.Path, ev.Type, ev.Fingerprint}, "\x00")
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[key]; ok {
		r.Count++
		return
	}
	ev.Count = 1
	s.rows[key] = &ev
}

// findings turns the rows into findings sorted by resource, after the steps that need every row
// (rows.go). Without emit_noise, noise is only counted.
func (s *scan) findings() ([]finding.Finding, noiseCounts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa := map[string]bool{} // a service-account key is not reported again as a private key
	for _, ev := range s.rows {
		if ev.Type == "gcp-service-account" {
			sa[fileValueKey(*ev)] = true
		}
	}
	var evs []secretrisk.Evidence
	for _, ev := range s.rows {
		if ev.Type == privateKeyType && sa[fileValueKey(*ev)] {
			continue
		}
		evs = append(evs, *ev)
	}
	evs, folded := collapseTemporaryAWS(markReused(inheritForkUpstream(evs)))
	// Noise is still emitted when it is one more copy of a real secret, or a third-party copy that
	// names an account the tracker may attribute to the owner.
	fs := make([]finding.Finding, len(evs))
	real := map[string]bool{}
	for i, ev := range evs {
		fs[i] = toFinding(ev)
		if !isNoise(fs[i]) {
			real[ev.Fingerprint] = true
		}
	}
	noise := noiseCounts{}
	var out []finding.Finding
	for i, ev := range evs {
		attributable := secretrisk.UpstreamOnly(ev) && ev.Claims.NamesAccount()
		if !s.cfg.emitNoise && isNoise(fs[i]) && !real[ev.Fingerprint] && !attributable {
			noise.add(ev)
			for _, f := range folded[ev.Fingerprint] {
				if !real[f.Fingerprint] {
					noise.name(f)
				}
			}
			continue
		}
		out = append(out, fs[i])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource.ID < out[j].Resource.ID })
	return out, noise
}

// isNoise is an exposure without a priority; an SSH key with a passphrase is an info setting.
func isNoise(f finding.Finding) bool {
	return f.Severity == finding.SevInfo && f.Kind == finding.KindExposure
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
	return finding.Finding{
		Account:     localAccount,
		Scope:       secretScope(ev),
		Resource:    finding.Resource{Type: "secret", ID: ev.Source + ":" + ev.Path + "#" + ev.Fingerprint, Name: t.Label},
		Kind:        kind,
		Severity:    secretrisk.SeverityOf(prio),
		Title:       title,
		Evidence:    ev.Map(),
		Remediation: remedy(summary, t.RotateURL, ev),
	}
}

// Scopes say which part of the machine a run left unread: the files, or one repository's history
// or dumps.
const filesScope = "files"

func historyScope(repo string) string { return "history:" + repo }
func dumpsScope(repo string) string   { return "dumps:" + repo }

func secretScope(ev secretrisk.Evidence) string {
	if ev.Source == "gitleaks" {
		return historyScope(ev.Repo)
	}
	return filesScope
}

// remedy offers a chmod 600 for a working file other users can read: ranked by the finding when
// they can now, low (grouped by top folder) when only a parent folder keeps them out. Noise gets
// no fix: closing a third-party file for its `password=` buys nothing.
func remedy(summary, url string, ev secretrisk.Evidence) finding.Remediation {
	r := finding.Remediation{Summary: summary, URL: url}
	if ev.Source == "gitleaks" || ev.Mode == "" || secretrisk.ImpactOf(ev) == secretrisk.Noise {
		return r
	}
	switch {
	case othersCanRead(ev.Mode):
		r.Action = connector.ActionChmod600
	case othersCanRead(ev.FileMode):
		r.Action, r.Severity, r.Group = connector.ActionChmod600, finding.SevLow, hardeningGroup(ev.Path)
		r.Summary += fmt.Sprintf(" The file itself is mode %s: only a closed parent folder keeps other users out, so `segurata remediate` can also close the file (chmod 600) in case that folder is opened later.", ev.FileMode)
	}
	return r
}

func othersCanRead(mode string) bool {
	return secretrisk.Where("", "", mode, false, false).Level == secretrisk.Shared
}

// hardeningGroup is the file's folder, cut at three levels under the home (~/src/acme/app).
func hardeningGroup(path string) string {
	parts := strings.Split(filepath.ToSlash(filepath.Dir(path)), "/")
	return "files in " + strings.Join(parts[:min(len(parts), 4)], "/")
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
