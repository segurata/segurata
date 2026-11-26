package localsecrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
)

// A repository's history is scanned in full once; later runs scan `<new tips> --not <old tips>`
// and replay the cached leaks. A ref rewritten or deleted since (an old tip no longer reachable)
// and any change of format, gitleaks version or config or fingerprint key mean a full scan again.
// The cache holds prepared evidence only, never a value.

// historyCacheVersion goes up when the cached evidence of the same leaks would differ.
const historyCacheVersion = 2

var maxLogOpts = 256 << 10 // well under any OS argument limit

func (c *Connector) cacheRoot(home string) string { return filepath.Dir(c.CacheDir(home)) }

func defaultCacheDir(home string) string {
	return filepath.Join(home, ".cache", "segurata", "gitleaks")
}

type historyCache struct {
	Version int          `json:"version"`
	Repo    string       `json:"repo"`  // the file name is only its hash
	Rules   string       `json:"rules"` // gitleaks version and configuration
	Key     string       `json:"key"`   // changes with the fingerprint key
	Tips    []string     `json:"tips"`  // what the refs and HEAD pointed to
	Leaks   []cachedLeak `json:"leaks"`
	Omitted int          `json:"omitted,omitempty"`
}

// cachedLeak keeps a JWT's exp, so a token that expired since is judged as of today.
type cachedLeak struct {
	Evidence secretrisk.Evidence `json:"evidence"`
	Expires  int64               `json:"expires,omitempty"`
}

// evidence is the cached evidence as of now, with the repository's current remote and origin.
func (c cachedLeak) evidence(now time.Time, remote bool, origin string) secretrisk.Evidence {
	ev := c.Evidence
	ev.Remote, ev.Origin = remote, origin
	if c.Expires > 0 && time.Unix(c.Expires, 0).Before(now) && !strings.Contains(ev.Note, "expired") {
		ev.Note = strings.TrimSpace(ev.Note + " expired")
		ev.Public = true
	}
	secretrisk.ExpireTemporaryAWS(&ev, commitDay(ev.Date), now)
	return ev
}

// commitDay is the end of a commit's day, the latest it can have happened; zero when unreadable.
func commitDay(date string) time.Time {
	d, err := time.Parse(time.DateOnly, leading(date, 10))
	if err != nil {
		return time.Time{}
	}
	return d.Add(24 * time.Hour)
}

type historyStats struct{ unchanged, incremental, full atomic.Int64 }

func (h *historyStats) String() string {
	return fmt.Sprintf("%d unchanged, %d incremental, %d full", h.unchanged.Load(), h.incremental.Load(), h.full.Load())
}

// gitleaks scans one repository's history and replays each leak with what may have changed since
// it was cached: remote, origin, inherited commits, dumps and notebook outputs.
func (s *scan) gitleaks(repo string) error {
	remote := s.hasRemote(repo)
	org := s.originOf(repo)
	replay := func(leaks []cachedLeak, omitted int) {
		var inherited map[string]bool
		if org.upstream != "" {
			commits := make([]string, len(leaks))
			for i, l := range leaks {
				commits[i] = l.Evidence.Commit
			}
			inherited = s.inheritedCommits(repo, org.upstream, commits)
		}
		for _, l := range leaks {
			origin := org.origin
			if inherited[l.Evidence.Commit] {
				origin = secretrisk.OriginForkUpstream
			}
			ev := l.evidence(s.now, remote, origin)
			if s.inNotebookOutput(repo, ev) {
				continue
			}
			s.markDump(repo, &ev)
			s.store(ev)
		}
		s.omit(omitted)
	}
	if !s.cfg.gitCache {
		leaks, omitted, err := s.runGitleaks(repo, "")
		if err != nil {
			return err
		}
		s.stats.full.Add(1)
		replay(leaks, omitted)
		return nil
	}
	c, err := s.scanWithCache(repo)
	if err != nil {
		return err
	}
	replay(c.Leaks, c.Omitted)
	return nil
}

func (s *scan) scanWithCache(repo string) (*historyCache, error) {
	tips, err := s.tips(repo)
	if err != nil {
		return nil, err
	}
	rules, rulesErr := s.rulesKey(repo)
	fresh := &historyCache{Version: historyCacheVersion, Repo: repo, Rules: rules, Key: s.cacheKeyProbe(), Tips: tips}
	path := s.cachePath(repo)
	old := s.loadCache(path, fresh)

	incremental := old != nil && s.stillReachable(repo, old.Tips, tips)
	var logOpts string
	switch {
	case incremental && len(without(tips, old.Tips)) == 0, !incremental && len(tips) == 0:
		if incremental { // nothing new
			fresh.Leaks, fresh.Omitted = old.Leaks, old.Omitted
		}
		s.stats.unchanged.Add(1)
		s.saveCache(path, fresh, rulesErr)
		return fresh, nil
	case incremental:
		logOpts = "--full-history " + strings.Join(without(tips, old.Tips), " ") + " --not " + strings.Join(old.Tips, " ")
	default:
		// Explicit tips, so the cache records what was scanned even if a commit lands meanwhile.
		logOpts = "--full-history " + strings.Join(tips, " ")
	}
	if len(logOpts) > maxLogOpts { // too many refs for a command line: scan everything
		incremental, logOpts = false, ""
	}
	leaks, omitted, err := s.runGitleaks(repo, logOpts)
	if err != nil {
		return nil, err
	}
	if incremental {
		s.stats.incremental.Add(1)
		fresh.Leaks, fresh.Omitted = old.Leaks, old.Omitted
	} else {
		s.stats.full.Add(1)
	}
	fresh.Leaks = append(fresh.Leaks, leaks...)
	fresh.Omitted += omitted
	s.saveCache(path, fresh, rulesErr)
	return fresh, nil
}

func gitDirArg(repo string) string { return "--git-dir=" + filepath.Join(repo, ".git") }

func (s *scan) tips(repo string) ([]string, error) {
	out, err := guardGit(s.c.Git).Run(s.ctx, gitDirArg(repo), "rev-list", "--no-walk", "--all")
	if err != nil {
		return nil, fmt.Errorf("listing refs: %w", err)
	}
	return sortedUnique(strings.Fields(string(out))), nil
}

// stillReachable: no ref was rewritten or deleted. A missing object counts as rewritten: gitleaks
// would silently scan nothing.
func (s *scan) stillReachable(repo string, old, current []string) bool {
	if len(old) == 0 {
		return true
	}
	if len(current) == 0 {
		return false
	}
	args := append([]string{gitDirArg(repo), "rev-list", "-n", "1"}, old...)
	args = append(append(args, "--not"), current...)
	out, err := guardGit(s.c.Git).Run(s.ctx, args...)
	return err == nil && strings.TrimSpace(string(out)) == ""
}

// rulesKey hashes what decides gitleaks' results besides the commits. Without a version the scan
// runs in full and is not cached.
func (s *scan) rulesKey(repo string) (string, error) {
	s.glOnce.Do(func() {
		out, err := guardGitleaks(s.c.Gitleaks).Run(s.ctx, "version")
		s.glVersion, s.glErr = strings.TrimSpace(string(out)), err
	})
	if s.glErr != nil {
		return "", fmt.Errorf("gitleaks version: %w", s.glErr)
	}
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00", historyCacheVersion, s.glVersion)
	for _, env := range []string{"GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"} {
		v := os.Getenv(env)
		fmt.Fprintf(h, "%s=%s\x00", env, v)
		if env == "GITLEAKS_CONFIG" && v != "" {
			raw, _ := os.ReadFile(v)
			h.Write(raw)
		}
	}
	for _, f := range []string{".gitleaks.toml", ".gitleaksignore"} {
		raw, _ := os.ReadFile(filepath.Join(repo, f))
		fmt.Fprintf(h, "\x00%s\x00", f)
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

func (s *scan) cacheKeyProbe() string { return s.fp.Of("segurata git history cache") }

func (s *scan) cachePath(repo string) string { return repoCacheFile(s.c.CacheDir(s.home), repo) }

func repoCacheFile(dir, repo string) string {
	sum := sha256.Sum256([]byte(repo))
	return filepath.Join(dir, hex.EncodeToString(sum[:8])+".json")
}

// loadCache is nil, a full scan, unless the cache matches want's version, repository, rules and key.
func (s *scan) loadCache(path string, want *historyCache) *historyCache {
	var c historyCache
	found, err := statefile.ReadJSON(path, &c)
	if err != nil {
		s.emit.Log("gitleaks cache " + path + ": " + err.Error())
	}
	if !found || err != nil {
		return nil
	}
	if c.Version != want.Version || c.Repo != want.Repo || c.Rules != want.Rules || want.Rules == "" || c.Key != want.Key {
		return nil
	}
	return &c
}

// saveCache skips a scan whose rules are unknown; a failed write costs the next run a full scan.
func (s *scan) saveCache(path string, c *historyCache, rulesErr error) {
	if rulesErr != nil {
		s.emit.Log(rulesErr.Error() + ": git history cache not written")
		return
	}
	if err := statefile.WriteJSON(path, c); err != nil {
		s.emit.Log("gitleaks cache " + path + ": " + err.Error())
	}
}

func without(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	return out
}

func sortedUnique(xs []string) []string { return slices.Compact(slices.Sorted(slices.Values(xs))) }
