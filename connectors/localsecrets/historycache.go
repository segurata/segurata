package localsecrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
)

// Git history is append-only in practice, so a repository's history needs a full gitleaks scan
// once: after that only the commits added since the last run are scanned, and the leaks found
// before are replayed from a per-repository cache.
//
// The cache records the commit every ref (and HEAD) pointed to when the scan ran, its tips. The
// next run lists the tips again and scans `<new tips> --not <old tips>`: exactly the commits no
// earlier scan saw. That is only valid while every old tip is still reachable from a current one;
// when a ref was rewritten or deleted, the commits it held may be gone, their leaks with them, and
// the run falls back to a full scan. So does a change of cache format, gitleaks version, gitleaks
// configuration or fingerprint key.
//
// The cache holds evidence only (fingerprints, redacted hints, paths, commits), never a value: it
// stores the evidence after prepare, which has already refused any that would contain the value.

const historyCacheVersion = 1

// maxLogOpts bounds the commit list passed to gitleaks, well under any OS argument limit.
var maxLogOpts = 256 << 10

// DefaultCacheDir is ~/.cache/securizame/gitleaks.
func DefaultCacheDir(home string) string {
	return filepath.Join(home, ".cache", "securizame", "gitleaks")
}

// historyCache is one repository's cache file.
type historyCache struct {
	Version int          `json:"version"`
	Repo    string       `json:"repo"`  // absolute path: the file name is only its hash
	Rules   string       `json:"rules"` // hash of the gitleaks version and configuration in force
	Key     string       `json:"key"`   // fingerprint of a fixed probe: changes with the machine key
	Tips    []string     `json:"tips"`  // commits the refs and HEAD pointed to at the last scan
	Leaks   []cachedLeak `json:"leaks"`
	Omitted int          `json:"omitted,omitempty"` // leaks dropped because evidence held the value
}

// cachedLeak is one gitleaks finding, already prepared. Expires keeps a JWT's exp claim so a
// token that expired after it was cached is judged as of today.
type cachedLeak struct {
	Evidence secretrisk.Evidence `json:"evidence"`
	Expires  int64               `json:"expires,omitempty"`
}

// evidence is the cached evidence as of now, for a repository that has a remote or not.
func (c cachedLeak) evidence(now time.Time, remote bool) secretrisk.Evidence {
	ev := c.Evidence
	ev.Remote = remote
	if c.Expires > 0 && time.Unix(c.Expires, 0).Before(now) && !strings.Contains(ev.Note, "expired") {
		ev.Note = strings.TrimSpace(ev.Note + " expired")
		ev.Public = true
	}
	return ev
}

// historyStats counts how each repository's history was scanned, for the run's status line.
type historyStats struct{ unchanged, incremental, full atomic.Int64 }

func (h *historyStats) String() string {
	return fmt.Sprintf("%d unchanged, %d incremental, %d full", h.unchanged.Load(), h.incremental.Load(), h.full.Load())
}

// gitleaks scans one repository's history, through the cache unless git_cache is false.
func (s *scan) gitleaks(repo string) error {
	remote := s.hasRemote(repo)
	replay := func(leaks []cachedLeak, omitted int) {
		for _, l := range leaks {
			s.store(l.evidence(s.now, remote))
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

// scanWithCache brings a repository's cache up to date, scanning only what it lacks, and saves it.
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
		// Nothing new, or no commits yet.
		if incremental {
			fresh.Leaks, fresh.Omitted = old.Leaks, old.Omitted
		}
		s.stats.unchanged.Add(1)
		s.saveCache(path, fresh, rulesErr)
		return fresh, nil
	case incremental:
		logOpts = "--full-history " + strings.Join(without(tips, old.Tips), " ") + " --not " + strings.Join(old.Tips, " ")
	default:
		// Explicit tips rather than gitleaks' default --all, so the cache records exactly what was
		// scanned even if a commit lands during the scan.
		logOpts = "--full-history " + strings.Join(tips, " ")
	}
	if len(logOpts) > maxLogOpts {
		// Thousands of refs would not fit on a command line: scan everything the gitleaks way.
		// A commit that lands during this scan may then be scanned twice by the next run.
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

// tips lists the distinct commits the refs and HEAD point to (tags peeled), sorted.
func (s *scan) tips(repo string) ([]string, error) {
	out, err := guardGit(s.c.Git).Run(s.ctx, gitDirArg(repo), "rev-list", "--no-walk", "--all")
	if err != nil {
		return nil, fmt.Errorf("listing refs: %w", err)
	}
	return sortedUnique(strings.Fields(string(out))), nil
}

// stillReachable reports whether every old tip is reachable from a current one, i.e. no ref was
// rewritten or deleted since the last scan. A missing object is a rewrite too: git fails on it,
// whereas gitleaks would silently scan nothing.
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

// rulesKey hashes what decides gitleaks' results besides the commits: its version, the
// configuration named by its environment variables and the repository's own config and ignore
// files. An error means the version could not be read; the scan then runs in full and is not cached.
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

// cacheKeyProbe changes whenever the fingerprint key does, which invalidates cached fingerprints.
func (s *scan) cacheKeyProbe() string { return s.fp.ofString("securizame git history cache") }

func (s *scan) cachePath(repo string) string {
	sum := sha256.Sum256([]byte(repo))
	return filepath.Join(s.c.CacheDir(s.home), hex.EncodeToString(sum[:8])+".json")
}

// loadCache returns the cache at path when it matches want's version, repository, rules and key,
// or nil (missing, unreadable or stale), which means a full scan.
func (s *scan) loadCache(path string, want *historyCache) *historyCache {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.emit.Log("gitleaks cache " + path + ": " + err.Error())
		}
		return nil
	}
	var c historyCache
	if err := json.Unmarshal(raw, &c); err != nil {
		s.emit.Log("gitleaks cache " + path + ": " + err.Error())
		return nil
	}
	if c.Version != want.Version || c.Repo != want.Repo || c.Rules != want.Rules || want.Rules == "" || c.Key != want.Key {
		return nil
	}
	return &c
}

// saveCache writes the cache, mode 0600 in a 0700 directory, unless the rules could not be read.
// A cache that cannot be written only costs the next run a full scan.
func (s *scan) saveCache(path string, c *historyCache, rulesErr error) {
	if rulesErr != nil {
		s.emit.Log(rulesErr.Error() + ": git history cache not written")
		return
	}
	if err := statefile.WriteJSON(path, c); err != nil {
		s.emit.Log("gitleaks cache " + path + ": " + err.Error())
	}
}

// without returns the elements of a not in b.
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

func sortedUnique(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// historyOnce guards the gitleaks version lookup shared by every repository of a run.
type historyOnce struct {
	glOnce    sync.Once
	glVersion string
	glErr     error
}
