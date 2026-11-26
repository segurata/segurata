package localsecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
)

// historyRepo is a real git repository whose commits each add one generated secret, and a fake
// gitleaks that reports the secrets of exactly the commits its --log-opts select, as listed by
// the real git. So the test checks which commits each run scans, not just how often it ran.
type historyRepo struct {
	t       *testing.T
	home    string
	dir     string
	secrets map[string]string // commit -> secret it added
	files   map[string]string // commit -> file it added
	scans   [][]string        // args of every `gitleaks git` call
}

func newHistoryRepo(t *testing.T) *historyRepo {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	r := &historyRepo{t: t, home: home, dir: filepath.Join(home, "src", "repo"), secrets: map[string]string{}, files: map[string]string{}}
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r.git("init", "-q")
	return r
}

func (r *historyRepo) git(args ...string) string {
	cmd := exec.Command("git", append([]string{"-C", r.dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit adds a file holding a new secret and returns the commit and the secret.
func (r *historyRepo) commit(name string) (string, string) {
	secret := fake("sk_live_", 40)
	if err := os.WriteFile(filepath.Join(r.dir, name), []byte("KEY="+secret+"\n"), 0o600); err != nil {
		r.t.Fatal(err)
	}
	r.git("add", name)
	r.git("commit", "-q", "-m", name)
	c := r.git("rev-parse", "HEAD")
	r.secrets[c], r.files[c] = secret, name
	return c, secret
}

func (r *historyRepo) gitleaks() cli.Runner {
	return cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "version" {
			return []byte("v8.30.1\n"), nil
		}
		r.scans = append(r.scans, args)
		revs := strings.Fields(logOpts(args))
		if len(revs) == 0 {
			revs = []string{"--all"} // gitleaks' default
		}
		var leaks []map[string]any
		for _, c := range strings.Fields(r.git(append([]string{"rev-list"}, revs...)...)) {
			if s, ok := r.secrets[c]; ok {
				leaks = append(leaks, map[string]any{"RuleID": "stripe-access-token", "File": r.files[c], "StartLine": 1,
					"Secret": s, "Commit": c, "Date": "2026-11-01T00:00:00Z"})
			}
		}
		return json.Marshal(leaks)
	})
}

// run scans the repository once and returns the secrets (fingerprints) found and the scan's
// gitleaks calls.
func (r *historyRepo) run(gitCache bool, key byte) (map[string]bool, [][]string) {
	r.scans = nil
	c := &Connector{
		Gitleaks: r.gitleaks(),
		Git:      cli.Exec{Path: "git", Timeout: time.Minute},
		CacheDir: defaultCacheDir,
		Now:      func() time.Time { return time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) },
	}
	cfg := settings{reposRoot: filepath.Join(r.home, "src"), workers: 1, timeout: time.Minute, gitCache: gitCache}
	s := newScan(context.Background(), c, r.home, cfg, fingerprint.FromBytes(bytes.Repeat([]byte{key}, 32)), &recorder{})
	if err := s.gitleaks(r.dir); err != nil {
		r.t.Fatal(err)
	}
	got := map[string]bool{}
	fs, _ := s.findings()
	for _, f := range fs {
		got[evidence(f, "fingerprint")] = true
	}
	return got, r.scans
}

func (r *historyRepo) fp(secret string, key byte) string {
	return fingerprint.FromBytes(bytes.Repeat([]byte{key}, 32)).Of(secret)
}

func (r *historyRepo) want(t *testing.T, got map[string]bool, key byte, secrets ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, s := range secrets {
		want[r.fp(s, key)] = true
	}
	if len(got) != len(want) {
		t.Fatalf("found %d secrets, want %d", len(got), len(want))
	}
	for fp := range want {
		if !got[fp] {
			t.Fatalf("secret %s missing", fp)
		}
	}
}

// logOpts are the commits a `gitleaks git` call selects, without gitLogSafety; "" for every commit.
func logOpts(scan []string) string {
	i := slices.Index(scan, "--log-opts")
	if i < 0 {
		return ""
	}
	opts, ok := strings.CutPrefix(scan[i+1], gitLogSafety+" ")
	if !ok {
		panic("gitleaks --log-opts without " + gitLogSafety)
	}
	if opts == gitleaksDefaultLogOpts {
		return ""
	}
	return opts
}

func TestHistoryCacheScansOnlyNewCommits(t *testing.T) {
	r := newHistoryRepo(t)
	c1, s1 := r.commit("a.env")

	got, scans := r.run(true, 1)
	r.want(t, got, 1, s1)
	if len(scans) != 1 || logOpts(scans[0]) != "--full-history "+c1 {
		t.Fatalf("first run: %v", scans)
	}
	cache := r.cacheFile(t)
	fileacltest.AssertPrivate(t, cache)
	raw, _ := os.ReadFile(cache)
	if strings.Contains(string(raw), s1) {
		t.Fatal("cache holds a raw secret")
	}

	got, scans = r.run(true, 1)
	r.want(t, got, 1, s1)
	if len(scans) != 0 {
		t.Fatalf("unchanged repository scanned again: %v", scans)
	}

	c2, s2 := r.commit("b.env")
	got, scans = r.run(true, 1)
	r.want(t, got, 1, s1, s2)
	if len(scans) != 1 || logOpts(scans[0]) != "--full-history "+c2+" --not "+c1 {
		t.Fatalf("incremental run: %v", scans)
	}

	// A new branch from an old commit only adds its own commits.
	r.git("checkout", "-q", "-b", "side", c1)
	c3, s3 := r.commit("c.env")
	got, scans = r.run(true, 1)
	r.want(t, got, 1, s1, s2, s3)
	if len(scans) != 1 || !strings.HasPrefix(logOpts(scans[0]), "--full-history "+c3+" --not ") {
		t.Fatalf("new branch: %v", scans)
	}
}

func TestHistoryCacheRescansAfterRewrite(t *testing.T) {
	r := newHistoryRepo(t)
	c1, s1 := r.commit("a.env")
	r.commit("b.env")
	r.run(true, 1)

	// Rewrite: drop the second commit and add another. Its secret is no longer in the history.
	r.git("reset", "-q", "--hard", c1)
	c3, s3 := r.commit("c.env")
	got, scans := r.run(true, 1)
	r.want(t, got, 1, s1, s3)
	if len(scans) != 1 || logOpts(scans[0]) != "--full-history "+c3 {
		t.Fatalf("rewritten history not scanned in full: %v", scans)
	}
}

func TestHistoryCacheInvalidation(t *testing.T) {
	r := newHistoryRepo(t)
	c1, s1 := r.commit("a.env")
	r.run(true, 1)

	full := func(what string, gitCache bool, key byte) {
		t.Helper()
		got, scans := r.run(gitCache, key)
		r.want(t, got, key, s1)
		if len(scans) != 1 {
			t.Fatalf("%s: %d scans", what, len(scans))
		}
		want := "--full-history " + c1
		if !gitCache {
			want = ""
		}
		if logOpts(scans[0]) != want {
			t.Fatalf("%s: log opts %q", what, logOpts(scans[0]))
		}
	}
	// Another fingerprint key: cached fingerprints are useless.
	full("new key", true, 2)
	// A repository gitleaks config changes what gitleaks reports.
	if err := os.WriteFile(filepath.Join(r.dir, ".gitleaks.toml"), []byte("[extend]\nuseDefault = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	full("gitleaks config", true, 2)
	// A broken cache file is a full scan, not an error.
	if err := os.WriteFile(r.cacheFile(t), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	full("broken cache", true, 2)
	// git_cache false scans everything the gitleaks way and leaves the cache alone.
	before, _ := os.ReadFile(r.cacheFile(t))
	full("git_cache false", false, 2)
	after, _ := os.ReadFile(r.cacheFile(t))
	if !bytes.Equal(before, after) {
		t.Fatal("git_cache false wrote the cache")
	}
}

func (r *historyRepo) cacheFile(t *testing.T) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(defaultCacheDir(r.home), "*.json"))
	if len(files) != 1 {
		t.Fatalf("cache files %v", files)
	}
	return files[0]
}

func TestCachedJWTExpiresOnReplay(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	c := cachedLeak{Evidence: secretrisk.Evidence{Type: "jwt", Note: "role=service_role"}, Expires: now.Add(-time.Hour).Unix()}
	ev := c.evidence(now, true, "")
	if !ev.Public || ev.Note != "role=service_role expired" || !ev.Remote {
		t.Errorf("expired token replayed as %+v", ev)
	}
	c.Expires = now.Add(time.Hour).Unix()
	if ev := c.evidence(now, false, ""); ev.Public || ev.Note != "role=service_role" {
		t.Errorf("valid token replayed as %+v", ev)
	}
}

func TestHistoryCacheTooManyRefsScansTheGitleaksWay(t *testing.T) {
	r := newHistoryRepo(t)
	_, s1 := r.commit("a.env")
	r.run(true, 1)
	_, s2 := r.commit("b.env")
	defer func(n int) { maxLogOpts = n }(maxLogOpts)
	maxLogOpts = 10
	got, scans := r.run(true, 1)
	r.want(t, got, 1, s1, s2)
	if len(scans) != 1 || logOpts(scans[0]) != "" {
		t.Fatalf("long commit list not replaced by a full scan: %v", scans)
	}
}
