package localsecrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
)

// A run that could not read part of the machine says so, so the findings it missed there are not
// taken as resolved.

// writeExe writes an executable shell script named name into a fresh directory and returns its path.
func writeExe(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFailedRipgrepLeavesTheFilesUninspected(t *testing.T) {
	// The fake ripgrep's last argument is the last root of its search.
	const lastRoot = `for root; do :; done; `
	for _, tc := range []struct {
		name, script string
		timeout      time.Duration
		skipped      bool
		unreadable   int // paths the status detail counts as skipped
	}{
		{"regex error", `echo "rg: regex parse error" >&2; exit 2`, time.Minute, true, 0},
		{"partial output, then an error", `printf '%s\0001:x\n' "$HOME/.zshrc"; echo "rg: something broke" >&2; exit 2`, time.Minute, true, 0},
		{"unreadable files and an I/O error", `echo "rg: /x/a: Permission denied (os error 13)" >&2
echo "rg: /x/b: Input/output error (os error 5)" >&2; exit 2`, time.Minute, true, 0},
		{"unreadable root", lastRoot + `echo "rg: $root: Permission denied (os error 13)" >&2; exit 2`, time.Minute, true, 0},
		{"exit 2 without a message", `exit 2`, time.Minute, true, 0},
		{"killed", `kill -9 $$`, time.Minute, true, 0},
		{"timed out", `exec sleep 5`, 100 * time.Millisecond, true, 0},
		{"unreadable files only", `echo "rg: /x/Mail: Operation not permitted (os error 1)" >&2
echo "rg: /x/a: Permission denied (os error 13)" >&2
echo "rg: /x/a: Permission denied (os error 13)" >&2; exit 2`, time.Minute, false, 2},
		{"no match", `exit 1`, time.Minute, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			c := fx.connector(t, "[]")
			c.RG = cli.Exec{Path: writeExe(t, "rg", tc.script), Timeout: tc.timeout}
			rec := &recorder{}
			if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
				t.Fatal(err)
			}
			var files []string
			for _, s := range rec.skipped {
				if strings.HasPrefix(s, filesScope+": ") {
					files = append(files, s)
				}
			}
			if got := len(files) > 0; got != tc.skipped {
				t.Errorf("files scope skipped = %v, want %v (skipped: %q)", got, tc.skipped, rec.skipped)
			}
			for _, s := range files {
				if !strings.Contains(s, "rg") {
					t.Errorf("reason does not name ripgrep: %q", s)
				}
				if strings.Contains(s, "/x/") || strings.Contains(s, fx.home) {
					t.Errorf("reason names a path: %q", s)
				}
			}
			var detail string
			for _, s := range rec.statuses {
				if s.Account == localAccount && s.Scope == "" {
					detail = s.Detail
				}
			}
			want := fmt.Sprintf("; %d unreadable paths skipped", tc.unreadable)
			if got := strings.Contains(detail, "unreadable paths skipped"); got != (tc.unreadable > 0) || tc.unreadable > 0 && !strings.Contains(detail, want) {
				t.Errorf("status detail %q, want unreadable count %d", detail, tc.unreadable)
			}
			if strings.Contains(detail, "/x/") {
				t.Errorf("status detail names a path: %q", detail)
			}
		})
	}
}

// The real ripgrep exits 2 on a file it may not read, as it does on every macOS home: the rest of
// the search is still complete, and still finds what it reads.
func TestRealRipgrepCountsAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	fx := newFixture(t)
	c := fx.connector(t, "[]")
	locked := fx.write(t, ".config/locked.env", "TOKEN="+fx.stripe+"\n", 0o000)
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
		t.Fatal(err)
	}
	for _, s := range rec.skipped {
		if strings.HasPrefix(s, filesScope+": ") {
			t.Errorf("files scope skipped: %q", s)
		}
	}
	var detail string
	for _, s := range rec.statuses {
		if s.Account == localAccount && s.Scope == "" {
			detail = s.Detail
		}
	}
	if !strings.Contains(detail, "; 1 unreadable paths skipped") {
		t.Errorf("status detail %q does not count the unreadable file", detail)
	}
	var zshrc bool
	for _, f := range rec.findings {
		zshrc = zshrc || strings.HasSuffix(evidence(f, "path"), ".zshrc")
	}
	if !zshrc {
		t.Errorf("the readable files were not searched: %d findings", len(rec.findings))
	}
}

func TestFailedLsFilesIsAScopedErrorNotAnEmptyRepository(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, "[]")
	var lsCalls int
	git := c.Git
	c.Git = cli.RunnerFunc(func(ctx context.Context, args ...string) ([]byte, error) {
		for _, a := range args {
			if a == "ls-files" {
				lsCalls++
				return nil, errors.New("index file corrupt")
			}
		}
		return git.Run(ctx, args...)
	})
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
		t.Fatal(err)
	}
	var failed int
	for _, s := range rec.statuses {
		if s.State == finding.StateError && s.Scope == filesScope && s.Account == "~/src/shop" && strings.Contains(s.Detail, "git ls-files") {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("want one error status for ~/src/shop scoped to %q, got %d: %+v", filesScope, failed, rec.statuses)
	}
	if lsCalls != 1 {
		t.Errorf("ls-files ran %d times for one repository in one run", lsCalls)
	}
}

// hostileRepo is a repository under home/src whose own config names a program for every hook git
// offers a read to run: fsmonitor, a textconv driver, an external diff, signature verification,
// hooks and a lazy fetch of missing objects over ssh. Each program touches marker.
func hostileRepo(t *testing.T) (r *historyRepo, marker string) {
	r = newHistoryRepo(t)
	marker = filepath.Join(r.home, "ran")
	prog := writeExe(t, "evil", `echo "$0 $*" >> "`+marker+`"`)
	r.writeFile(".gitattributes", []byte("*.env diff=evil\n"))
	r.commit("a.env")
	r.commit("b.env")
	// A signed commit, so that log.showSignature has a signature to verify.
	raw := r.git("cat-file", "commit", "HEAD")
	head, msg, _ := strings.Cut(raw, "\n\n")
	signed := head + "\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n iQ==\n -----END PGP SIGNATURE-----\n\n" + msg + "\n"
	r.writeFile("signed.txt", []byte(signed))
	id := r.git("hash-object", "-t", "commit", "-w", "signed.txt")
	r.git("update-ref", "HEAD", id)
	if err := os.Remove(filepath.Join(r.dir, "signed.txt")); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Dir(prog)
	for _, h := range []string{"post-index-change", "reference-transaction", "pre-auto-gc", "post-checkout"} {
		if err := os.Symlink(prog, filepath.Join(hooks, h)); err != nil {
			t.Fatal(err)
		}
	}
	for _, kv := range [][2]string{
		{"core.fsmonitor", prog},
		{"core.hooksPath", hooks},
		{"core.pager", prog},
		{"diff.evil.textconv", prog},
		{"diff.external", prog},
		{"log.showSignature", "true"},
		{"gpg.program", prog},
		{"core.repositoryformatversion", "1"},
		{"extensions.partialClone", "origin"},
		{"remote.origin.url", "ssh://example.invalid/x.git"},
		{"remote.origin.promisor", "true"},
		{"core.sshCommand", prog},
	} {
		r.git("config", kv[0], kv[1])
	}
	return r, marker
}

// A repository's own config cannot make the scan run a program: every git the connector starts,
// directly or through gitleaks, runs with those settings overridden.
func TestRepositoryConfigRunsNothing(t *testing.T) {
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("ripgrep not installed")
	}
	r, marker := hostileRepo(t)
	c := New()
	c.Home = func() (string, error) { return r.home, nil }
	c.KeyPath = func(home string) string { return filepath.Join(home, ".config", "segurata", "fingerprint.key") }
	c.GH = nil
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	// Reads that would fetch a missing object from the promisor remote.
	missing := strings.Repeat("e", 40)
	s := newScan(context.Background(), c, r.home, settings{}, fingerprint.FromBytes(make([]byte, 32)), rec)
	_, _ = guardGit(c.Git).Run(s.ctx, gitDirArg(r.dir), "cat-file", "-s", missing)
	_, _ = guardGitHead(c.GitHead).Run(s.ctx, gitDirArg(r.dir), "cat-file", "blob", missing)
	if ran, err := os.ReadFile(marker); err == nil {
		t.Fatalf("the repository's config ran a program:\n%s", ran)
	}
	if _, err := exec.LookPath("gitleaks"); err == nil {
		var scanned bool
		for _, f := range rec.findings {
			scanned = scanned || evidence(f, "source") == "gitleaks"
		}
		if !scanned {
			t.Errorf("gitleaks found nothing in the repository's history: %+v", rec.statuses)
		}
	}
}

// gitleaks exits 0 with an empty report when the git it runs fails (a bad revision in --log-opts,
// a corrupt object) and only logs git's error: that scan is a failure, and the history cache must
// not record the repository as scanned.
func TestGitErrorUnderGitleaksIsAFailedScan(t *testing.T) {
	for _, tc := range []struct {
		name, stderr string
		failed       bool
	}{
		{"git fatal", "12:16AM ERR [git] fatal: bad revision 'deadbeef'\n12:16AM ERR error=\"stderr is not empty\"", true},
		{"git error", "12:16AM ERR [git] error: object file is empty\n", true},
		{"git warning only", "12:16AM ERR [git] warning: refname 'x' is ambiguous.\n12:16AM ERR error=\"stderr is not empty\"", false},
		{"remote link only", "12:16AM ERR skipping finding links: unable to parse remote URL\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newHistoryRepo(t)
			r.commit("a.env")
			gl := New().Gitleaks.(cli.Exec)
			gl.Path = writeExe(t, "gitleaks", `[ "$1" = version ] && { echo 8.30.1; exit 0; }
printf '%s\n' "`+tc.stderr+`" >&2
echo '[]'`)
			c := &Connector{Gitleaks: gl, Git: cli.Exec{Path: "git", Timeout: time.Minute}, CacheDir: DefaultCacheDir,
				Now: func() time.Time { return time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) }}
			cfg := settings{reposRoot: filepath.Join(r.home, "src"), workers: 1, timeout: time.Minute, gitCache: true}
			s := newScan(context.Background(), c, r.home, cfg, fingerprint.FromBytes(make([]byte, 32)), &recorder{})
			err := s.gitleaks(r.dir)
			if (err != nil) != tc.failed {
				t.Fatalf("scan error %v, want failed=%v", err, tc.failed)
			}
			cached, _ := filepath.Glob(filepath.Join(DefaultCacheDir(r.home), "*.json"))
			if (len(cached) == 0) != tc.failed {
				t.Errorf("cache files %v after failed=%v", cached, tc.failed)
			}
		})
	}
}
