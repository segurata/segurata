package localsecrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/proc/proctest"
	"github.com/segurata/segurata/internal/secretrisk"
)

// A run that could not read part of the machine says so, so the findings it missed there are not
// taken as resolved.

// writeExe makes an executable shell script named name in a fresh directory and returns its path.
func writeExe(t *testing.T, name, body string) string {
	t.Helper()
	return proctest.Script(t, "", name, body+"\n")
}

func TestFailedRipgrepLeavesTheFilesUninspected(t *testing.T) {
	// The fake ripgrep's last argument is the last root of its search.
	const lastRoot = `for root; do :; done; `
	for _, tc := range []struct {
		name, script string
		timeout      time.Duration
		skipped      bool
		unreadable   []string // paths the run skips, which the status detail counts
	}{
		{"regex error", `echo "rg: regex parse error" >&2; exit 2`, time.Minute, true, nil},
		{"partial output, then an error", `printf '%s\0001:x\n' "$HOME/.zshrc"; echo "rg: something broke" >&2; exit 2`, time.Minute, true, nil},
		{"unreadable files and an I/O error", `echo "rg: /x/a: Permission denied (os error 13)" >&2
echo "rg: /x/b: Input/output error (os error 5)" >&2; exit 2`, time.Minute, true, nil},
		{"unreadable root", lastRoot + `printf 'rg: %s: Permission denied (os error 13)\n' "$root" >&2; exit 2`, time.Minute, true, nil},
		{"exit 2 without a message", `exit 2`, time.Minute, true, nil},
		{"killed", `kill -9 $$`, time.Minute, true, nil},
		{"timed out", `exec sleep 5`, 100 * time.Millisecond, true, nil},
		{"unreadable files only", `echo "rg: /x/Mail: Operation not permitted (os error 1)" >&2
echo "rg: /x/a: Permission denied (os error 13)" >&2
echo "rg: /x/a: Permission denied (os error 13)" >&2; exit 2`, time.Minute, false, []string{"/x/Mail", "/x/a"}},
		{"unreadable and vanished files", `echo "rg: /x/a: Permission denied (os error 13)" >&2
echo "rg: /x/gone.jsonl: No such file or directory (os error 2)" >&2; exit 2`, time.Minute, false, []string{"/x/a"}},
		{"vanished root", lastRoot + `printf 'rg: %s: No such file or directory (os error 2)\n' "$root" >&2; exit 2`, time.Minute, true, nil},
		{"no match", `exit 1`, time.Minute, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			c := fx.connector(t, "[]")
			c.RG = cli.Exec{Path: writeExe(t, "rg", tc.script), Timeout: tc.timeout}
			rec := &recorder{}
			if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
				t.Fatal(err)
			}
			var files, paths []string
			for _, s := range rec.skipped() {
				if strings.HasPrefix(s, secretrisk.FilesScope+": ") {
					files = append(files, s)
				}
				if p, ok := strings.CutPrefix(s, secretrisk.FilesScope+":/"); ok {
					paths = append(paths, "/"+strings.TrimSuffix(p, ": "+finding.UnreadableReason))
				}
			}
			if !slices.Equal(paths, tc.unreadable) {
				t.Errorf("unreadable paths skipped %q, want %q", paths, tc.unreadable)
			}
			if got := len(files) > 0; got != tc.skipped {
				t.Errorf("files scope skipped = %v, want %v (skipped: %q)", got, tc.skipped, rec.skipped())
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
			for _, s := range rec.Statuses {
				if s.Account == localAccount && s.Scope == "" {
					detail = s.Detail
				}
			}
			n := len(tc.unreadable)
			want := fmt.Sprintf("; %d unreadable paths skipped", n)
			if got := strings.Contains(detail, "unreadable paths skipped"); got != (n > 0) || n > 0 && !strings.Contains(detail, want) {
				t.Errorf("status detail %q, want unreadable count %d", detail, n)
			}
			if strings.Contains(detail, "/x/") {
				t.Errorf("status detail names a path: %q", detail)
			}
			// Unreadable paths are expected: they leave nothing of the files missed.
			cov := runCoverage(rec)
			missed := slices.ContainsFunc(cov.Missed(), func(s finding.Skipped) bool { return strings.HasPrefix(s.Scope, secretrisk.FilesScope) })
			if missed != tc.skipped || cov.Unreadable() != n {
				t.Errorf("files missed %v, unreadable %d; missed %q", missed, cov.Unreadable(), cov.Missed())
			}
		})
	}
}

// runCoverage is the coverage the run_end of rec's run would give.
func runCoverage(rec *recorder) finding.Coverage {
	var tally finding.Tally
	for _, st := range rec.Statuses {
		tally.Status(st)
	}
	for _, sc := range rec.Scopes {
		tally.Declare(sc.ID, sc.Inspected, sc.Reason)
	}
	end := tally.End(name, "", time.Now(), time.Now(), nil)
	return finding.CoverageOf(&end)
}

// More unreadable paths than run_end lists prove nothing, expected or not: the run is partial.
func TestTooManyUnreadablePathsProveNothing(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, "[]")
	c.RG = cli.Exec{Path: writeExe(t, "rg", `i=0; while [ $i -le 200 ]; do echo "rg: /x/f$i: Permission denied (os error 13)" >&2; i=$((i+1)); done; exit 2`), Timeout: time.Minute}
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
		t.Fatal(err)
	}
	cov := runCoverage(rec)
	if why, none := cov.NoneChecked(); !none || !strings.Contains(why, "too many to list") || cov.CompleteAsConfigured() {
		t.Errorf("201 unreadable paths: none checked %v (%q), complete as configured %v", none, why, cov.CompleteAsConfigured())
	}
}

// The real ripgrep exits 2 on a file it may not read, as it does on every macOS home: the run
// skips that file alone, and the rest of the search is still complete and finds what it reads.
func TestRealRipgrepCountsAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	fx := newFixture(t)
	c := fx.connector(t, "[]")
	locked := fx.write(t, ".config/locked.env", "TOKEN="+fx.stripe+"\n", 0o600)
	denyRead(t, locked)
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, s := range rec.skipped() {
		if strings.HasPrefix(s, secretrisk.FilesScope) {
			files = append(files, s)
		}
	}
	if want := []string{finding.PathScope(secretrisk.FilesScope, "~/.config/locked.env") + ": " + finding.UnreadableReason}; !slices.Equal(files, want) {
		t.Errorf("files skipped %q, want %q", files, want)
	}
	var detail string
	for _, s := range rec.Statuses {
		if s.Account == localAccount && s.Scope == "" {
			detail = s.Detail
		}
	}
	if !strings.Contains(detail, "; 1 unreadable paths skipped") {
		t.Errorf("status detail %q does not count the unreadable file", detail)
	}
	if cov := runCoverage(rec); cov.Unreadable() != 1 || slices.ContainsFunc(cov.Missed(), func(s finding.Skipped) bool { return strings.HasPrefix(s.Scope, secretrisk.FilesScope) }) {
		t.Errorf("unreadable %d, missed %q: the unreadable file is not expected", cov.Unreadable(), cov.Missed())
	}
	var zshrc bool
	for _, f := range rec.Findings {
		zshrc = zshrc || strings.HasSuffix(evidence(f, "path"), ".zshrc")
	}
	if !zshrc {
		t.Errorf("the readable files were not searched: %d findings", len(rec.Findings))
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
	for _, s := range rec.Statuses {
		if s.State == finding.StateError && s.Scope == secretrisk.FilesScope && s.Account == "~/src/shop" && strings.Contains(s.Detail, "git ls-files") {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("want one error status for ~/src/shop scoped to %q, got %d: %+v", secretrisk.FilesScope, failed, rec.Statuses)
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
		for _, f := range rec.Findings {
			scanned = scanned || evidence(f, "source") == "gitleaks"
		}
		if !scanned {
			t.Errorf("gitleaks found nothing in the repository's history: %+v", rec.Statuses)
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
			c := &Connector{Gitleaks: gl, Git: cli.Exec{Path: "git", Timeout: time.Minute}, CacheDir: defaultCacheDir,
				Now: func() time.Time { return time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) }}
			cfg := settings{reposRoot: filepath.Join(r.home, "src"), workers: 1, timeout: time.Minute, gitCache: true}
			s := newScan(context.Background(), c, r.home, cfg, fingerprint.FromBytes(make([]byte, 32)), &recorder{})
			err := s.gitleaks(r.dir)
			if (err != nil) != tc.failed {
				t.Fatalf("scan error %v, want failed=%v", err, tc.failed)
			}
			cached, _ := filepath.Glob(filepath.Join(defaultCacheDir(r.home), "*.json"))
			if (len(cached) == 0) != tc.failed {
				t.Errorf("cache files %v after failed=%v", cached, tc.failed)
			}
		})
	}
}

// The index is listed whole and by repository-relative name when segurata runs from a directory
// inside the repository: git otherwise lists only that directory, relative to it.
func TestIndexListingIgnoresTheWorkingDirectory(t *testing.T) {
	r := newHistoryRepo(t)
	r.writeFile("db/backup.sql", []byte("x\n"))
	r.writeFile("sub/deep/x.txt", []byte("x\n"))
	r.commitAll("files")
	t.Chdir(filepath.Join(r.dir, "sub", "deep"))
	s, _ := r.dumpScan(cli.Exec{Path: "git", Timeout: time.Minute}, nil, nil)
	files, err := s.lsFiles(r.dir)
	if err != nil || !files[filepath.Join(r.dir, "db", "backup.sql")] || !files[filepath.Join(r.dir, "sub", "deep", "x.txt")] {
		t.Errorf("ls-files from a subdirectory: %v, %v", files, err)
	}
	dumps, err := s.trackedDumps(r.dir)
	if _, ok := dumps["db/backup.sql"]; err != nil || !ok {
		t.Errorf("tracked dumps from a subdirectory: %v, %v", dumps, err)
	}
}
