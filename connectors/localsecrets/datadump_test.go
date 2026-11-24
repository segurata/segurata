package localsecrets

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
)

func TestClassifyDumpName(t *testing.T) {
	cases := []struct {
		path      string
		match     bool
		prod      bool
		minSize   int64
		reasoning string
	}{
		{"production_latest_backup.sql", true, true, dumpMinSize, "the case that started it"},
		{"db/dump.sql.gz", true, true, dumpMinSize, "compressed dump"},
		{"data/app.sqlite3", true, false, dumpMinSize, "database file"},
		{"var/cache.db", true, false, dumpMinSize, ".db"},
		{"backups/latest.pgdump", true, true, dumpMinSize, "pg_dump custom format"},
		{"exports/users.sql.zip", true, false, dumpMinSize, "zipped SQL"},
		{"old/mysql-2023.bak", true, true, dumpMinSize, ".bak with a database word"},
		{"notes/feedback.bak", false, false, 0, ".bak without one"},
		{"exports/prod_customers.csv", true, true, dumpLargeSize, "export with a production name"},
		{"exports/customers.csv", false, false, 0, "plain export"},
		{"api/products.json", false, false, 0, "products is not prod"},
		{"db/structure.sql", false, false, 0, "Rails structure"},
		{"db/schema_cache.sql", false, false, 0, "schema"},
		{"db/migrate/20240101_init.sql", false, false, 0, "migration"},
		{"priv/repo/migrations/1.sql", false, false, 0, "Ecto migration"},
		{"db/seeds.sql", false, false, 0, "seeds"},
		{"test/fixtures/sample.sql", true, false, dumpLargeSize, "fixtures need a large size"},
		{"spec/fixtures/users.db", true, false, dumpLargeSize, "spec fixtures too"},
		{"Assets/Thumbs.db", false, false, 0, "Windows thumbnails"},
		{"main.go", false, false, 0, "code"},
		{"workspaces/erl_crash.dump", true, false, dumpMinSize, "the .dump extension is not a production name"},
		{"db/development_structure.sql", false, false, 0, "structure"},
		{"packages/db/drizzle/0003_profiles.sql", false, false, 0, "drizzle migrations"},
		{"vendor/plugins/riddle/data.sql", false, false, 0, "vendored code"},
		{"application/third_party/ar-php/cities.db", false, false, 0, "third-party code"},
	}
	for _, c := range cases {
		n := classifyDumpName(c.path)
		if n.match != c.match || n.prodLike != c.prod || (c.match && n.minSize != c.minSize) {
			t.Errorf("%s (%s): got %+v", c.path, c.reasoning, n)
		}
	}
}

func gz(t *testing.T, b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	return buf.Bytes()
}

// fakeRows is a generated SQL dump: a pg_dump-like preamble, a table and fake rows.
func fakeRows(table string, n int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SET statement_timeout = 0;\nCREATE TABLE %s (id integer, email text, password_digest text);\n", table)
	for i := range n {
		fmt.Fprintf(&b, "INSERT INTO %s VALUES (%d, 'user%d@example.test', '%040x');\n", table, i, i, i*7919)
	}
	return b.String()
}

func TestSniffDump(t *testing.T) {
	copyRows := "--\n-- PostgreSQL-like\n--\nCOPY public.users (id, email) FROM stdin;\n1\ta@example.test\n\\.\n"
	cases := []struct {
		name, class, label string
		head               []byte
	}{
		{"insert", contentRows, "INSERT INTO", []byte("CREATE TABLE x (a int);\nINSERT INTO x VALUES (1);")},
		{"copy", contentRows, "COPY ... FROM stdin", []byte(copyRows)},
		{"pg custom", contentData, "PGDMP (pg_dump custom format)", append([]byte("PGDMP"), 1, 14, 0)},
		{"sqlite", contentData, "SQLite format 3", append([]byte("SQLite format 3\x00"), make([]byte, 84)...)},
		{"pg header", contentData, "pg_dump header", []byte("--\n-- PostgreSQL database dump\n--\n\nSET x = 0;\nCREATE TABLE a (b int);")},
		{"mysql header", contentData, "mysqldump header", []byte("-- MySQL dump 10.13  Distrib 8.0.36\n")},
		{"schema", contentSchema, "CREATE TABLE", []byte("create table users (id int);\ncreate index i on users (id);")},
		{"gzip", contentRows, "INSERT INTO", gz(t, []byte(fakeRows("users", 50)))},
		{"utf-16", contentRows, "INSERT INTO", utf16le("INSERT [dbo].[x] VALUES (1)\r\nINSERT INTO [dbo].[x] VALUES (2)")},
		{"nothing", contentNone, "", []byte("id,email\n1,a@example.test\n")},
	}
	for _, c := range cases {
		class, label := sniffDump(c.head)
		if class != c.class || label != c.label {
			t.Errorf("%s: got %q %q", c.name, class, label)
		}
	}
}

func TestDumpSeverity(t *testing.T) {
	big := int64(12 << 20)
	cases := []struct {
		name string
		h    dumpHit
		want finding.Severity
	}{
		{"prod name, public remote", dumpHit{ProdName: true, Size: big, Remote: true, Visibility: "PUBLIC"}, finding.SevCritical},
		{"dump header, private remote", dumpHit{Content: contentData, Size: 8 << 10, Remote: true, Visibility: "PRIVATE"}, finding.SevHigh},
		{"database file, remote of unknown visibility", dumpHit{Content: contentData, Size: 8 << 10, Remote: true}, finding.SevHigh},
		{"many rows, private remote", dumpHit{Content: contentRows, Size: dumpRowsSize, Remote: true}, finding.SevHigh},
		{"a few rows: a script", dumpHit{Content: contentRows, Size: 12 << 10, Remote: true, Visibility: "PUBLIC"}, finding.SevInfo},
		{"rows, local only", dumpHit{Content: contentData, Size: big}, finding.SevMedium},
		{"big schema-looking file", dumpHit{Content: contentSchema, Size: big, Remote: true}, finding.SevHigh},
		{"small schema", dumpHit{Content: contentSchema, Size: 8 << 10, Remote: true, Visibility: "PUBLIC"}, finding.SevInfo},
		{"unknown content, big, pushed", dumpHit{Size: big, Remote: true}, finding.SevMedium},
		{"unknown content, big, local", dumpHit{Size: big}, finding.SevLow},
		{"unknown content, small", dumpHit{Size: 8 << 10, Remote: true}, finding.SevInfo},
	}
	for _, c := range cases {
		if got := c.h.severity(); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	f := dumpHit{Repo: "~/src/shop", Path: "db/production_latest_backup.sql", Size: big, ProdName: true, Content: contentData,
		Remote: true, OnRemoteBranch: true, Visibility: "PRIVATE"}.toFinding()
	if f.Title != "Production database dump in the git history of ~/src/shop: db/production_latest_backup.sql (12 MB, pushed)" {
		t.Errorf("title %q", f.Title)
	}
	if f.Kind != finding.KindExposure || f.Resource.Type != "data_dump" || f.Resource.ID != "~/src/shop:db/production_latest_backup.sql" || f.Remediation.Action != "" || f.Scope != "dumps:~/src/shop" {
		t.Errorf("finding %+v", f)
	}
	for _, want := range []string{"git filter-repo --path 'db/production_latest_backup.sql' --invert-paths", "force-push", "re-clone", "segurata never rewrites history", secretrisk.URLAEPDBreaches, secretrisk.URLEDPBBreaches} {
		if !strings.Contains(f.Remediation.Summary, want) {
			t.Errorf("remediation lacks %q: %s", want, f.Remediation.Summary)
		}
	}
}

func TestDumpGuards(t *testing.T) {
	refused := func(c cli.Checker, args ...string) bool { return errors.Is(c.Check(args), cli.ErrRefused) }
	blob := strings.Repeat("a", 40)
	for _, ok := range [][]string{
		{"--git-dir=/r/.git", "log", "--all", "--no-renames", "--diff-filter=A", "--name-only", "--format=", "-z"},
		{"--git-dir=/r/.git", "log", "--all", "--raw", "--no-abbrev", "--format=%x01%H", "-z", "--", ":(literal)-p", "--output=x"},
		{"--git-dir=/r/.git", "cat-file", "-s", blob},
		{"--git-dir=/r/.git", "--work-tree=/r", "ls-files", "-s", "-z"},
		{"--git-dir=/r/.git", "rev-list", "--no-walk", "--all"},
	} {
		if refused(gitCheck, ok...) {
			t.Errorf("read-only git refused: %v", ok)
		}
	}
	for _, bad := range [][]string{
		{"--git-dir=/r/.git", "log", "-p"},
		{"--git-dir=/r/.git", "log", "--output=/tmp/x", "--all"},
		{"--git-dir=/r/.git", "log", "--ext-diff", "--all"},
		{"--git-dir=/r/.git", "log", "--textconv"},
		{"--git-dir=/r/.git", "cat-file", "-p", blob},
		{"--git-dir=/r/.git", "cat-file", "blob", blob},
		{"--git-dir=/r/.git", "cat-file", "-s", "HEAD"},
		{"-c", "core.pager=sh", "log"},
		{"--git-dir=/r/.git", "config", "x"},
		{"--git-dir=/r/.git"},
	} {
		if !refused(gitCheck, bad...) {
			t.Errorf("git allowed: %v", bad)
		}
	}
	if refused(gitHeadCheck, "--git-dir=/r/.git", "cat-file", "blob", blob) || !refused(gitHeadCheck, "--git-dir=/r/.git", "cat-file", "blob", "HEAD:x") ||
		!refused(gitHeadCheck, "--git-dir=/r/.git", "cat-file", "-p", blob) {
		t.Error("git head check")
	}
	if refused(ghCheck, "repo", "view", "o/r", "--json", "visibility") || !refused(ghCheck, "repo", "delete", "o/r") ||
		!refused(ghCheck, "repo", "view", "o/r", "--web") || !refused(ghCheck, "api", "-X", "DELETE", "repos/o/r") {
		t.Error("gh check")
	}
}

func TestDataDumpsSetting(t *testing.T) {
	for v, want := range map[any]dumpMode{nil: dumpsOn, true: dumpsOn, false: dumpsOff, "only": dumpsOnly} {
		cfg := map[string]any{}
		if v != nil {
			cfg["data_dumps"] = v
		}
		s, err := parseSettings(cfg, "/h")
		if err != nil || s.dumps != want {
			t.Errorf("data_dumps %v: %v %v", v, s.dumps, err)
		}
	}
	if _, err := parseSettings(map[string]any{"data_dumps": "yes"}, "/h"); err == nil {
		t.Error("bad data_dumps accepted")
	}
}

// countingGit runs the real git and counts each subcommand, so tests can see what a run asked.
type countingGit struct {
	mu    sync.Mutex
	calls map[string]int
	run   cli.Runner
}

func newCountingGit(r cli.Runner) *countingGit { return &countingGit{calls: map[string]int{}, run: r} }

func (g *countingGit) Run(ctx context.Context, args ...string) ([]byte, error) {
	sub := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			sub = a
			break
		}
	}
	g.mu.Lock()
	g.calls[sub]++
	g.mu.Unlock()
	return g.run.Run(ctx, args...)
}

func (g *countingGit) reset() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.calls
	g.calls = map[string]int{}
	return c
}

func (r *historyRepo) writeFile(rel string, data []byte) {
	p := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *historyRepo) commitAll(msg string) string {
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

// newDumpRepo builds a repository with every kind of candidate: a production dump committed and
// later deleted, a tracked SQLite file, excluded schema, migration, fixture and small files, and a
// remote whose tracking ref holds the dump.
func newDumpRepo(t *testing.T) (*historyRepo, string) {
	r := newHistoryRepo(t)
	r.writeFile("README.md", []byte("shop\n"))
	r.writeFile("db/production_latest_backup.sql", []byte(fakeRows("users", 400)))
	r.writeFile("db/structure.sql", []byte(fakeRows("structure", 400)))
	r.writeFile("db/migrate/001_init.sql", []byte(fakeRows("mig", 400)))
	r.writeFile("db/seeds.sql", []byte(fakeRows("seed", 400)))
	r.writeFile("test/fixtures/sample.sql", []byte(fakeRows("fixture", 400)))
	r.writeFile("tiny.sql", []byte(fakeRows("tiny", 2)))
	first := r.commitAll("initial")
	r.git("remote", "add", "origin", "git@github.com:acme/shop.git")
	r.git("update-ref", "refs/remotes/origin/main", first)
	r.git("rm", "-q", "db/production_latest_backup.sql")
	r.writeFile("data/app.sqlite3", append([]byte("SQLite format 3\x00"), bytes.Repeat([]byte{0}, 8192)...))
	r.writeFile("data.sql", []byte("CREATE TABLE a (id int);\n"+strings.Repeat("-- comment line\n", 400)))
	r.commitAll("drop the dump, add a database")
	return r, first
}

func (r *historyRepo) dumpScan(git, head, gh cli.Runner) (*scan, *recorder) {
	c := &Connector{
		Git: git, GitHead: head, GH: gh,
		LookPath: func(string) (string, error) { return "/bin/true", nil },
		CacheDir: DefaultCacheDir,
		Now:      func() time.Time { return time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) },
	}
	cfg := settings{reposRoot: filepath.Join(r.home, "src"), workers: 2, timeout: time.Minute, gitCache: true}
	rec := &recorder{}
	return newScan(context.Background(), c, r.home, cfg, fingerprint.FromBytes(bytes.Repeat([]byte{1}, 32)), rec), rec
}

func publicGH(calls *int) cli.Runner {
	return cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
		*calls++
		if args[2] != "acme/shop" {
			return nil, errors.New("unknown repository")
		}
		return []byte(`{"visibility":"PUBLIC"}`), nil
	})
}

func TestDataDumpsInARealRepository(t *testing.T) {
	r, first := newDumpRepo(t)
	ghCalls := 0
	s, _ := r.dumpScan(cli.Exec{Path: "git", Timeout: time.Minute}, headExec{Path: "git", Limit: dumpPeekSize, Timeout: time.Minute}, publicGH(&ghCalls))
	s.dumpsAll()
	got, repos := s.dumpFindings()
	if repos != 1 || len(got) != 3 {
		var titles []string
		for _, f := range got {
			titles = append(titles, f.Title)
		}
		t.Fatalf("want 3 dumps in 1 repository, got %d in %d: %v", len(got), repos, titles)
	}
	by := map[string]finding.Finding{}
	for _, f := range got {
		by[evidence(f, "path")] = f
	}
	prod := by["db/production_latest_backup.sql"]
	if prod.Severity != finding.SevCritical || evidence(prod, "tracked") != "false" || evidence(prod, "in_working_tree") != "false" ||
		evidence(prod, "on_remote_branch") != "true" || evidence(prod, "visibility") != "PUBLIC" || evidence(prod, "header") != "INSERT INTO" ||
		evidence(prod, "first_commit") != first[:10] || evidence(prod, "production_name") != "true" {
		t.Errorf("production dump: %s %v", prod.Severity, prod.Evidence)
	}
	if !strings.HasPrefix(prod.Title, "Production database dump in the git history of ~/src/repo: db/production_latest_backup.sql (") ||
		!strings.HasSuffix(prod.Title, "KB, pushed to a public repository)") {
		t.Errorf("title %q", prod.Title)
	}
	size := int64(len(fakeRows("users", 400)))
	if evidence(prod, "size_bytes") != fmt.Sprint(size) {
		t.Errorf("size %s, want %d", evidence(prod, "size_bytes"), size)
	}
	db := by["data/app.sqlite3"]
	if db.Severity != finding.SevCritical || evidence(db, "tracked") != "true" || evidence(db, "in_working_tree") != "true" ||
		evidence(db, "header") != "SQLite format 3" || evidence(db, "on_remote_branch") != "false" {
		t.Errorf("sqlite file: %s %v", db.Severity, db.Evidence)
	}
	schema := by["data.sql"]
	if schema.Severity != finding.SevInfo || !strings.HasPrefix(schema.Title, "Database schema committed to") {
		t.Errorf("schema-only file: %s %q", schema.Severity, schema.Title)
	}
	if ghCalls != 1 {
		t.Errorf("gh asked %d times, want once per repository", ghCalls)
	}

	// gitleaks matches inside the dump are marked and become noise, except a recognisable key.
	repo := s.tilde(r.dir)
	hash := secretrisk.Evidence{Source: "gitleaks", Type: "sourcegraph-access-token", Redacted: "…(40)", Repo: repo, Path: repo + "/db/production_latest_backup.sql"}
	aws := secretrisk.Evidence{Source: "gitleaks", Type: "aws-access-key-id", Redacted: "AKIA…(20)", Repo: repo, Path: repo + "/db/production_latest_backup.sql"}
	jwtElsewhere := secretrisk.Evidence{Source: "gitleaks", Type: "jwt", Redacted: "eyJ…(200)", Repo: repo, Path: repo + "/config/app.env"}
	for _, ev := range []*secretrisk.Evidence{&hash, &aws, &jwtElsewhere} {
		s.markDump(r.dir, ev)
	}
	if !hash.InDataDump || !aws.InDataDump || jwtElsewhere.InDataDump {
		t.Fatalf("marking: %v %v %v", hash.InDataDump, aws.InDataDump, jwtElsewhere.InDataDump)
	}
	if secretrisk.ImpactOf(hash) != secretrisk.Noise || secretrisk.ImpactOf(aws) != secretrisk.High || secretrisk.ImpactOf(jwtElsewhere) == secretrisk.Noise {
		t.Error("impact of matches inside a dump")
	}
	got, _ = s.dumpFindings()
	for _, f := range got {
		if evidence(f, "path") == "db/production_latest_backup.sql" && evidence(f, "gitleaks_matches") != "2" {
			t.Errorf("gitleaks matches counted: %v", f.Evidence)
		}
	}
}

func TestDataDumpCacheReuse(t *testing.T) {
	r, _ := newDumpRepo(t)
	git := newCountingGit(cli.Exec{Path: "git", Timeout: time.Minute})
	head := newCountingGit(headExec{Path: "git", Limit: dumpPeekSize, Timeout: time.Minute})
	ghCalls := 0
	run := func() []finding.Finding {
		s, _ := r.dumpScan(git, head, publicGH(&ghCalls))
		s.dumpsAll()
		f, _ := s.dumpFindings()
		return f
	}
	first := run()
	if c := git.reset(); c["log"] == 0 || c["cat-file"] == 0 {
		t.Fatalf("first run did not read the history: %v", c)
	}
	head.reset()
	files, _ := filepath.Glob(filepath.Join(r.home, ".cache", "segurata", "datadumps", "*.json"))
	if len(files) != 1 {
		t.Fatalf("dump cache files %v", files)
	}
	if st, err := os.Stat(files[0]); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cache not 0600: %v", err)
	}
	raw, _ := os.ReadFile(files[0])
	if strings.Contains(string(raw), "example.test") {
		t.Fatal("the cache holds dump content")
	}
	before, _ := os.Stat(files[0])

	second := run()
	if c := git.reset(); c["log"] != 0 || c["cat-file"] != 0 || c["rev-list"] != 1 || c["ls-files"] != 1 {
		t.Errorf("unchanged repository read again: %v", c)
	}
	if c := head.reset(); len(c) != 0 || ghCalls != 1 {
		t.Errorf("unchanged repository peeked or asked gh again: %v, gh %d", c, ghCalls)
	}
	if after, _ := os.Stat(files[0]); !after.ModTime().Equal(before.ModTime()) {
		t.Error("unchanged cache rewritten")
	}
	if len(second) != len(first) {
		t.Fatalf("cached run found %d, first %d", len(second), len(first))
	}
	for i := range first {
		if first[i].Title != second[i].Title || first[i].Severity != second[i].Severity {
			t.Errorf("cached finding differs: %q vs %q", first[i].Title, second[i].Title)
		}
	}

	// A new commit reads the history again, but known blobs are neither sized nor peeked twice.
	r.writeFile("exports/prod_users.csv", bytes.Repeat([]byte("1,user@example.test,hash\n"), (dumpLargeSize/24)+10))
	r.commitAll("an export")
	third := run()
	c := git.reset()
	if c["log"] == 0 || c["cat-file"] != 1 {
		t.Errorf("after a commit: %v (want history read, one new blob sized)", c)
	}
	if len(third) != len(first)+1 {
		t.Errorf("export not found: %d findings", len(third))
	}
}

func TestDataDumpsOnlyRunsNothingElse(t *testing.T) {
	r, _ := newDumpRepo(t)
	ghCalls := 0
	c := &Connector{
		Git: cli.Exec{Path: "git", Timeout: time.Minute}, GitHead: headExec{Path: "git", Limit: dumpPeekSize, Timeout: time.Minute}, GH: publicGH(&ghCalls),
		LookPath: func(string) (string, error) { return "", errors.New("RG, gitleaks and ssh-keygen must not be needed") },
		Home:     func() (string, error) { return r.home, nil },
		KeyPath:  func(home string) string { return filepath.Join(home, ".config", "segurata", "fingerprint.key") },
		CacheDir: DefaultCacheDir,
		Now:      time.Now,
	}
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": "only"}}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.findings) != 3 || len(rec.statuses) != 1 || !strings.Contains(rec.statuses[0].Detail, "data dumps: 3 in 1 of 1 repositories (0 from cache)") {
		t.Errorf("findings %d, statuses %+v", len(rec.findings), rec.statuses)
	}
	for _, f := range rec.findings {
		if f.Resource.Type != "data_dump" {
			t.Errorf("only data dumps expected, got %s", f.Title)
		}
	}
}

func TestHeadExecReadsOnlyTheStart(t *testing.T) {
	r := newHistoryRepo(t)
	r.writeFile("big.sql", []byte(fakeRows("users", 5000)))
	r.commitAll("big")
	blob := r.git("rev-parse", "HEAD:big.sql")
	h := headExec{Path: "git", Limit: dumpPeekSize, Timeout: time.Minute}
	out, err := guardGitHead(h).Run(context.Background(), gitDirArg(r.dir), "cat-file", "blob", blob)
	if err != nil || len(out) != dumpPeekSize || !strings.HasPrefix(string(out), "SET statement_timeout") {
		t.Fatalf("head: %d bytes, %v", len(out), err)
	}
	if _, err := h.Run(context.Background(), gitDirArg(r.dir), "cat-file", "blob", strings.Repeat("0", 40)); err == nil {
		t.Error("a missing object is not an error")
	}
}

func TestGithubSlug(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	_ = os.WriteFile(p, []byte("[remote \"fork\"]\n\turl = https://github.com/me/shop\n[remote \"origin\"]\n\turl = git@github.com:acme/shop.git\n[branch \"main\"]\n\tremote = origin\n"), 0o600)
	if got := githubSlug(p); got != "acme/shop" {
		t.Errorf("slug %q", got)
	}
	_ = os.WriteFile(p, []byte("[remote \"origin\"]\n\turl = git@gitlab.com:acme/shop.git\n"), 0o600)
	if got := githubSlug(p); got != "" {
		t.Errorf("non-GitHub remote gave %q", got)
	}
}

func TestGitleaksReplayMarksMatchesInDumps(t *testing.T) {
	r := newHistoryRepo(t)
	secret := fake("sk_live_", 40)
	r.writeFile("backup/prod.sql", []byte(fakeRows("users", 200)+"INSERT INTO keys VALUES ('"+secret+"');\n"))
	c := r.commitAll("dump")
	r.secrets[c], r.files[c] = secret, "backup/prod.sql"
	sc, _ := r.dumpScan(cli.Exec{Path: "git", Timeout: time.Minute}, nil, nil)
	sc.c.Gitleaks = r.gitleaks()
	if err := sc.gitleaks(r.dir); err != nil {
		t.Fatal(err)
	}
	got, _ := sc.findings()
	if len(got) != 1 || evidence(got[0], "in_data_dump") != "true" || got[0].Severity == finding.SevInfo {
		t.Fatalf("live Stripe key inside a dump: %+v", got)
	}
	dumps, _ := sc.dumpFindings()
	if len(dumps) != 1 || evidence(dumps[0], "gitleaks_matches") != "1" {
		t.Fatalf("dump finding: %+v", dumps)
	}

	// data_dumps: false leaves gitleaks evidence alone.
	off, _ := r.dumpScan(cli.Exec{Path: "git", Timeout: time.Minute}, nil, nil)
	off.cfg.dumps = dumpsOff
	off.c.Gitleaks = r.gitleaks()
	if err := off.gitleaks(r.dir); err != nil {
		t.Fatal(err)
	}
	if got, _ := off.findings(); len(got) != 1 || evidence(got[0], "in_data_dump") != "<nil>" {
		t.Fatalf("marked with data_dumps off: %+v", got[0].Evidence)
	}
}

func utf16le(s string) []byte {
	out := []byte{0xff, 0xfe}
	for _, r := range []byte(s) {
		out = append(out, r, 0)
	}
	return out
}

// A dump added and deleted on a branch that was merged leaves the merge TREESAME to its first
// parent, so a plain `git log -- <path>` simplifies the branch away. The check must still see it.
func TestDumpAddedOnAMergedBranch(t *testing.T) {
	r := newHistoryRepo(t)
	r.writeFile("README.md", []byte("x\n"))
	r.commitAll("init")
	main := r.git("rev-parse", "--abbrev-ref", "HEAD")
	r.git("checkout", "-q", "-b", "side")
	r.writeFile("production_latest_backup.sql", []byte(fakeRows("users", 300)))
	added := r.commitAll("add the dump")
	r.git("rm", "-q", "production_latest_backup.sql")
	r.commitAll("remove it")
	r.git("checkout", "-q", main)
	r.writeFile("other.txt", []byte("y\n"))
	r.commitAll("main moves on")
	r.git("merge", "-q", "--no-ff", "-m", "merge", "side")
	r.git("branch", "-q", "-D", "side")

	s, _ := r.dumpScan(cli.Exec{Path: "git", Timeout: time.Minute}, headExec{Path: "git", Limit: dumpPeekSize, Timeout: time.Minute}, nil)
	s.dumpsAll()
	got, _ := s.dumpFindings()
	if len(got) != 1 || evidence(got[0], "first_commit") != added[:10] || evidence(got[0], "header") != "INSERT INTO" {
		t.Fatalf("dump on a merged branch: %+v", got)
	}
}
