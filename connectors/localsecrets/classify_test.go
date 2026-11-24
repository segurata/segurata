package localsecrets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Tests for the rules that decide whose a secret is and whether it is one: repository origin,
// fixture paths, expired STS keys, pre-signed URLs, URL hosts, notebook outputs, public OAuth
// clients and segurata's own test corpus. Every value is generated at run time.

func TestPublicOAuthClientSecretIsPublic(t *testing.T) {
	for _, c := range publicClients {
		v := c.head + fake("", publicClientLen-len(c.head)-len(c.tail)) + c.tail
		note, ok := publicValue(v)
		if !ok || !strings.Contains(note, c.name) {
			t.Errorf("%s client not recognised: %q", c.name, note)
		}
		if _, ok := publicValue(v + "x"); ok {
			t.Error("a longer value is another secret")
		}
		ver, ok := judge(specificByType("oauth-client-secret"), v, "", time.Now())
		if !ok || !ver.public {
			t.Errorf("judge: %+v", ver)
		}
	}
	if _, ok := publicValue(fake("", publicClientLen)); ok {
		t.Error("a random client secret is not public")
	}
}

func TestSampleValue(t *testing.T) {
	for _, v := range []string{"sk_live_" + fake("", 10) + "TEST" + fake("", 10), fake("", 12) + "1234" + fake("", 8), fake("", 10) + "zzzz" + fake("", 10), "AKIAFAKE" + fake("", 12)} {
		if !sampleValue(v) {
			t.Errorf("%d-char sample-like value not flagged", len(v))
		}
	}
	seeded := 0
	for range 200 {
		if sampleValue(fake("", 40)) {
			seeded++
		}
	}
	if seeded > 10 {
		t.Errorf("%d of 200 random keys look like samples", seeded)
	}
}

func TestURLContextHelpers(t *testing.T) {
	m := "?access_token=" + fake("", 24)
	line := `curl -s "https://api.Acme.io:8443/v1/items` + m + `&page=2"`
	if s, h := urlBefore(line, m); s != "https" || h != "api.acme.io" {
		t.Errorf("urlBefore: %q %q", s, h)
	}
	if s, h := urlBefore("token list "+m, m); s != "" || h != "" {
		t.Errorf("a bare query string has no host: %q %q", s, h)
	}
	if _, h := urlBefore("postgres://u:p@10.0.0.5/db"+m, m); h != "10.0.0.5" {
		t.Errorf("credentials before the host: %q", h)
	}
	if queryParam("&API_KEY="+fake("", 20)) != "api_key" {
		t.Error("queryParam")
	}
}

func TestNotebookSourceLines(t *testing.T) {
	nb := strings.Join([]string{
		`{`,
		` "cells": [`,
		`  {`,
		`   "cell_type": "code",`,
		`   "metadata": {"tags": ["x"]},`,
		`   "outputs": [`,
		`    {`,
		`     "data": {`,
		`      "image/png": "iVBORw0KGgo"`,
		`     },`,
		`     "output_type": "display_data"`,
		`    }`,
		`   ],`,
		`   "source": [`,
		`    "key = \"abc\"\n",`,
		`    "print(key) # [brackets] {braces}"`,
		`   ]`,
		`  },`,
		`  {"cell_type": "markdown", "source": "# Title"}`,
		` ],`,
		` "nbformat": 4`,
		`}`,
	}, "\n")
	lines := notebookSourceLines([]byte(nb))
	want := []int{15, 16, 19}
	for l := 1; l <= 22; l++ {
		if lines[l] != slices.Contains(want, l) {
			t.Errorf("line %d: source=%v", l, lines[l])
		}
	}
	if notebookSourceLines([]byte(`{"cells": [`)) != nil || notebookSourceLines(nil) != nil {
		t.Error("broken JSON must give nil (keep every match)")
	}
}

func TestNotebookOutputsAreIgnoredInHistory(t *testing.T) {
	r := newHistoryRepo(t)
	inSource, inOutput := fake("EAAA", 40), fake("EAAA", 40)
	nb := "{\n \"cells\": [\n  {\n   \"outputs\": [\n    {\"text\": [\"" + inOutput + "\"]}\n   ],\n   \"source\": [\n    \"tok = '" + inSource + "'\"\n   ]\n  }\n ]\n}\n"
	r.writeFile("lesson.ipynb", []byte(nb))
	c := r.commitAll("notebook")
	sc, _ := r.dumpScan(cli.Exec{Path: "git", Timeout: time.Minute}, nil, nil)
	sc.cfg.dumps, sc.cfg.emitNoise = dumpsOff, true
	sc.c.Gitleaks = cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "version" {
			return []byte("8.30.1\n"), nil
		}
		return json.Marshal([]map[string]any{
			{"RuleID": "square-access-token", "File": "lesson.ipynb", "StartLine": 5, "Secret": inOutput, "Commit": c, "Date": "2017-10-19T00:00:00Z"},
			{"RuleID": "square-access-token", "File": "lesson.ipynb", "StartLine": 8, "Secret": inSource, "Commit": c, "Date": "2017-10-19T00:00:00Z"},
		})
	})
	if err := sc.gitleaks(r.dir); err != nil {
		t.Fatal(err)
	}
	got, _ := sc.findings()
	if len(got) != 1 || evidence(got[0], "line") != "8" {
		t.Fatalf("want only the source-cell match, got %d: %+v", len(got), got)
	}
}

func TestClassifyOrigin(t *testing.T) {
	names := map[string]bool{"me": true, "my-org": true}
	cases := []struct {
		remotes []githubRemote
		want    repoOrigin
	}{
		{nil, repoOrigin{}},
		{[]githubRemote{{"origin", "instructure/canvas-lms"}}, repoOrigin{origin: secretrisk.OriginThirdParty}},
		{[]githubRemote{{"origin", "My-Org/app"}}, repoOrigin{origin: secretrisk.OriginOwned}},
		{[]githubRemote{{"origin", "me/sure"}, {"upstream", "we-promise/sure"}}, repoOrigin{origin: secretrisk.OriginOwned, upstream: "upstream"}},
		{[]githubRemote{{"origin", "me/a"}, {"mirror", "my-org/a"}}, repoOrigin{origin: secretrisk.OriginOwned}},
	}
	for _, c := range cases {
		if got := classifyOrigin(c.remotes, names); got != c.want {
			t.Errorf("%v: %+v, want %+v", c.remotes, got, c.want)
		}
	}
	if got := classifyOrigin([]githubRemote{{"origin", "instructure/canvas-lms"}}, nil); got != (repoOrigin{}) {
		t.Errorf("no known owner: %+v", got)
	}
}

func TestGithubRemotesOriginFirst(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	cfg := "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = https://github.com/we-promise/sure.git\n" +
		"[remote \"gitlab\"]\n\turl = git@gitlab.com:me/sure.git\n[remote \"origin\"]\n\turl = git@github.com:me/sure.git\n"
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	got := githubRemotes(p)
	want := []githubRemote{{"origin", "me/sure"}, {"upstream", "we-promise/sure"}}
	if !slices.Equal(got, want) || githubSlug(p) != "me/sure" {
		t.Errorf("remotes %+v", got)
	}
}

func TestInheritedCommitsOfAFork(t *testing.T) {
	r := newHistoryRepo(t)
	upstreamCommit, _ := r.commit("a.env")
	r.git("remote", "add", "upstream", "https://github.com/acme/tool.git")
	r.git("update-ref", "refs/remotes/upstream/main", upstreamCommit)
	ownCommit, _ := r.commit("b.env")
	sc, _ := r.dumpScan(cli.Exec{Path: "git", Timeout: time.Minute}, nil, nil)
	got := sc.inheritedCommits(r.dir, "upstream", []string{upstreamCommit[:10], ownCommit[:10]})
	if !got[upstreamCommit[:10]] || got[ownCommit[:10]] {
		t.Errorf("inherited %v", got)
	}
	if sc.inheritedCommits(r.dir, "nowhere", []string{ownCommit[:10]}) != nil {
		t.Error("an upstream without fetched branches tells nothing")
	}
	if sc.inheritedCommits(r.dir, "upstream", []string{"0123456789"}) != nil {
		t.Error("an unknown commit must not count as inherited")
	}
}

// ownersFixture is a home with three repositories: the owner's (my-org/app), a clone of someone
// else's (instructure/canvas-lms) and segurata's own; gh says the user is "me" in "my-org".
type ownersFixture struct {
	home        string
	shared      string // a key committed to the owner's repository and to the third-party one
	upstreamKey string // a key only the third-party repository has
	reusedKey   string // a key committed to the third-party repository and kept in ~/.zshrc
	ghCalls     int
}

func newOwnersFixture(t *testing.T) (*ownersFixture, *Connector) {
	fx := &fixture{home: t.TempDir()}
	o := &ownersFixture{home: fx.home, shared: fake("sk_live_", 40), upstreamKey: fake("sk_live_", 40), reusedKey: fake("sk_live_", 40)}
	repo := func(name, url string) string {
		fx.write(t, "src/"+name+"/.git/config", "[remote \"origin\"]\n\turl = "+url+"\n", 0o600)
		return filepath.Join(fx.home, "src", name)
	}
	mine, theirs := repo("app", "git@github.com:My-Org/app.git"), repo("canvas-lms", "https://github.com/instructure/canvas-lms.git")
	self := repo("segurata", "git@github.com:segurata/segurata.git")
	fx.write(t, "src/segurata/go.mod", "module "+selfModule+"\n\ngo 1.25\n", 0o600)
	fx.write(t, "src/segurata/.env", "STRIPE_KEY="+fake("sk_live_", 40)+"\n", 0o600)
	fx.write(t, ".zshrc", "export STRIPE_KEY="+o.reusedKey+"\n", 0o600)
	leak := func(file, secret string) map[string]any {
		return map[string]any{"RuleID": "stripe-access-token", "File": file, "StartLine": 1, "Secret": secret, "Commit": "0123456789abcdef", "Date": "2024-05-01T00:00:00Z"}
	}
	reports := map[string][]map[string]any{
		mine:   {leak("config/live.env", o.shared)},
		theirs: {leak("config/a.env", o.shared), leak("config/b.env", o.upstreamKey), leak("config/c.env", o.reusedKey)},
		self:   {leak("internal/testcorpus/corpus.go", fake("sk_live_", 40))},
	}
	rg, err := exec.LookPath("rg")
	if err != nil {
		t.Skip("ripgrep not installed")
	}
	c := &Connector{
		RG: cli.Exec{Path: rg, Timeout: time.Minute},
		Gitleaks: cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
			if args[0] == "version" {
				return []byte("8.30.1\n"), nil
			}
			return json.Marshal(reports[args[len(args)-1]])
		}),
		Git: cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
			if args[1] == "rev-list" && args[2] == "--no-walk" {
				return []byte(strings.Repeat("a", 40) + "\n"), nil
			}
			return nil, nil
		}),
		GH: cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
			o.ghCalls++
			switch strings.Join(args, " ") {
			case "api user":
				return []byte(`{"login":"me"}`), nil
			case "api user/orgs?per_page=100":
				return []byte(`[{"login":"my-org"}]`), nil
			}
			return nil, errors.New("unexpected gh call")
		}),
		SSHKeygen: &fakeTool{reply: func([]string) ([]byte, error) { return nil, errors.New("no keys") }},
		LookPath:  func(string) (string, error) { return "/bin/true", nil },
		Home:      func() (string, error) { return fx.home, nil },
		KeyPath:   func(home string) string { return filepath.Join(home, ".config", "segurata", "fingerprint.key") },
		CacheDir:  DefaultCacheDir,
		Now:       func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) },
	}
	return o, c
}

func TestThirdPartyRepositoriesAreNotTheOwners(t *testing.T) {
	o, c := newOwnersFixture(t)
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false, "emit_noise": true}}, rec); err != nil {
		t.Fatal(err)
	}
	byPath := map[string]finding.Finding{}
	for _, f := range rec.findings {
		byPath[evidence(f, "path")] = f
	}
	check := func(path string, sev finding.Severity, origin, reused string) {
		t.Helper()
		f, ok := byPath[path]
		if !ok {
			t.Fatalf("no finding for %s", path)
		}
		if f.Severity != sev || evidence(f, "origin") != origin || evidence(f, "reused") != reused {
			t.Errorf("%s: %s origin=%s reused=%s", path, f.Severity, evidence(f, "origin"), evidence(f, "reused"))
		}
	}
	check("~/src/app/config/live.env", finding.SevCritical, secretrisk.OriginOwned, "<nil>")
	// The shared key is the owner's (their repository holds it): its third-party copy counts.
	check("~/src/canvas-lms/config/a.env", finding.SevCritical, secretrisk.OriginThirdParty, "true")
	check("~/src/canvas-lms/config/b.env", finding.SevInfo, secretrisk.OriginThirdParty, "<nil>")
	check("~/src/canvas-lms/config/c.env", finding.SevCritical, secretrisk.OriginThirdParty, "true")
	for p := range byPath {
		if strings.HasPrefix(p, "~/src/segurata/") {
			t.Errorf("segurata's own repository scanned: %s", p)
		}
	}
	if !strings.Contains(rec.statuses[0].Detail, "1 in segurata's own repositories skipped") {
		t.Errorf("status: %s", rec.statuses[0].Detail)
	}

	// The owner's names are cached: a second run asks gh nothing.
	calls := o.ghCalls
	if calls != 2 {
		t.Errorf("gh calls on the first run: %d", calls)
	}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, &recorder{}); err != nil {
		t.Fatal(err)
	}
	if o.ghCalls != calls {
		t.Errorf("gh asked again within the cache's lifetime")
	}
	if st, err := os.Stat(filepath.Join(o.home, ".cache", "segurata", "github-owners.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("owners cache: %v", err)
	}
}

func TestOwnedOwnersConfigWithoutGH(t *testing.T) {
	_, c := newOwnersFixture(t)
	c.GH = nil
	run := func(cfg map[string]any) map[string]finding.Severity {
		cfg["data_dumps"], cfg["emit_noise"] = false, true
		rec := &recorder{}
		if err := c.Inventory(context.Background(), connector.Request{Config: cfg}, rec); err != nil {
			t.Fatal(err)
		}
		out := map[string]finding.Severity{}
		for _, f := range rec.findings {
			out[evidence(f, "path")] = f.Severity
		}
		return out
	}
	// No gh and no config: nobody is known, so nothing is third-party.
	if got := run(map[string]any{}); got["~/src/canvas-lms/config/b.env"] != finding.SevCritical {
		t.Errorf("unknown ownership must count as the owner's: %v", got)
	}
	if got := run(map[string]any{"owned_owners": []any{"my-org"}}); got["~/src/canvas-lms/config/b.env"] != finding.SevInfo {
		t.Errorf("owned_owners: %v", got)
	}
}

func TestTemporaryAWSAndPresignedURLs(t *testing.T) {
	fx := newFixture(t)
	sts := func() string { return "ASIA" + strings.ToUpper(fake("", 16)) }
	var urls []string
	for range 3 {
		urls = append(urls, "https://b.s3.amazonaws.com/f.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential="+sts()+"%2F20241101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature="+fake("", 64))
	}
	fx.write(t, "src/shop/.env.signed", "LINKS="+strings.Join(urls, " ")+"\n", 0o600)
	fx.write(t, "src/shop/.env.old", "AWS_ACCESS_KEY_ID="+sts()+"\n", 0o600)
	fx.write(t, "src/shop/.env.fresh", "AWS_ACCESS_KEY_ID="+sts()+"\n", 0o600)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	for _, f := range []string{".env.signed", ".env.old"} {
		if err := os.Chtimes(filepath.Join(fx.home, "src/shop", f), now.Add(-48*time.Hour), now.Add(-48*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Join(fx.home, "src/shop/.env.fresh"), now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	c := fx.connector(t, "[]")
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"emit_noise": true}}, rec); err != nil {
		t.Fatal(err)
	}
	got := map[string][]finding.Finding{}
	for _, f := range rec.findings {
		got[evidence(f, "path")] = append(got[evidence(f, "path")], f)
	}
	signed := got["~/src/shop/.env.signed"]
	if len(signed) != 1 || evidence(signed[0], "type") != "aws-presigned-url" || evidence(signed[0], "count") != "3" ||
		signed[0].Severity != finding.SevInfo || !strings.Contains(evidence(signed[0], "note"), "3 temporary AWS credentials or pre-signed URLs, all expired") {
		t.Errorf("pre-signed URLs: %+v", signed)
	}
	if old := got["~/src/shop/.env.old"]; len(old) != 1 || old[0].Severity != finding.SevInfo || evidence(old[0], "public") != "true" {
		t.Errorf("STS key two days old: %+v", old)
	}
	if fresh := got["~/src/shop/.env.fresh"]; len(fresh) != 1 || fresh[0].Severity != finding.SevLow {
		t.Errorf("STS key an hour old: %+v", fresh)
	}
}

func TestURLHostsAndGcloudFiles(t *testing.T) {
	fx := newFixture(t)
	neon := "postgresql://app:" + fake("", 20) + "@ep-x-1.eu-central-1.aws.neon.tech/shop"
	local := "postgresql://app:" + fake("", 20) + "@127.0.0.1:5432/shop"
	tokURL := "https://api.acme.io/v1/export?access_token=" + fake("", 32)
	fx.write(t, ".claude/projects/p/urls.jsonl", `{"a":"`+neon+`","b":"`+local+`","c":"`+tokURL+`"}`+"\n", 0o600)
	adc, _ := json.Marshal(map[string]string{"type": "authorized_user", "client_id": "32555940559.apps.googleusercontent.com",
		"client_secret": publicClients[0].head + fake("", 13) + publicClients[0].tail, "refresh_token": "1//0" + fake("", 60)})
	fx.write(t, ".config/gcloud/application_default_credentials.json", string(adc), 0o600)
	fx.write(t, ".config/gcloud/logs/2026.11.24/10.00.00.log", "Authorization: Bearer ya29 refresh_token="+fake("", 40)+"\n", 0o600)
	c := fx.connector(t, "[]")
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"emit_noise": true}}, rec); err != nil {
		t.Fatal(err)
	}
	byNote := map[string]finding.Finding{}
	for _, f := range rec.findings {
		if strings.HasPrefix(evidence(f, "path"), "~/.config/gcloud/logs") {
			t.Errorf("gcloud log scanned: %s", f.Title)
		}
		byNote[evidence(f, "type")+" "+evidence(f, "note")] = f
	}
	want := map[string]finding.Severity{
		"url-credentials postgresql://…@ep-x-1.eu-central-1.aws.neon.tech": finding.SevCritical, // high × transcript
		"url-credentials postgresql://…@127.0.0.1":                         finding.SevInfo,
		"url-token-param https://api.acme.io/…?access_token=…":             finding.SevHigh, // medium × transcript
		"oauth-client-secret public OAuth client of Google Cloud SDK":      finding.SevInfo,
		"oauth-refresh-token <nil>":                                        finding.SevLow, // the refresh token beside it is still a secret
	}
	for k, sev := range want {
		f, ok := byNote[k]
		if !ok {
			keys := make([]string, 0, len(byNote))
			for kk := range byNote {
				keys = append(keys, kk)
			}
			t.Errorf("no finding %q; have %v", k, keys)
			continue
		}
		if f.Severity != sev {
			t.Errorf("%s: %s, want %s", k, f.Severity, sev)
		}
	}
}

func TestFixturePathsLowerImpact(t *testing.T) {
	fx := newFixture(t)
	real := fake("sk_live_", 40)
	sample := "sk_live_" + fake("", 12) + "TEST" + fake("", 20)
	report, _ := json.Marshal([]map[string]any{
		{"RuleID": "stripe-access-token", "File": "src/Register.test.tsx", "StartLine": 4, "Secret": real, "Commit": "0123456789ab", "Date": "2024-01-01T00:00:00Z"},
		{"RuleID": "stripe-access-token", "File": "test/integration/setup.ts", "StartLine": 2, "Secret": sample, "Commit": "0123456789ab", "Date": "2024-01-01T00:00:00Z"},
		{"RuleID": "stripe-access-token", "File": "files.md5", "StartLine": 2, "Secret": fake("sk_live_", 40), "Commit": "0123456789ab", "Date": "2024-01-01T00:00:00Z"},
	})
	c := fx.connector(t, string(report))
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	got := map[string]finding.Severity{}
	for _, f := range rec.findings {
		got[evidence(f, "path")] = f.Severity
	}
	if got["~/src/shop/src/Register.test.tsx"] != finding.SevHigh { // high − 1 = medium, × pushed history
		t.Errorf("live key in a test file: %v", got)
	}
	for _, p := range []string{"~/src/shop/test/integration/setup.ts", "~/src/shop/files.md5"} {
		if _, ok := got[p]; ok {
			t.Errorf("%s should be noise, not emitted", p)
		}
	}
}

func TestNewGuardShapes(t *testing.T) {
	refused := func(c cli.Checker, args ...string) bool { return errors.Is(c.Check(args), cli.ErrRefused) }
	if refused(ghCheck, "api", "user") || refused(ghCheck, "api", "user/orgs?per_page=100") {
		t.Error("gh reads of the user refused")
	}
	if !refused(ghCheck, "api", "-X", "DELETE", "user") || !refused(ghCheck, "api", "user/repos") || !refused(ghCheck, "api", "graphql") {
		t.Error("gh api beyond the two reads allowed")
	}
	if refused(gitCheck, "--git-dir=/r/.git", "cat-file", "blob", "0123456789:nb/a b.ipynb") {
		t.Error("cat-file blob <commit>:<path> refused")
	}
	if !refused(gitCheck, "--git-dir=/r/.git", "cat-file", "blob", "HEAD:x") || !refused(gitCheck, "--git-dir=/r/.git", "cat-file", "--textconv", "0123456789:x") {
		t.Error("cat-file with a symbolic ref or textconv allowed")
	}
	if refused(gitCheck, "--git-dir=/r/.git", "rev-list", "0123456789", "--not", "--remotes=upstream") {
		t.Error("fork history check refused")
	}
}

func TestSettingsOwnersAndNoise(t *testing.T) {
	s, err := parseSettings(map[string]any{"owned_owners": []any{"me", "my-org"}, "emit_noise": true}, "/h")
	if err != nil || !slices.Equal(s.ownedOwners, []string{"me", "my-org"}) || !s.emitNoise {
		t.Fatalf("settings %+v err %v", s, err)
	}
	for _, bad := range []any{"me", []any{"me", 3}, []any{""}} {
		if _, err := parseSettings(map[string]any{"owned_owners": bad}, "/h"); err == nil {
			t.Errorf("owned_owners %v accepted", bad)
		}
	}
}

func TestNoiseCountsLine(t *testing.T) {
	var n noiseCounts
	if n.String() != "" {
		t.Error("nothing left out, nothing said")
	}
	for i := range maxNoisePlaces + 2 {
		n.add(secretrisk.Evidence{Type: "generic-api-key", Repo: "~/src/r" + string(rune('a'+i))})
	}
	n.add(secretrisk.Evidence{Type: "assignment", Kind: "config"})
	got := n.String()
	if !strings.Contains(got, "noise not emitted (emit_noise: true lists it): 28; by type: generic-api-key 27, assignment 1;") ||
		!strings.HasSuffix(got, ", 3 more places 3") {
		t.Errorf("noise line: %s", got)
	}
}

// Every hint the connector writes has one shape, prefix…tail(len), and reads back with
// secretrisk.ParseHint: the format `rotations replace` and the correlations rely on.
func TestEveryHintHasTheSharedFormat(t *testing.T) {
	for _, p := range withAssignment {
		prefixes := strings.Split(p.prefix, "|")
		v := prefixes[0] + fake("", 40)
		hint := secretrisk.Redact(p.typ, p.prefix, v)
		h, ok := secretrisk.ParseHint(hint)
		if !ok || !h.Fits(v) || h.Prefix != prefixes[0] {
			t.Errorf("%s: hint %q does not read back", p.typ, hint)
		}
		if strings.Contains(hint, v[len(prefixes[0]):len(v)-4]) {
			t.Errorf("%s: hint shows the body", p.typ)
		}
	}
}

// A generic match is noise on its own, but not when the same value is a real secret elsewhere: it
// is one more place that secret went, and stays in the output.
func TestNoiseCopyOfARealSecretIsEmitted(t *testing.T) {
	fx := newFixture(t)
	key := fake("", 40)
	fx.write(t, ".aws/credentials", "[default]\naws_secret_access_key = "+key+"\n", 0o600)
	report, _ := json.Marshal([]map[string]any{
		{"RuleID": "generic-api-key", "File": "lib/s3.py", "StartLine": 3, "Secret": key, "Commit": "0123456789ab", "Date": "2019-08-01T00:00:00Z"},
		{"RuleID": "generic-api-key", "File": "lib/other.py", "StartLine": 3, "Secret": fake("", 32), "Commit": "0123456789ab", "Date": "2019-08-01T00:00:00Z"},
	})
	rec := &recorder{}
	if err := fx.connector(t, string(report)).Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	got := map[string]finding.Finding{}
	for _, f := range rec.findings {
		got[evidence(f, "path")] = f
	}
	cred, git := got["~/.aws/credentials"], got["~/src/shop/lib/s3.py"]
	if evidence(git, "fingerprint") == "<nil>" || evidence(git, "fingerprint") != evidence(cred, "fingerprint") || git.Severity != finding.SevInfo {
		t.Errorf("the generic copy of the real key: %+v", git)
	}
	if _, ok := got["~/src/shop/lib/other.py"]; ok {
		t.Error("a generic match with no real copy was emitted")
	}
}

// A copy in someone else's repository is noise and left out, unless it names an account: then the
// tracker may attribute it to the owner (an AWS key id of one of the owner's accounts), so it is
// emitted for the tracker to judge.
func TestThirdPartyCopyNamingAnAccountIsEmitted(t *testing.T) {
	copyOf := func(fp string, c attribution.Claims) secretrisk.Evidence {
		return secretrisk.Evidence{Fingerprint: fp, Type: "aws-access-key-id", Redacted: "AKIA…(20)", Path: "~/src/lms/k.py", Repo: "~/src/lms",
			Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Origin: secretrisk.OriginThirdParty, Claims: c}
	}
	sc := &scan{rows: map[string]*row{
		"a": {ev: copyOf("aaaaaaaaaaaaaaaa", attribution.Claims{AWSAccount: "171436882533"})},
		"b": {ev: copyOf("bbbbbbbbbbbbbbbb", attribution.Claims{AuthorEmail: "me@x.com"})},
	}}
	got, noise := sc.findings()
	if len(got) != 1 || evidence(got[0], "fingerprint") != "aaaaaaaaaaaaaaaa" || got[0].Severity != finding.SevInfo {
		t.Fatalf("want only the copy naming an account, as noise: %+v", got)
	}
	if noise.total != 1 || noise.types["bbbbbbbbbbbbbbbb"] == "" {
		t.Errorf("the copy naming only its author should be counted as noise: %+v", noise)
	}
}
