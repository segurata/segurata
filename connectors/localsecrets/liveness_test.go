package localsecrets

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/liveness"
	"github.com/segurata/segurata/connectors/internal/sshkey"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/testcorpus"
)

// fakeProviders answers Anthropic (every key revoked), Stripe (every key works) and AWS STS (works
// for the key ids in live), and records which credentials it was asked about.
type fakeProviders struct {
	*httptest.Server
	mu    sync.Mutex
	asked []string // the credential header of every request
}

func newFakeProviders(t *testing.T, liveKeyIDs ...string) *fakeProviders {
	f := &fakeProviders{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization") + r.Header.Get("X-Api-Key")
		f.mu.Lock()
		f.asked = append(f.asked, auth)
		f.mu.Unlock()
		switch {
		case r.Header.Get("X-Api-Key") != "": // the documented invalid-key answer
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
		case strings.HasPrefix(auth, "AWS4-HMAC-SHA256"):
			for _, id := range liveKeyIDs {
				if strings.Contains(auth, "Credential="+id+"/") {
					_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>012345678901</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))
					return
				}
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`))
		default:
			_, _ = w.Write([]byte(`{"available":[]}`))
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeProviders) askedAbout(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.asked {
		if strings.Contains(a, s) {
			return true
		}
	}
	return false
}

func (f *fakeProviders) askedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

func (fx *fixture) livenessConnector(t *testing.T, f *fakeProviders) *Connector {
	c := fx.connector(t, fx.gitleaksReport())
	c.NewChecker = func(home string, cfg liveness.Config) *liveness.Checker {
		bases := map[string][]string{}
		for _, p := range liveness.Providers() {
			bases[p] = []string{f.URL}
		}
		return &liveness.Checker{Config: cfg, Bases: bases, Interval: time.Millisecond,
			Cache: liveness.LoadCache(filepath.Join(home, ".cache", "segurata", "liveness.json"))}
	}
	return c
}

func livenessOf(t *testing.T, rec *recorder, typ string) map[string]*secretrisk.Liveness {
	t.Helper()
	out := map[string]*secretrisk.Liveness{}
	for _, f := range rec.findings {
		ev, ok := secretrisk.EvidenceOf(f)
		if ok && ev.Type == typ {
			out[ev.Source+":"+ev.Path] = ev.Liveness
		}
	}
	return out
}

func TestLivenessAtScanTime(t *testing.T) {
	fx := newFixture(t)
	mine := testcorpus.AWSKeyID("AKIA", 12345678901, false, 1)
	theirs := testcorpus.AWSKeyID("AKIA", 999999999999, false, 1)
	mineSecret, theirSecret := fake("", 40), fake("", 40)
	fx.secrets = append(fx.secrets, mine, theirs, mineSecret, theirSecret)
	fx.write(t, ".aws/credentials", "[default]\naws_access_key_id = "+mine+"\naws_secret_access_key = "+mineSecret+"\n", 0o600)
	fx.write(t, "src/legacy/.env", "AWS_ACCESS_KEY_ID="+theirs+"\naws_secret_access_key="+theirSecret+"\n", 0o600)

	f := newFakeProviders(t, mine)
	c := fx.livenessConnector(t, f)
	known := &attribution.Known{Owned: attribution.Owned{AWSAccounts: []string{"012345678901"}}}
	req := connector.Request{Known: known, Config: map[string]any{"liveness": map[string]any{"enabled": true, "owners": []any{"mine", "unknown"}}}}
	rec := &recorder{}
	if err := c.Inventory(context.Background(), req, rec); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal([]any{rec.findings, rec.statuses})
	for _, s := range fx.secrets {
		if len(s) >= 6 && strings.Contains(string(raw), s) {
			t.Fatal("a raw secret reached the output")
		}
	}
	if f.askedAbout(theirs) || f.askedAbout(theirSecret) {
		t.Error("a key attributed to someone else's AWS account was tried")
	}
	for where, l := range livenessOf(t, rec, "stripe-live") {
		if l == nil || l.State != secretrisk.Live || l.Provider != "stripe" {
			t.Errorf("stripe key at %s: %+v", where, l)
		}
	}
	if n := len(livenessOf(t, rec, "stripe-live")); n != 2 {
		t.Errorf("the stripe key's working copy and its git history both carry the result: %d", n)
	}
	for where, l := range livenessOf(t, rec, "anthropic") {
		if l == nil || l.State != secretrisk.Dead {
			t.Errorf("revoked anthropic key at %s: %+v", where, l)
		}
	}
	for _, typ := range []string{"aws-secret-key", "aws-access-key-id"} {
		for where, l := range livenessOf(t, rec, typ) {
			switch {
			case strings.Contains(where, "legacy"):
				if l != nil {
					t.Errorf("%s at %s, not-mine, has a result: %+v", typ, where, l)
				}
			case l == nil || l.State != secretrisk.Live || l.Account != "aws:012345678901":
				t.Errorf("%s at %s: %+v", typ, where, l)
			}
		}
	}
	detail := rec.statuses[0].Detail
	// The fixture's private keys are looked up too; with no gh and no ~/.ssh they stay unknown.
	if !strings.Contains(detail, "liveness: 6 asked, 0 from cache, 0 values recovered from git history; 2 live, 1 dead, 0 unregistered, 3 unknown") || !strings.Contains(detail, "1 not allowed") {
		t.Errorf("status detail: %s", detail)
	}

	// A second run finds every provider's answer in the cache and asks no provider; the unknown
	// lookups, never cached, run again.
	before := f.askedCount()
	rec2 := &recorder{}
	if err := c.Inventory(context.Background(), req, rec2); err != nil {
		t.Fatal(err)
	}
	if f.askedCount() != before || !strings.Contains(rec2.statuses[0].Detail, "3 asked, 3 from cache,") {
		t.Errorf("second run asked %d more; %s", f.askedCount()-before, rec2.statuses[0].Detail)
	}
}

func TestLivenessGates(t *testing.T) {
	cases := []struct {
		name   string
		known  *attribution.Known
		config any
		detail string
	}{
		{"off by default", &attribution.Known{}, nil, ""},
		{"off", &attribution.Known{}, map[string]any{"enabled": false}, ""},
		{"no attribution lent", nil, map[string]any{"enabled": true, "owners": []any{"unknown"}}, "liveness: not run"},
		// Only the lookups run, which send nothing: the private keys.
		{"mine only: the unknown keys stay untried", &attribution.Known{}, map[string]any{"enabled": true}, "3 asked"},
		{"provider allowlist", &attribution.Known{}, map[string]any{"enabled": true, "owners": []any{"unknown"}, "providers": []any{"github"}}, "0 asked"},
	}
	for _, tc := range cases {
		fx := newFixture(t)
		f := newFakeProviders(t)
		c := fx.livenessConnector(t, f)
		req := connector.Request{Known: tc.known}
		if tc.config != nil {
			req.Config = map[string]any{"liveness": tc.config}
		}
		rec := &recorder{}
		if err := c.Inventory(context.Background(), req, rec); err != nil {
			t.Fatal(err)
		}
		if f.askedCount() != 0 {
			t.Errorf("%s: asked %d times", tc.name, f.askedCount())
		}
		detail := rec.statuses[0].Detail
		if tc.detail == "" && strings.Contains(detail, "liveness") || tc.detail != "" && !strings.Contains(detail, tc.detail) {
			t.Errorf("%s: %s", tc.name, detail)
		}
	}
	if _, err := parseSettings(map[string]any{"liveness": map[string]any{"enabled": true, "owners": []any{"not-mine"}}}, "/h"); err == nil {
		t.Error("liveness for not-mine accepted")
	}
}

// A secret seen only in git history replayed from the gitleaks cache has no value in memory: the
// check reads it again from the commit, by its fingerprint, only when the liveness cache has no
// answer, and keeps it nowhere.
func TestLivenessRecoversCachedHistoryValues(t *testing.T) {
	r := newHistoryRepo(t)
	_, secret := r.commit("a.env")
	r.run(true, 1) // the full scan fills the gitleaks cache
	f := newFakeProviders(t)
	known := &attribution.Known{}
	check := func() (string, map[string]*secretrisk.Liveness) {
		c := &Connector{Gitleaks: r.gitleaks(), Git: cli.Exec{Path: "git", Timeout: time.Minute}, CacheDir: defaultCacheDir,
			Now: func() time.Time { return time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) },
			NewChecker: func(home string, cfg liveness.Config) *liveness.Checker {
				return &liveness.Checker{Config: cfg, Bases: map[string][]string{"stripe": {f.URL}}, Interval: time.Millisecond}
			}}
		lc, err := liveness.ParseConfig(map[string]any{"enabled": true, "owners": []any{"unknown"}})
		if err != nil {
			t.Fatal(err)
		}
		cfg := settings{reposRoot: filepath.Join(r.home, "src"), workers: 1, timeout: time.Minute, gitCache: true, liveness: lc}
		s := newScan(context.Background(), c, r.home, cfg, fingerprint.FromBytes(bytes.Repeat([]byte{1}, 32)), &recorder{})
		if err := s.gitleaks(r.dir); err != nil {
			t.Fatal(err)
		}
		if len(r.scans) != 0 {
			t.Fatalf("the history was scanned again: %v", r.scans)
		}
		fs, _ := s.findings()
		line := s.checkLiveness(context.Background(), fs, known)
		out := map[string]*secretrisk.Liveness{}
		for _, fd := range fs {
			if ev, ok := secretrisk.EvidenceOf(fd); ok && ev.Liveness != nil {
				out[ev.Path] = ev.Liveness
			}
		}
		raw, _ := json.Marshal(fs)
		if strings.Contains(string(raw)+line, secret) {
			t.Fatal("the recovered value reached the output")
		}
		return line, out
	}
	r.scans = nil
	line, got := check()
	if l := got["~/src/repo/a.env"]; l == nil || l.State != secretrisk.Live || !f.askedAbout(secret) {
		t.Fatalf("history-only secret: %+v; %s", l, line)
	}
	if !strings.Contains(line, "1 values recovered from git history") || !strings.Contains(line, "0 without a value") {
		t.Errorf("status: %s", line)
	}

	// The cached leak names a commit git no longer has: the value cannot be read, the secret stays
	// unchecked and nothing is asked.
	cache := r.cacheFile(t)
	raw, _ := os.ReadFile(cache)
	var hc historyCache
	if err := json.Unmarshal(raw, &hc); err != nil || len(hc.Leaks) != 1 {
		t.Fatalf("cache: %v", err)
	}
	hc.Leaks[0].Evidence.Commit = "0000000000"
	raw, _ = json.Marshal(hc)
	if err := os.WriteFile(cache, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	before := f.askedCount()
	line, got = check()
	if l := got["~/src/repo/a.env"]; l != nil || f.askedCount() != before || !strings.Contains(line, "1 without a value") {
		t.Errorf("unrecoverable: %+v, %d asked; %s", l, f.askedCount()-before, line)
	}
}

// Secret keys (upper case) pair with key ids (lower case) by proximity, on the side the place
// writes its key ids, one to one; a place with one key id pairs it however far, as it always did.
func TestAWSPlacePairs(t *testing.T) {
	at := func(fp string, line int) awsSighting { return awsSighting{fp, line} }
	cases := []struct {
		name         string
		ids, secrets []awsSighting
		taken        []string
		want         map[string]string
	}{
		{"key ids above, a setting between", []awsSighting{at("a", 2), at("b", 5)}, []awsSighting{at("A", 4), at("B", 7)}, nil, map[string]string{"A": "a", "B": "b"}},
		{"secret keys above", []awsSighting{at("a", 3), at("b", 6)}, []awsSighting{at("A", 1), at("B", 4)}, nil, map[string]string{"A": "a", "B": "b"}},
		{"adjacent blocks", []awsSighting{at("a", 1), at("b", 3), at("c", 5)}, []awsSighting{at("A", 2), at("B", 4), at("C", 6)}, nil, map[string]string{"A": "a", "B": "b", "C": "c"}},
		{"same line", []awsSighting{at("a", 1), at("b", 2)}, []awsSighting{at("A", 1), at("B", 2)}, nil, map[string]string{"A": "a", "B": "b"}},
		{"one key id, two secret keys: the nearer", []awsSighting{at("a", 1)}, []awsSighting{at("B", 4), at("A", 2)}, nil, map[string]string{"A": "a"}},
		{"one key id, far away", []awsSighting{at("a", 1)}, []awsSighting{at("A", 30)}, nil, map[string]string{"A": "a"}},
		{"one key id seen twice, far away", []awsSighting{at("a", 1), at("a", 40)}, []awsSighting{at("A", 20)}, nil, map[string]string{"A": "a"}},
		{"two key ids, both far away", []awsSighting{at("a", 1), at("b", 2)}, []awsSighting{at("A", 30)}, nil, map[string]string{}},
		{"a key id paired elsewhere", []awsSighting{at("a", 1)}, []awsSighting{at("A", 2)}, []string{"a"}, map[string]string{}},
		{"no key id", nil, []awsSighting{at("A", 2)}, nil, map[string]string{}},
	}
	for _, tc := range cases {
		taken := map[string]bool{}
		for _, fp := range tc.taken {
			taken[fp] = true
		}
		got := map[string]string{}
		for _, pr := range (awsPlace{ids: tc.ids, secrets: tc.secrets}).pair(taken) {
			got[pr[0]] = pr[1]
		}
		if !maps.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
		for s, id := range got {
			if !taken[s] || !taken[id] {
				t.Errorf("%s: %s and %s not marked taken", tc.name, s, id)
			}
		}
	}
}

// A lone AWS key id and a private key are looked up with the owner's credentials (fake aws and gh
// here): the key id among the owner's IAM keys, the private key's public half among their GitHub
// keys. Neither value reaches a finding, a status, or a command other than the read-only ones.
func TestLivenessLookupsAtScanTime(t *testing.T) {
	fx := newFixture(t)
	keyID := testcorpus.AWSKeyID("AKIA", 12345678901, false, 7)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, body := testcorpus.PEM("", der)
	pub, _, err := sshkey.FromPrivate(body)
	if err != nil {
		t.Fatal(err)
	}
	fx.secrets = append(fx.secrets, keyID, keyPEM)
	fx.write(t, "src/shop/config/.env", "AWS_ACCESS_KEY_ID="+keyID+"\n", 0o600)
	fx.write(t, "src/shop/deploy2.pem", keyPEM, 0o600)

	var commands []string
	var mu sync.Mutex
	runner := func(answer func(args []string) string) cli.Runner {
		return cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
			mu.Lock()
			commands = append(commands, strings.Join(args, " "))
			mu.Unlock()
			return []byte(answer(args)), nil
		})
	}
	aws := runner(func(a []string) string {
		switch strings.Join(a[:2], " ") {
		case "configure list-profiles":
			return "prod\n"
		case "sts get-caller-identity":
			return `{"Account":"012345678901"}`
		case "iam list-users":
			return `{"Users":[{"UserName":"ci"}]}`
		case "iam list-access-keys":
			return `{"AccessKeyMetadata":[{"AccessKeyId":"` + keyID + `","Status":"Active"}]}`
		}
		return `{"SummaryMap":{"AccountAccessKeysPresent":0}}`
	})
	gh := runner(func(a []string) string {
		switch a[len(a)-1] {
		case "user":
			return `{"login":"octocat"}`
		case "user/keys":
			return `[{"key":"` + pub.Type + " " + base64.StdEncoding.EncodeToString(pub.Blob) + `","title":"deploy box"}]`
		}
		return "[]"
	})
	c := fx.connector(t, fx.gitleaksReport())
	c.NewChecker = func(home string, cfg liveness.Config) *liveness.Checker {
		return &liveness.Checker{Config: cfg, Owner: liveness.Owner{AWS: aws, GH: gh, Home: home}}
	}
	known := &attribution.Known{Owned: attribution.Owned{AWSAccounts: []string{"012345678901"}}}
	req := connector.Request{Known: known, Config: map[string]any{"liveness": map[string]any{"enabled": true}}}
	rec := &recorder{}
	if err := c.Inventory(context.Background(), req, rec); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal([]any{rec.findings, rec.statuses})
	for _, s := range append(fx.secrets, body) {
		if len(s) >= 6 && strings.Contains(string(raw), s) {
			t.Fatal("a raw secret reached the output")
		}
	}
	for _, cmd := range commands {
		if strings.Contains(cmd, keyID) || strings.Contains(cmd, body[:16]) {
			t.Errorf("a command was given the secret: %s", cmd)
		}
	}
	ids := livenessOf(t, rec, "aws-access-key-id")
	if l := ids["scan:~/src/shop/config/.env"]; l == nil || l.State != secretrisk.Live || !l.ByOwner || l.Account != "aws:012345678901" || l.Reason != "Active, IAM user ci of account 012345678901" {
		t.Errorf("lone key id: %+v", l)
	}
	keys := livenessOf(t, rec, "private-key")
	if l := keys["scan:~/src/shop/deploy2.pem"]; l == nil || l.State != secretrisk.Live || l.Reason != `GitHub SSH key "deploy box"` || l.Account != "github:octocat" {
		t.Errorf("private key: %+v", keys)
	}
}

// pairHistory is a repository with one commit holding one file, and a gitleaks that reports the
// leaks given for that file as committed in that commit.
type pairHistory struct {
	*historyRepo
	gl cli.Runner
}

// newPairHistory commits an AWS key id and a secret access key on the next line, both reported
// (the secret key by a custom gitleaks rule) as committed on date.
func newPairHistory(t *testing.T, keyID, secret, date string) pairHistory {
	return newLeakHistory(t, "creds.env", "AWS_ACCESS_KEY_ID="+keyID+"\naws_secret_access_key="+secret+"\n", date,
		map[string]any{"RuleID": "aws-access-token", "StartLine": 1, "Secret": keyID},
		map[string]any{"RuleID": "aws-secret-key", "StartLine": 2, "Secret": secret})
}

// newLeakHistory commits file with content and a gitleaks that reports leaks (RuleID, StartLine,
// Secret, Match) in that file and commit, committed on date.
func newLeakHistory(t *testing.T, file, content, date string, leaks ...map[string]any) pairHistory {
	r := newHistoryRepo(t)
	if err := os.WriteFile(filepath.Join(r.dir, file), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	r.git("add", file)
	r.git("commit", "-q", "-m", "creds")
	commit := r.git("rev-parse", "HEAD")
	for _, l := range leaks {
		l["File"], l["Commit"], l["Date"] = file, commit, date
	}
	gl := cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "version" {
			return []byte("v8.30.1\n"), nil
		}
		r.scans = append(r.scans, args)
		return json.Marshal(leaks)
	})
	return pairHistory{r, gl}
}

// check scans the history (from the gitleaks cache after the first time, replayed says which) and
// runs the liveness check for mine and unknown secrets against f; it fails if a value reaches the
// findings or the status line.
func (h pairHistory) check(t *testing.T, f *fakeProviders, known *attribution.Known, values ...string) (line string, replayed bool, fs []finding.Finding) {
	t.Helper()
	c := &Connector{Gitleaks: h.gl, Git: cli.Exec{Path: "git", Timeout: time.Minute}, CacheDir: defaultCacheDir,
		Now: func() time.Time { return time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) },
		NewChecker: func(home string, cfg liveness.Config) *liveness.Checker {
			return &liveness.Checker{Config: cfg, Bases: map[string][]string{"aws": {f.URL}}, Interval: time.Millisecond}
		}}
	lc, err := liveness.ParseConfig(map[string]any{"enabled": true, "owners": []any{"mine", "unknown"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := settings{reposRoot: filepath.Join(h.home, "src"), workers: 1, timeout: time.Minute, gitCache: true, liveness: lc}
	h.scans = nil
	s := newScan(context.Background(), c, h.home, cfg, fingerprint.FromBytes(bytes.Repeat([]byte{1}, 32)), &recorder{})
	if err := s.gitleaks(h.dir); err != nil {
		t.Fatal(err)
	}
	fs, _ = s.findings()
	line = s.checkLiveness(context.Background(), fs, known)
	raw, _ := json.Marshal(fs)
	for _, v := range values {
		if strings.Contains(string(raw)+line, v) {
			t.Fatal("a value reached the output")
		}
	}
	return line, len(h.scans) == 0, fs
}

// A secret key committed next to someone else's key id: the pair is never sent to STS, neither
// when the scan read the values nor when the history is replayed from the cache and the values
// would have to be recovered. The key id's own attribution gates the probe, not the secret key's.
func TestLivenessNeverSendsAForeignKeyID(t *testing.T) {
	theirs, secret := testcorpus.AWSKeyID("AKIA", 999999999999, false, 1), fake("", 40)
	h := newPairHistory(t, theirs, secret, "2026-11-01T00:00:00Z")
	f := newFakeProviders(t, theirs)
	theirAccount := &attribution.Known{Owned: attribution.Owned{AWSAccounts: []string{"012345678901"}}}
	for _, wantReplay := range []bool{false, true} {
		line, replayed, _ := h.check(t, f, theirAccount, theirs, secret)
		if replayed != wantReplay || f.askedCount() != 0 || !strings.Contains(line, "0 asked") || strings.Contains(line, " 0 not allowed") {
			t.Fatalf("replay %v: someone else's key id was sent (%d calls): %s", replayed, f.askedCount(), line)
		}
	}
	// The control: the same pair, the owner's, is recovered and tried.
	line, _, _ := h.check(t, f, &attribution.Known{Owned: attribution.Owned{AWSAccounts: []string{"999999999999"}}}, theirs, secret)
	if !f.askedAbout(theirs) || !strings.Contains(line, "1 asked") {
		t.Errorf("the owner's pair was not tried: %s", line)
	}
}

// A temporary key id (ASIA) next to a secret key is no pair: signed without its session token it
// would read as rejected. Neither path pairs it: the key id gets its own lookup (which sends
// nothing) and the secret key is tried alone: unsupported without a key id.
func TestLivenessNeverPairsATemporaryKeyID(t *testing.T) {
	temp, secret := testcorpus.AWSKeyID("ASIA", 12345678901, false, 1), fake("", 40)
	h := newPairHistory(t, temp, secret, "2026-11-23T20:00:00Z") // within STS's lifetime: not noise
	f := newFakeProviders(t, temp)
	for _, wantReplay := range []bool{false, true} {
		line, replayed, _ := h.check(t, f, &attribution.Known{}, temp, secret)
		if replayed != wantReplay || f.askedCount() != 0 || !strings.Contains(line, "1 asked,") || !strings.Contains(line, "1 unsupported") && !strings.Contains(line, "1 without a value") {
			t.Errorf("replay %v: an ASIA id was paired (%d calls): %s", replayed, f.askedCount(), line)
		}
	}
}

// One key id and two secret keys in one place, and the same key id in another place beside a
// third: the id goes with one of them, the nearest, every run, and the others are tried alone
// (unsupported, or from the cache).
func TestHeldKeyIDPairsOnce(t *testing.T) {
	h := heldValues{
		byFP:   map[string]heldValue{"s2": {"aws-secret-key", "two"}, "s1": {"aws-secret-key", "one"}, "s3": {"aws-secret-key", "three"}},
		awsIDs: map[string]string{"id": "AKIA0"},
		aws: awsPlaces{
			"p": {ids: []awsSighting{{"id", 1}}, secrets: []awsSighting{{"s2", 3}, {"s1", 2}}},
			"q": {ids: []awsSighting{{"id", 1}}, secrets: []awsSighting{{"s3", 2}}},
		},
	}
	for range 20 {
		var paired []string
		for _, p := range h.probes() {
			if slices.Contains(p.Fingerprints, "id") {
				paired = append(paired, strings.Join(p.Fingerprints, ","))
				if p.KeyID != "AKIA0" || p.Value != "one" {
					t.Fatalf("pair %+v", p)
				}
			}
		}
		if len(paired) != 1 || paired[0] != "s1,id" {
			t.Fatalf("the key id went with %v", paired)
		}
	}
}

// A Cloudflare token is the one probed type whose value does not name its provider: it is tried
// only when its key names Cloudflare, never for a bare CF_TOKEN, which may be anything.
func TestCloudflareOnlyWhenNamed(t *testing.T) {
	fx := newFixture(t)
	named, bare := fake("", 40), fake("", 40)
	fx.secrets = append(fx.secrets, named, bare)
	fx.write(t, ".config/cf/env", "CLOUDFLARE_API_TOKEN="+named+"\nCF_API_TOKEN="+bare+"\n", 0o600)
	f := newFakeProviders(t)
	c := fx.livenessConnector(t, f)
	req := connector.Request{Known: &attribution.Known{}, Config: map[string]any{"liveness": map[string]any{"enabled": true, "owners": []any{"unknown"}, "providers": []any{"cloudflare"}}}}
	rec := &recorder{}
	if err := c.Inventory(context.Background(), req, rec); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, fd := range rec.findings {
		if ev, ok := secretrisk.EvidenceOf(fd); ok && ev.Type == "cloudflare-token" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("both tokens found: %d", n)
	}
	if !f.askedAbout(named) || f.askedAbout(bare) {
		t.Errorf("named asked %v, bare asked %v", f.askedAbout(named), f.askedAbout(bare))
	}
	raw, _ := json.Marshal([]any{rec.findings, rec.statuses})
	if strings.Contains(string(raw), named) || strings.Contains(string(raw), bare) {
		t.Fatal("a token reached the output")
	}
}

// hangingProviders never answers until the request is abandoned; called runs at the first request.
func hangingProviders(t *testing.T, called func()) *fakeProviders {
	var once sync.Once
	f := &fakeProviders{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.asked = append(f.asked, r.Header.Get("Authorization")+r.Header.Get("X-Api-Key"))
		f.mu.Unlock()
		once.Do(called)
		<-r.Context().Done()
	}))
	t.Cleanup(f.Close)
	return f
}

// The liveness phase never costs the scan its findings: it ends a minute before the run's deadline
// (so a deadline closer than livenessTimeout leaves it no time at all), and a run cancelled while
// it probes still emits every finding before it returns.
func TestLivenessNeverDiscardsTheScan(t *testing.T) {
	req := connector.Request{Known: &attribution.Known{}, Config: map[string]any{"liveness": map[string]any{"enabled": true, "owners": []any{"unknown"}}}}
	reported := func(rec *recorder) int {
		n := 0
		for _, f := range rec.findings {
			if _, ok := secretrisk.EvidenceOf(f); ok {
				n++
			}
		}
		return n
	}

	fx := newFixture(t)
	f := hangingProviders(t, func() {})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rec := &recorder{}
	start := time.Now()
	if err := fx.livenessConnector(t, f).Inventory(ctx, req, rec); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 20*time.Second || reported(rec) == 0 || f.askedCount() != 0 || !strings.Contains(rec.statuses[0].Detail, "interrupted") {
		t.Errorf("deadline in 30s: took %s, %d findings, %d asked; %v", d, reported(rec), f.askedCount(), rec.statuses)
	}

	fx = newFixture(t)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	f = hangingProviders(t, cancel) // Ctrl-C while the first provider is asked
	rec = &recorder{}
	if err := fx.livenessConnector(t, f).Inventory(ctx, req, rec); err == nil {
		t.Error("a cancelled run reported success")
	}
	if reported(rec) == 0 || f.askedCount() == 0 {
		t.Errorf("cancelled while probing: %d findings, %d asked", reported(rec), f.askedCount())
	}
	raw, _ := json.Marshal([]any{rec.findings, rec.statuses})
	for _, s := range fx.secrets {
		if len(s) >= 6 && strings.Contains(string(raw), s) {
			t.Fatal("a raw secret reached the output")
		}
	}
}

// The liveness cache sits beside the other caches, under the connector's CacheDir root.
func TestLivenessCacheFollowsCacheDir(t *testing.T) {
	home := t.TempDir()
	c := &Connector{CacheDir: func(h string) string { return filepath.Join(h, "state", "gitleaks") }}
	ch := c.checker(home, liveness.Config{})
	if err := ch.Cache.Save(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "state", "liveness.json")); err != nil {
		t.Errorf("cache not under CacheDir's root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".cache")); err == nil {
		t.Error("a cache was written under ~/.cache")
	}
}

// awsSecret is a synthetic secret access key: 40 characters of the alphabet AWS uses, a slash
// among them.
func awsSecret() string {
	s := fake("", 39)
	return s[:20] + "/" + s[20:]
}

// mineKeyID is a synthetic long-term key id of the account the fake STS answers for; n tells
// several apart.
func mineKeyID(n byte) string { return testcorpus.AWSKeyID("AKIA", 12345678901, false, n) }

// theirKeyID is a synthetic key id of an account that is not the owner's.
func theirKeyID(n byte) string { return testcorpus.AWSKeyID("AKIA", 999999999999, false, n) }

// threePairs is an Ansible vars file holding three key id / secret access key pairs, a setting
// between each id and its secret key, so that the nearest key id of the second secret key is the
// third's, not its own. The third pair names its secret key only "secret" and belongs to someone
// else; a commit hash sits next to it under a secret-ish name. Lines are 1-based.
type threePairs struct {
	ids, secrets         [3]string
	sha, content         string
	idLines, secretLines [3]int
}

func newThreePairs() threePairs {
	p := threePairs{ids: [3]string{mineKeyID(1), mineKeyID(2), theirKeyID(3)}, secrets: [3]string{awsSecret(), awsSecret(), awsSecret()},
		sha: testcorpus.Fake(rng, "", 40, testcorpus.Hex)}
	lines := []string{
		"---",
		`alpha_access_key_id: "` + p.ids[0] + `"`,
		"alpha_region: eu-west-1",
		`alpha_secret_access_key: "` + p.secrets[0] + `"`,
		`beta_access_key_id: "` + p.ids[1] + `"`,
		"beta_region: eu-west-1",
		`beta_secret_access_key: "` + p.secrets[1] + `"`,
		`gamma_key: "` + p.ids[2] + `"`,
		`gamma_secret: "` + p.secrets[2] + `"`,
		`deploy_secret: "` + p.sha + `"`,
	}
	p.idLines, p.secretLines = [3]int{2, 5, 8}, [3]int{4, 7, 9}
	p.content = strings.Join(lines, "\n") + "\n"
	return p
}

func (p threePairs) values() []string { return append(append(p.ids[:], p.secrets[:]...), p.sha) }

// An AWS secret access key is recognised in the forms it is written in: under any key name that
// holds secret_access_key (Ansible YAML, env, JS), and under a weaker secret_key or *_secret
// only with an AWS key id within awsPairLines lines. A commit hash never is one, not even under
// aws_secret_access_key; a 40-character token under a name that does not say secret, or too far
// from any key id, is not one either; a lone key id stays alone.
func TestAWSSecretKeyForms(t *testing.T) {
	fx := newFixture(t)
	vars := newThreePairs()
	// The JS secret key ends in "/", where a word boundary would cut it off before the quote.
	ini, env, js := [2]string{mineKeyID(4), awsSecret()}, [2]string{mineKeyID(5), awsSecret()}, [2]string{mineKeyID(6), fake("", 39) + "/"}
	plain, token, far, lone, sha := awsSecret(), awsSecret(), awsSecret(), mineKeyID(9), testcorpus.Fake(rng, "", 40, testcorpus.Hex)
	fx.secrets = append(fx.secrets, vars.values()...)
	fx.secrets = append(fx.secrets, ini[0], ini[1], env[0], env[1], js[0], js[1], plain, token, far, lone, sha)
	fx.write(t, ".config/ansible/group_vars/all.yml", vars.content, 0o600)
	fx.write(t, ".config/app/settings.ini", "[s3]\naccess_key = "+ini[0]+"\nsecret_key = "+ini[1]+"\n", 0o600)
	fx.write(t, ".config/app/old.ini", "aws_secret_access_key = "+sha+"\n", 0o600)
	fx.write(t, "src/shop/.env.aws", "AWS_ACCESS_KEY_ID="+env[0]+"\nAWS_SECRET_ACCESS_KEY="+env[1]+"\n", 0o600)
	fx.write(t, "src/shop/secrets.js", "module.exports = {\n  accessKeyId: '"+js[0]+"',\n  secretAccessKey: '"+js[1]+"',\n};\n", 0o600)
	fx.write(t, ".config/other/plain.yml", "plain_secret: "+plain+"\n", 0o600)
	fx.write(t, ".config/other/token.yml", "access_key: "+mineKeyID(7)+"\napi_token: "+token+"\n", 0o600)
	fx.write(t, ".config/other/far.yml", "access_key: "+mineKeyID(8)+"\n"+strings.Repeat("setting: on\n", awsPairLines)+"app_secret: "+far+"\n", 0o600)
	fx.write(t, ".config/lone/env", "AWS_ACCESS_KEY_ID="+lone+"\n", 0o600)

	c := fx.connector(t, "[]")
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"emit_noise": true}}, rec); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]any{rec.findings, rec.statuses})
	for _, s := range fx.secrets {
		if len(s) >= 6 && strings.Contains(string(raw), s) {
			t.Fatal("a raw secret reached the output")
		}
	}
	got := map[string]string{} // fingerprint -> type
	for _, f := range rec.findings {
		if ev, ok := secretrisk.EvidenceOf(f); ok {
			got[ev.Fingerprint] = ev.Type
		}
	}
	for name, v := range map[string]string{"yaml 1": vars.secrets[0], "yaml 2": vars.secrets[1], "yaml secret": vars.secrets[2],
		"ini secret_key": ini[1], "env": env[1], "js": js[1]} {
		if typ := got[fx.fpOf(t, c, v, "aws-secret-key")]; typ != "aws-secret-key" {
			t.Errorf("%s: %q, want aws-secret-key", name, typ)
		}
	}
	for name, v := range map[string]string{"commit hash near a key id": vars.sha, "commit hash under aws_secret_access_key": sha,
		"secret-ish name, no key id": plain, "key id near, not a secret-ish name": token, "secret-ish name too far": far} {
		if typ := got[fx.fpOf(t, c, v, "aws-secret-key")]; typ == "aws-secret-key" {
			t.Errorf("%s: reported as an AWS secret key", name)
		}
	}
	if typ := got[fx.fpOf(t, c, lone, "aws-access-key-id")]; typ != "aws-access-key-id" {
		t.Errorf("lone key id: %q", typ)
	}
	// The pattern alone, with no key id beside it, takes a value that ends in "/" before its quote.
	text := "secretAccessKey: '" + js[1] + "'"
	if cl, ok := classify("x.yml", text, specific); !ok || cl.p != awsSecretKey || cl.subs(text)[1] != js[1] {
		t.Error("a secret key ending in / is cut off or missed")
	}
}

// Several key id / secret key pairs in one working file: each secret key is tried with its own
// key id, by proximity, and only the pairs whose key id is the owner's (default owners: mine; the
// secret keys themselves name no account, as the file names two). STS here accepts only the
// second key id: its secret key, and no other, gets the live result.
func TestLivenessPairsEachSecretKeyWithItsKeyID(t *testing.T) {
	fx := newFixture(t)
	vars := newThreePairs()
	fx.secrets = append(fx.secrets, vars.values()...)
	fx.write(t, ".config/ansible/group_vars/all.yml", vars.content, 0o600)
	f := newFakeProviders(t, vars.ids[1])
	c := fx.livenessConnector(t, f)
	known := &attribution.Known{Owned: attribution.Owned{AWSAccounts: []string{"012345678901"}}}
	req := connector.Request{Known: known, Config: map[string]any{"liveness": map[string]any{"enabled": true, "providers": []any{"aws"}}}}
	rec := &recorder{}
	if err := c.Inventory(context.Background(), req, rec); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]any{rec.findings, rec.statuses})
	for _, s := range fx.secrets {
		if len(s) >= 6 && strings.Contains(string(raw), s) {
			t.Fatal("a raw secret reached the output")
		}
	}
	checkThreePairs(t, f, vars, rec.findings, func(v, typ string) string { return fx.fpOf(t, c, v, typ) })
}

// checkThreePairs asserts that the owner's two pairs of vars were each tried as a pair, the second
// found live on both of its findings and the first not, that someone else's pair was never sent,
// and that every pair, someone else's too, names its other half on both findings.
func checkThreePairs(t *testing.T, f *fakeProviders, vars threePairs, fs []finding.Finding, fpOf func(v, typ string) string) {
	t.Helper()
	byFP := map[string]*secretrisk.Liveness{}
	pairOf := map[string]string{}
	for _, fd := range fs {
		if ev, ok := secretrisk.EvidenceOf(fd); ok {
			byFP[ev.Fingerprint] = ev.Liveness
			pairOf[ev.Fingerprint] = ev.Pair
		}
	}
	for i := range vars.ids {
		s, id := fpOf(vars.secrets[i], "aws-secret-key"), fpOf(vars.ids[i], "aws-access-key-id")
		if pairOf[s] != id || pairOf[id] != s {
			t.Errorf("pair %d does not name its other half", i)
		}
	}
	live := func(v, typ string) bool {
		l := byFP[fpOf(v, typ)]
		return l != nil && l.State == secretrisk.Live && l.Account == "aws:012345678901"
	}
	if !live(vars.secrets[1], "aws-secret-key") || !live(vars.ids[1], "aws-access-key-id") {
		t.Errorf("the second pair: secret key %+v, key id %+v", byFP[fpOf(vars.secrets[1], "aws-secret-key")], byFP[fpOf(vars.ids[1], "aws-access-key-id")])
	}
	if live(vars.secrets[0], "aws-secret-key") || !f.askedAbout(vars.ids[0]) {
		t.Errorf("the first secret key was not tried with its own key id: %+v", byFP[fpOf(vars.secrets[0], "aws-secret-key")])
	}
	if f.askedAbout(vars.ids[2]) || byFP[fpOf(vars.secrets[2], "aws-secret-key")] != nil {
		t.Error("someone else's pair was tried")
	}
}

// The same file in git history, as gitleaks reports it: the key ids by its aws-access-token rule,
// the secret keys and the commit hash by generic-api-key. The secret keys become aws-secret-key
// and pair by proximity, both when the scan holds the values and when the history is replayed
// from the cache and the values are read again from the commit.
func TestLivenessPairsHistoryByProximity(t *testing.T) {
	vars := newThreePairs()
	var leaks []map[string]any
	names := []string{"alpha_secret_access_key", "beta_secret_access_key", "gamma_secret"}
	for i := range 3 {
		leaks = append(leaks,
			map[string]any{"RuleID": "aws-access-token", "StartLine": vars.idLines[i], "Secret": vars.ids[i], "Match": vars.ids[i]},
			map[string]any{"RuleID": "generic-api-key", "StartLine": vars.secretLines[i], "Secret": vars.secrets[i], "Match": names[i] + `: "` + vars.secrets[i]})
	}
	leaks = append(leaks, map[string]any{"RuleID": "generic-api-key", "StartLine": 10, "Secret": vars.sha, "Match": `deploy_secret: "` + vars.sha})
	h := newLeakHistory(t, "all.yml", vars.content, "2026-11-01T00:00:00Z", leaks...)
	known := &attribution.Known{Owned: attribution.Owned{AWSAccounts: []string{"012345678901"}}}
	fp := fingerprint.FromBytes(bytes.Repeat([]byte{1}, 32))
	for _, wantReplay := range []bool{false, true} {
		f := newFakeProviders(t, vars.ids[1])
		line, replayed, fs := h.check(t, f, known, vars.values()...)
		if replayed != wantReplay {
			t.Fatalf("replayed %v, want %v", replayed, wantReplay)
		}
		types := map[string]string{}
		for _, fd := range fs {
			if ev, ok := secretrisk.EvidenceOf(fd); ok {
				types[ev.Fingerprint] = ev.Type
			}
		}
		for i, s := range vars.secrets {
			if types[fp.Of(s)] != "aws-secret-key" {
				t.Errorf("replay %v: secret key %d is %q", replayed, i, types[fp.Of(s)])
			}
		}
		if types[fp.Of(vars.sha)] == "aws-secret-key" {
			t.Errorf("replay %v: a commit hash became an AWS secret key", replayed)
		}
		checkThreePairs(t, f, vars, fs, func(v, _ string) string { return fp.Of(v) })
		if !strings.Contains(line, "2 asked") {
			t.Errorf("replay %v: %s", replayed, line)
		}
	}
}
