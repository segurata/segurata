package localsecrets

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/testcorpus"
)

// Every secret in these tests is generated at run time from a fixed seed: no real or real-looking
// literal ever sits in the source.

var rng = rand.New(rand.NewPCG(7, 11))

func fake(prefix string, n int) string { return testcorpus.Fake(rng, prefix, n, testcorpus.Alnum) }

// fakePEM is a random key of a label in PEM armour, and its body.
func fakePEM(label string) (pem, body string) {
	return testcorpus.PEM(label, testcorpus.Bytes(rng, 600))
}

func opensshBlob(cipher string) []byte {
	b := binary.BigEndian.AppendUint32([]byte("openssh-key-v1\x00"), uint32(len(cipher)))
	return append(append(b, cipher...), testcorpus.Bytes(rng, 200)...)
}

// A short random body scores less entropy than a long one: an AWS key id's 16 characters fell
// under the 3.2 floor about 3 times in 100, and the key was silently dropped.
func TestJudgeKeepsShortRandomKeyIDs(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 5))
	const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	dropped := 0
	for range 5000 {
		b := make([]byte, 16)
		for i := range b {
			b[i] = base32[r.IntN(len(base32))]
		}
		for _, id := range []string{"AKIA" + string(b), "ASIA" + string(b)} {
			if p := classifyValue(id); p == nil {
				t.Fatalf("%s not classified", id)
			} else if _, ok := judge(p, id, "", time.Now()); !ok {
				dropped++
			}
		}
	}
	if dropped > 0 {
		t.Errorf("%d of 10000 random AWS key ids dropped as low entropy", dropped)
	}
	if p := classifyValue("AKIAAAAABBBBCCCCDDDD"); p == nil {
		t.Fatal("not classified")
	} else if _, ok := judge(p, "AKIAAAAABBBBCCCCDDDD", "", time.Now()); ok {
		t.Error("a key id of four repeated letters accepted")
	}
}

func TestJudgeRejectsPlaceholdersAndLowEntropy(t *testing.T) {
	p := classifyValue(fake("sk-ant-", 40))
	if p == nil || p.typ != "anthropic" {
		t.Fatalf("anthropic key not classified: %+v", p)
	}
	now := time.Now()
	if _, ok := judge(p, "sk-ant-"+strings.Repeat("x", 40), "", now); ok {
		t.Error("placeholder accepted")
	}
	if _, ok := judge(p, "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789ABCD", "", now); ok {
		t.Error("sequential fixture accepted")
	}
	if _, ok := judge(p, "sk-ant-"+strings.Repeat("ab", 20), "", now); ok {
		t.Error("low-entropy value accepted")
	}
	if _, ok := judge(p, fake("sk-ant-", 40), "", now); !ok {
		t.Error("random key rejected")
	}
	for _, v := range []string{"true", "/usr/local/bin/x", "${SOME_TOKEN}", "12345678901"} {
		if _, ok := judge(&assignment, v, "API_TOKEN", now); ok {
			t.Errorf("assignment value %q accepted", v)
		}
	}
	if _, ok := judge(&assignment, fake("", 24), "TOKEN_URL", now); ok {
		t.Error("assignment to a *_URL name accepted")
	}
}

func TestJWTAnonOrExpiredIsPublic(t *testing.T) {
	enc := func(m map[string]any) string {
		raw, _ := json.Marshal(m)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	head := enc(map[string]any{"alg": "HS256", "typ": "JWT"})
	sig := fake("", 30)
	p := classifyValue(head + "." + enc(map[string]any{"role": "service_role"}) + "." + sig)
	if p == nil || p.typ != "jwt" {
		t.Fatalf("jwt not classified")
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v, _ := judge(p, head+"."+enc(map[string]any{"role": "service_role", "sub": fake("", 12)})+"."+sig, "", now)
	if v.public || v.note != "role=service_role" {
		t.Errorf("service_role JWT: %+v", v)
	}
	v, _ = judge(p, head+"."+enc(map[string]any{"role": "anon", "sub": fake("", 12)})+"."+sig, "", now)
	if !v.public {
		t.Error("anon JWT not public")
	}
	v, _ = judge(p, head+"."+enc(map[string]any{"exp": 1000, "sub": fake("", 12)})+"."+sig, "", now)
	if !v.public || v.note != "expired" {
		t.Errorf("expired JWT: %+v", v)
	}
}

func TestPEMBodyIsTheSameInEveryForm(t *testing.T) {
	pem, body := fakePEM("RSA")
	escaped := strings.ReplaceAll(pem, "\n", `\n`)
	doubled := strings.ReplaceAll(pem, "\n", `\\n`)
	for name, text := range map[string]string{"file": pem, "escaped": escaped, "double-escaped": doubled} {
		if got := pemBody(text); got != body {
			t.Errorf("%s: body differs", name)
		}
	}
	// ripgrep's match on an escaped key carries the body; Go must classify it whole.
	m := regexp.MustCompile(specificByType(privateKeyType).src).FindString(`"private_key": "` + escaped + `"`)
	if !specificByType(privateKeyType).re.MatchString(m) || pemBody(m) != body {
		t.Error("escaped key match does not carry the full body")
	}
}

func TestPEMEncrypted(t *testing.T) {
	_, plain := testcorpus.PEM("OPENSSH", opensshBlob("none"))
	_, locked := testcorpus.PEM("OPENSSH", opensshBlob("aes256-ctr"))
	if pemEncrypted("OPENSSH", "", plain) {
		t.Error("cipher none reported encrypted")
	}
	if !pemEncrypted("OPENSSH", "", locked) {
		t.Error("aes256-ctr reported unencrypted")
	}
	if !pemEncrypted("ENCRYPTED", "", "") || !pemEncrypted("RSA", "Proc-Type: 4,ENCRYPTED\n", "") {
		t.Error("PKCS#8 or PKCS#1 encryption missed")
	}
}

func TestSettings(t *testing.T) {
	s, err := parseSettings(map[string]any{"repos_root": "~/code", "skip_git_history": true, "gitleaks_workers": 2.0, "gitleaks_timeout": "90s",
		"owned_owners": []any{"me", "my-org"}, "emit_noise": true}, "/h")
	if err != nil || s.reposRoot != "/h/code" || !s.skipHistory || s.workers != 2 || s.timeout != 90*time.Second ||
		!slices.Equal(s.ownedOwners, []string{"me", "my-org"}) || !s.emitNoise {
		t.Fatalf("settings %+v err %v", s, err)
	}
	for v, want := range map[any]dumpMode{nil: dumpsOn, true: dumpsOn, false: dumpsOff, "only": dumpsOnly} {
		cfg := map[string]any{}
		if v != nil {
			cfg["data_dumps"] = v
		}
		if s, err := parseSettings(cfg, "/h"); err != nil || s.dumps != want {
			t.Errorf("data_dumps %v: %v %v", v, s.dumps, err)
		}
	}
	for _, bad := range []map[string]any{
		{"gitleaks_timeout": "soon"}, {"data_dumps": "yes"},
		{"owned_owners": "me"}, {"owned_owners": []any{"me", 3}}, {"owned_owners": []any{""}},
	} {
		if _, err := parseSettings(bad, "/h"); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// fixture is a synthetic home directory with secrets in the places the connector looks.
type fixture struct {
	home    string
	secrets []string // every raw value planted, to check none is ever emitted
	keyPEM  string   // a private key present on disk, in a transcript and in git history
	stripe  string
}

func (fx *fixture) write(t *testing.T, rel, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(fx.home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func newFixture(t *testing.T) *fixture {
	fx := &fixture{home: t.TempDir()}
	_ = os.Chmod(fx.home, 0o755) // an open home folder, like macOS's default
	anthropic := fake("sk-ant-api03-", 60)
	fx.stripe = fake("sk_live_", 40)
	fx.keyPEM, _ = fakePEM("RSA")
	sshPEM, _ := testcorpus.PEM("OPENSSH", opensshBlob("none"))
	saPEM, _ := fakePEM("")
	noise := fake("", 19) + "7" // a digit: an all-letter value is not a secret (notSecretValue)
	fx.secrets = []string{anthropic, fx.stripe, fx.keyPEM, sshPEM, saPEM, noise}

	fx.write(t, ".zshrc", "export ANTHROPIC_API_KEY="+anthropic+"\nexport EXAMPLE_TOKEN=your-token-here\n", 0o644)
	fx.write(t, ".claude/projects/p/s.jsonl", `{"msg":"use `+anthropic+` and key \"`+strings.ReplaceAll(fx.keyPEM, "\n", `\n`)+`\""}`+"\n", 0o600)
	fx.write(t, "src/shop/.env", "STRIPE_SECRET_KEY="+fx.stripe+"\nSESSION_SECRET="+noise+"\n", 0o600)
	fx.write(t, "src/shop/deploy.pem", fx.keyPEM, 0o600)
	fx.write(t, "src/shop/.git/config", "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@example.com:o/shop.git\n", 0o600)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "ci@demo.iam.gserviceaccount.com", "private_key": saPEM})
	fx.write(t, ".config/gcloud/keys/ci.json", strings.Replace(string(sa), ",", ",\n", -1), 0o644)
	fx.write(t, ".ssh/id_open", sshPEM, 0o600)
	return fx
}

// fakeTool records calls and answers from a function.
type fakeTool struct {
	mu    sync.Mutex
	calls [][]string
	reply func(args []string) ([]byte, error)
}

func (f *fakeTool) Run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, args)
	f.mu.Unlock()
	return f.reply(args)
}

type recorder struct{ httpxtest.Recorder }

// Finding stamps what the run would before the tracker reads it.
func (r *recorder) Finding(f finding.Finding) {
	f.Connector = name
	f.Fill(time.Now())
	r.Recorder.Finding(f)
}

// skipped is each scope declared not inspected, as "scope: reason".
func (r *recorder) skipped() []string {
	var out []string
	for _, s := range r.Skipped() {
		out = append(out, s.Scope+": "+s.Reason)
	}
	return out
}

func (fx *fixture) connector(t *testing.T, gitleaksReport string) *Connector {
	rg, err := exec.LookPath("rg")
	if err != nil {
		t.Skip("ripgrep not installed")
	}
	tracked := filepath.Join(fx.home, "src", "shop")
	return &Connector{
		RG: cli.Exec{Path: rg, Timeout: time.Minute},
		Gitleaks: &fakeTool{reply: func(args []string) ([]byte, error) {
			if args[0] == "version" {
				return []byte("8.30.1\n"), nil
			}
			if args[len(args)-1] != tracked {
				return []byte("[]"), nil
			}
			return []byte(gitleaksReport), nil
		}},
		Git: &fakeTool{reply: func(args []string) ([]byte, error) {
			if args[1] == "rev-list" { // one commit per repository; nothing rewritten
				if args[2] == "--no-walk" {
					return []byte(strings.Repeat("a", 40) + "\n"), nil
				}
				return nil, nil
			}
			if args[0] == "--git-dir="+filepath.Join(tracked, ".git") {
				return []byte("deploy.pem\x00"), nil // .env is ignored, the key is committed
			}
			return nil, nil
		}},
		SSHKeygen: &fakeTool{reply: func(args []string) ([]byte, error) {
			if args[0] == "-l" {
				return []byte("256 SHA256:abc someone@laptop (ED25519)\n"), nil
			}
			return []byte("ssh-ed25519 AAAA"), nil // opens with an empty passphrase
		}},
		LookPath: func(string) (string, error) { return "/bin/true", nil },
		Home:     func() (string, error) { return fx.home, nil },
		KeyPath:  func(home string) string { return filepath.Join(home, ".config", "segurata", "fingerprint.key") },
		CacheDir: defaultCacheDir,
		Now:      func() time.Time { return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC) },
	}
}

func (fx *fixture) gitleaksReport() string {
	generic := fake("", 32)
	fx.secrets = append(fx.secrets, generic)
	leaks := []map[string]any{
		{"RuleID": "stripe-access-token", "File": "config/old.env", "StartLine": 3, "Secret": fx.stripe, "Match": "K=" + fx.stripe, "Commit": "0123456789abcdef", "Date": "2024-05-01T10:00:00Z"},
		{"RuleID": "stripe-access-token", "File": "config/old.env", "StartLine": 3, "Secret": fx.stripe, "Commit": "fedcba9876543210", "Date": "2024-06-01T10:00:00Z"},
		{"RuleID": "private-key", "File": "deploy.pem", "StartLine": 1, "Secret": fx.keyPEM, "Commit": "aaaaaaaaaaaa", "Date": "2023-01-01T00:00:00Z"},
		{"RuleID": "generic-api-key", "File": "app.js", "StartLine": 9, "Secret": generic, "Commit": "bbbbbbbbbbbb", "Date": "2023-01-01T00:00:00Z"},
		{"RuleID": "generic-api-key", "File": "README.md", "StartLine": 2, "Secret": "your-api-key-here-xxxxxxxx", "Commit": "cccccccccccc", "Date": "2023-01-01T00:00:00Z"},
	}
	raw, _ := json.Marshal(leaks)
	return string(raw)
}

func evidence(f finding.Finding, key string) string {
	v, _ := f.Evidence[key]
	return fmt.Sprint(v)
}

func TestInventoryEndToEnd(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, fx.gitleaksReport())
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}

	// No raw value anywhere in what the connector emitted.
	all, _ := json.Marshal(rec.Findings)
	for _, s := range fx.secrets {
		for _, piece := range []string{s, pemBody(s)} {
			if len(piece) >= 6 && strings.Contains(string(all), piece) {
				t.Fatalf("a raw secret reached the output")
			}
		}
	}

	byKey := map[string][]finding.Finding{}
	var summary *finding.Finding
	for _, f := range rec.Findings {
		if f.Resource.Type == secretrisk.NoiseSummaryType {
			summary = &f
			continue
		}
		k := evidence(f, "type") + " " + evidence(f, "path") + " " + evidence(f, "source")
		byKey[k] = append(byKey[k], f)
		if evidence(f, "fingerprint") == "" || len(evidence(f, "fingerprint")) != 16 {
			t.Errorf("finding without fingerprint: %s", f.Title)
		}
	}
	one := func(k string) finding.Finding {
		t.Helper()
		if len(byKey[k]) != 1 {
			keys := make([]string, 0, len(byKey))
			for kk := range byKey {
				keys = append(keys, kk)
			}
			t.Fatalf("want one finding %q, have %d; all: %v", k, len(byKey[k]), keys)
		}
		return byKey[k][0]
	}

	env := one("stripe-live ~/src/shop/.env scan")
	rc := one("anthropic ~/.zshrc scan")
	if rc.Severity != finding.SevMedium || evidence(rc, "bucket") != "1-readable" || evidence(rc, "note") != "ANTHROPIC_API_KEY" {
		t.Errorf("readable rc key: %s %v", rc.Severity, rc.Evidence)
	}
	if rc.Remediation.Action != "file.chmod600" || !rc.Remediation.Automatable || env.Remediation.Action != "" {
		t.Errorf("chmod action: readable %q, closed %q", rc.Remediation.Action, env.Remediation.Action)
	}
	if evidence(rc, "fix") != "docs/secrets.md#shell-variables-from-the-keychain" || !strings.HasPrefix(evidence(rc, "redacted"), "sk-ant-…") {
		t.Errorf("rc key fix or hint: %v", rc.Evidence)
	}
	tr := one("anthropic ~/.claude/projects/p/s.jsonl scan")
	if tr.Severity != finding.SevHigh || evidence(tr, "kind") != "transcript" || evidence(tr, "fingerprint") != evidence(rc, "fingerprint") {
		t.Errorf("transcript copy: %s %v", tr.Severity, tr.Evidence)
	}
	if tr.Remediation.URL != "https://platform.claude.com/settings/keys" {
		t.Errorf("rotate url %q", tr.Remediation.URL)
	}

	if env.Severity != finding.SevMedium || evidence(env, "tracked") != "false" {
		t.Errorf("local stripe key: %s %v", env.Severity, env.Evidence)
	}
	hist := one("stripe-live ~/src/shop/config/old.env gitleaks")
	if hist.Severity != finding.SevCritical || evidence(hist, "count") != "2" || evidence(hist, "remote") != "true" ||
		evidence(hist, "fingerprint") != evidence(env, "fingerprint") || evidence(hist, "commit") != "0123456789" {
		t.Errorf("stripe key in pushed history: %s %v", hist.Severity, hist.Evidence)
	}
	// A history finding belongs to its repository, as a failed gitleaks scan's status names it.
	if hist.Scope != "history:~/src/shop" || env.Scope != "files" {
		t.Errorf("scopes: history %q, working file %q", hist.Scope, env.Scope)
	}

	// One private key, three places, one fingerprint.
	pemFile := one("private-key ~/src/shop/deploy.pem scan")
	pemGit := one("private-key ~/src/shop/deploy.pem gitleaks")
	pemTr := one("private-key ~/.claude/projects/p/s.jsonl scan")
	if evidence(pemFile, "fingerprint") != evidence(pemGit, "fingerprint") || evidence(pemFile, "fingerprint") != evidence(pemTr, "fingerprint") {
		t.Error("the same private key has different fingerprints")
	}
	if evidence(pemFile, "tracked") != "true" || pemFile.Severity != finding.SevCritical {
		t.Errorf("committed key: %s %v", pemFile.Severity, pemFile.Evidence)
	}

	sa := one("gcp-service-account ~/.config/gcloud/keys/ci.json scan")
	if evidence(sa, "note") != "ci@demo.iam.gserviceaccount.com" || sa.Severity != finding.SevHigh {
		t.Errorf("service account key: %s %v", sa.Severity, sa.Evidence)
	}
	if len(byKey["private-key ~/.config/gcloud/keys/ci.json scan"]) != 0 {
		t.Error("service-account private key reported twice")
	}

	// Noise (the generic gitleaks match, the generic assignment) is counted, not emitted; the
	// summary lists each noise-only value with its type.
	if summary == nil || summary.Severity != finding.SevInfo {
		t.Fatalf("no noise summary: %+v", summary)
	}
	if fps, _ := summary.Evidence["noise_fingerprints"].(map[string]string); len(fps) != 2 {
		t.Errorf("noise fingerprints %v", summary.Evidence["noise_fingerprints"])
	}
	// Noise (the generic gitleaks match, the generic assignment) is counted, not emitted.
	for _, k := range []string{"generic-api-key ~/src/shop/app.js gitleaks", "assignment ~/src/shop/.env scan", "generic-api-key ~/src/shop/README.md gitleaks"} {
		if len(byKey[k]) != 0 {
			t.Errorf("noise emitted by default: %s", k)
		}
	}

	ssh := one("ssh-key ~/.ssh/id_open ssh")
	if ssh.Kind != finding.KindExposure || evidence(ssh, "note") != "ED25519 256 no passphrase" || ssh.Severity != finding.SevMedium {
		t.Errorf("ssh key: %s %s %v", ssh.Kind, ssh.Severity, ssh.Evidence)
	}
	if strings.Contains(string(all), "someone@laptop") {
		t.Error("ssh key comment leaked")
	}

	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateOK || !strings.Contains(rec.Statuses[0].Detail, "gitleaks: 1 repositories (0 unchanged, 0 incremental, 1 full), 0 failed") ||
		!strings.Contains(rec.Statuses[0].Detail, "noise not emitted (emit_noise: true lists it): 2; by type: assignment 1, generic-api-key 1; by place: repo 1, ~/src/shop 1") {
		t.Errorf("statuses %+v", rec.Statuses)
	}
	if st, err := os.Stat(filepath.Join(fx.home, ".config", "segurata", "fingerprint.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("fingerprint key not created 0600: %v", err)
	}
}

func TestEmitNoiseListsNoiseFindings(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, fx.gitleaksReport())
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"emit_noise": true}}, rec); err != nil {
		t.Fatal(err)
	}
	got := map[string]finding.Severity{}
	for _, f := range rec.Findings {
		got[evidence(f, "type")+" "+evidence(f, "path")] = f.Severity
	}
	if got["generic-api-key ~/src/shop/app.js"] != finding.SevInfo || got["assignment ~/src/shop/.env"] != finding.SevInfo {
		t.Errorf("noise findings with emit_noise: %v", got)
	}
	if _, ok := got["generic-api-key ~/src/shop/README.md"]; ok {
		t.Error("placeholder from gitleaks kept")
	}
	if strings.Contains(rec.Statuses[0].Detail, "noise not emitted") {
		t.Errorf("status counts noise that was emitted: %s", rec.Statuses[0].Detail)
	}
}

func TestFingerprintsAreStableAcrossRuns(t *testing.T) {
	fx := newFixture(t)
	fps := func() map[string]bool {
		rec := &recorder{}
		if err := fx.connector(t, "[]").Inventory(context.Background(), connector.Request{}, rec); err != nil {
			t.Fatal(err)
		}
		m := map[string]bool{}
		for _, f := range rec.Findings {
			m[evidence(f, "fingerprint")] = true
		}
		return m
	}
	a, b := fps(), fps()
	if len(a) == 0 || fmt.Sprint(a) != fmt.Sprint(b) {
		t.Errorf("fingerprints changed between runs")
	}
}

func TestMissingRipgrepIsUnsupported(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, "[]")
	c.LookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateUnsupported || len(rec.Findings) != 0 {
		t.Errorf("statuses %+v findings %d", rec.Statuses, len(rec.Findings))
	}
}

func TestGitleaksFailureIsAStatus(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, "not json")
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	var failed bool
	for _, s := range rec.Statuses {
		failed = failed || (s.State == finding.StateError && s.Account == "~/src/shop" && s.Scope == "history:~/src/shop")
	}
	if !failed {
		t.Errorf("no error status, scoped to the repository's history, for the failed repository: %+v", rec.Statuses)
	}
}

// Parts of the machine a configuration leaves unread are declared, so their earlier findings are
// not taken as resolved.
func TestUnreadPartsAreDeclared(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, fx.gitleaksReport())
	for _, tc := range []struct {
		cfg  map[string]any
		want string
	}{
		{map[string]any{}, ""},
		{map[string]any{"skip_git_history": true}, "history:*: skip_git_history is set"},
		{map[string]any{"data_dumps": false}, "dumps:*: data_dumps is false"},
		{map[string]any{"data_dumps": "only"}, `files: data_dumps is "only" | history:*: data_dumps is "only"`},
	} {
		rec := &recorder{}
		if err := c.Inventory(context.Background(), connector.Request{Config: tc.cfg}, rec); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(rec.skipped(), " | "); got != tc.want {
			t.Errorf("%v: skipped %q, want %q", tc.cfg, got, tc.want)
		}
	}
}

func TestReposFindsNestedRepositoriesAndSkipsDependencies(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{"src/a/.git", "src/org/b/.git", "src/org/b/sub/c/.git", "src/a/node_modules/x/.git", "src/1/2/3/4/5/6/deep/.git", ".claude/.git"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s := &scan{home: home, src: filepath.Join(home, "src")}
	var got []string
	for _, r := range s.repos() {
		got = append(got, s.tilde(r))
	}
	want := "[~/.claude ~/src/a ~/src/org/b ~/src/org/b/sub/c]"
	if fmt.Sprint(got) != want {
		t.Errorf("repos %v, want %s", got, want)
	}
}

func TestWorktreeRemoteIsReadFromTheCommonDir(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main", ".git")
	wt := filepath.Join(main, "worktrees", "w")
	for _, d := range []string{wt, filepath.Join(dir, "w")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(main, "config"), []byte("[remote \"origin\"]\n"), 0o600)
	_ = os.WriteFile(filepath.Join(wt, "commondir"), []byte("../..\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "w", ".git"), []byte("gitdir: "+wt+"\n"), 0o600)
	if !configHasRemote(gitConfigPath(filepath.Join(dir, "w"))) {
		t.Error("worktree remote not found")
	}
	if configHasRemote(gitConfigPath(filepath.Join(dir, "none"))) {
		t.Error("remote reported for a missing repository")
	}
}

func TestNoChmodFixForNoise(t *testing.T) {
	readable := secretrisk.Evidence{Source: "scan", Kind: "config", Mode: "644"}
	readable.Type = "assignment" // generic match: noise
	if r := remedy("s", "", readable); r.Action != "" {
		t.Fatalf("noise in a readable file must not offer a fix, got %q", r.Action)
	}
	readable.Type = "anthropic"
	if r := remedy("s", "", readable); r.Action != "file.chmod600" || r.Severity != "" || r.Group != "" {
		t.Fatalf("a real key in a readable file should offer chmod 600 ranked by the finding, got %+v", r)
	}
}

// A file the home folder closes is still worth closing itself: the home folder may open later.
func TestChmodHardeningForFilesOnlyAParentCloses(t *testing.T) {
	ev := secretrisk.Evidence{Source: "scan", Kind: "config", Type: "anthropic", Mode: "600", FileMode: "644",
		Path: "~/src/acme/app/config/.env"}
	r := remedy("Move it to the Keychain.", "", ev)
	if r.Action != "file.chmod600" || r.Severity != finding.SevLow || r.Group != "files in ~/src/acme/app" {
		t.Fatalf("hardening: %+v", r)
	}
	if !strings.HasPrefix(r.Summary, "Move it to the Keychain.") || !strings.Contains(r.Summary, "mode 644") {
		t.Fatalf("summary %q", r.Summary)
	}
	if g := hardeningGroup("~/.claude/history.jsonl"); g != "files in ~/.claude" {
		t.Errorf("shallow file group: %q", g)
	}
	ev.FileMode = "" // the file itself is private
	if r := remedy("s", "", ev); r.Action != "" {
		t.Fatalf("a private file needs nothing: %+v", r)
	}
	ev.FileMode, ev.Type = "644", "assignment"
	if r := remedy("s", "", ev); r.Action != "" {
		t.Fatalf("noise gets no hardening either: %+v", r)
	}
}

func TestModeCountsParentFolders(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "src", "app")
	_ = os.MkdirAll(dir, 0o755)
	f := filepath.Join(dir, ".env")
	_ = os.WriteFile(f, []byte("X=1\n"), 0o644)
	_ = os.Chmod(f, 0o644)

	_ = os.Chmod(home, 0o755)
	if eff, raw := modeOf(f, home); eff != "644" || raw != "" {
		t.Fatalf("open home: effective %q, file %q", eff, raw)
	}
	_ = os.Chmod(home, 0o700)
	if eff, raw := modeOf(f, home); eff != "600" || raw != "644" {
		t.Fatalf("closed home must close the file for others: effective %q, file %q", eff, raw)
	}
	_ = os.Chmod(home, 0o750) // the staff group can still traverse
	if eff, _ := modeOf(f, home); eff != "640" {
		t.Fatalf("group-traversable home: effective %q", eff)
	}
}

// Trails must see in a trail exactly what an inventory reports there: same types, same
// fingerprints, same noise.
func TestTrailsFindAgreesWithInventory(t *testing.T) {
	fx := newFixture(t)
	noise := fake("", 19) + "7"
	fx.write(t, ".zsh_history", ": 1700000000:0;export OPENAI_KEY="+fake("sk-proj-", 50)+"\n: 1700000001:0;MY_SECRET="+noise+"\n", 0o600)
	fx.write(t, "Library/Logs/app/app.log", "token "+fake("ghp_", 36)+" and https://u:"+fake("", 12)+"9@db.example.com\n", 0o600)
	c := fx.connector(t, "[]")
	rec := &recorder{}
	// Noise included: Trails reports every hit, with its impact.
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"emit_noise": true}}, rec); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, f := range rec.Findings {
		if isTrail(evidence(f, "kind")) && evidence(f, "source") == "scan" {
			want[evidence(f, "path")+" "+evidence(f, "type")+" "+evidence(f, "fingerprint")] = true
		}
	}
	tr, err := c.Trails(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := tr.Lines(nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for p, ls := range lines {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		all := strings.Split(string(raw), "\n")
		for _, n := range ls {
			text := all[n-1]
			for _, h := range tr.Find(p, tr.Mode(p), text) {
				got[tr.Tilde(p)+" "+h.Type+" "+h.Fingerprint] = true
				if h.Fingerprint != fx.fpOf(t, c, text[h.Start:h.End], h.Type) {
					t.Errorf("%s: the span does not hold the fingerprinted value", h.Type)
				}
			}
		}
	}
	if len(want) < 5 {
		t.Fatalf("fixture too small: %v", want)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("inventory reports %s, Trails does not", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("Trails finds %s, the inventory does not", k)
		}
	}
}

// fpOf fingerprints a span as the scan does: a private key by its body, anything else whole.
func (fx *fixture) fpOf(t *testing.T, c *Connector, span, typ string) string {
	t.Helper()
	key, err := fingerprint.Open(c.KeyPath(fx.home))
	if err != nil {
		t.Fatal(err)
	}
	if typ == privateKeyType {
		return key.Of(pemBody(span))
	}
	return key.Of(span)
}

// A trail search that ripgrep could not finish is an error, never a clean list: redact would
// otherwise skip the files it missed and verify a rewrite against nothing.
func TestTrailsLinesFailsWhenRipgrepFails(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, "[]")
	if _, err := fingerprint.Load(c.KeyPath(fx.home)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, script string
		fails        bool
	}{
		{"regex error", `echo "rg: regex parse error" >&2; exit 2`, true},
		{"killed", `kill -9 $$`, true},
		{"unreadable files only", `echo "rg: /x/a: Permission denied (os error 13)" >&2; exit 2`, false},
		{"no match", `exit 1`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.RG = cli.Exec{Path: writeExe(t, "rg", tc.script), Timeout: time.Minute}
			tr, err := c.Trails(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, files := range [][]string{nil, {filepath.Join(fx.home, ".zsh_history")}} {
				fx.write(t, ".zsh_history", "x\n", 0o600)
				if _, err := tr.Lines(files); (err != nil) != tc.fails {
					t.Errorf("files %v: error %v, want failure %v", files, err, tc.fails)
				}
			}
		})
	}
}

// A log keeps every match of the passes that read it: the credential-file pass reads ~/.config
// with the assignment pattern, and so does the whole-tree pass over repos_root when gitleaks is
// missing; with gitleaks, repos_root's logs get the trail pass's specific patterns only.
func TestLogsKeepTheMatchesOfEveryPassThatReadsThem(t *testing.T) {
	fx := newFixture(t)
	noise := fake("", 19) + "7"
	fx.write(t, "src/shop/server.log", "auth "+fake("ghp_", 36)+"\nMY_TOKEN="+noise+"\n", 0o600)
	fx.write(t, ".config/tool/debug.log", "MY_TOKEN="+fake("ghp_", 36)+"\nOTHER_TOKEN="+noise+"\n", 0o600)
	c := fx.connector(t, "[]")
	for _, gitleaks := range []bool{true, false} {
		c.LookPath = func(n string) (string, error) {
			if n == "gitleaks" && !gitleaks {
				return "", exec.ErrNotFound
			}
			return "/bin/true", nil
		}
		rec := &recorder{}
		if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false, "emit_noise": true}}, rec); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range rec.Findings {
			if p := evidence(f, "path"); strings.HasSuffix(p, ".log") {
				got = append(got, p+" "+evidence(f, "type"))
			}
		}
		slices.Sort(got)
		want := []string{"~/.config/tool/debug.log assignment", "~/.config/tool/debug.log github", "~/src/shop/server.log github"}
		if !gitleaks {
			want = append(want, "~/src/shop/server.log assignment")
			slices.Sort(want)
		}
		if !slices.Equal(got, want) {
			t.Errorf("gitleaks installed %v: log findings %v, want %v", gitleaks, got, want)
		}
	}
}
