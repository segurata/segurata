package localsecrets

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/segurata/segurata/internal/secretrisk"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
)

// Every secret in these tests is generated at run time from a fixed seed: no real or real-looking
// literal ever sits in the source.

var rng = rand.New(rand.NewPCG(7, 11))

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func fake(prefix string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alnum[rng.IntN(len(alnum))]
	}
	return prefix + string(b)
}

// fakePEM is random bytes in PEM armour: enough to exercise body extraction and fingerprints.
func fakePEM(label string, raw []byte) (pem, body string) {
	if raw == nil {
		raw = make([]byte, 600)
		for i := range raw {
			raw[i] = byte(rng.IntN(256))
		}
	}
	body = base64.StdEncoding.EncodeToString(raw)
	var lines []string
	for i := 0; i < len(body); i += 64 {
		lines = append(lines, body[i:min(i+64, len(body))])
	}
	head := "-----BEGIN " + strings.TrimSpace(label+" PRIVATE KEY") + "-----"
	tail := "-----END " + strings.TrimSpace(label+" PRIVATE KEY") + "-----"
	return head + "\n" + strings.Join(lines, "\n") + "\n" + tail + "\n", body
}

func opensshBlob(cipher string) []byte {
	b := []byte("openssh-key-v1\x00")
	b = binary.BigEndian.AppendUint32(b, uint32(len(cipher)))
	b = append(b, cipher...)
	for range 200 {
		b = append(b, byte(rng.IntN(256)))
	}
	return b
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
	pem, body := fakePEM("RSA", nil)
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

func specificByType(typ string) *pattern {
	for i := range specific {
		if specific[i].typ == typ {
			return &specific[i]
		}
	}
	return nil
}

func TestPEMEncrypted(t *testing.T) {
	_, plain := fakePEM("OPENSSH", opensshBlob("none"))
	_, locked := fakePEM("OPENSSH", opensshBlob("aes256-ctr"))
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

func TestGuards(t *testing.T) {
	refused := func(c cli.Checker, args ...string) bool { return errors.Is(c.Check(args), cli.ErrRefused) }
	if !refused(rgCheck, "--pre", "sh", "-e", "x") || !refused(rgCheck, "--pre=sh") || !refused(rgCheck, "-z", "-e", "x") {
		t.Error("rg ran another program")
	}
	if refused(rgCheck, "-o", "-e", "x", "--", "--pre") {
		t.Error("a path after -- is not a flag")
	}
	if !refused(gitleaksCheck, "git", "--report-path", "/tmp/r.json", "repo") || !refused(gitleaksCheck, "git", "--report-path=r.json", "repo") {
		t.Error("gitleaks may write the raw report to a file")
	}
	if !refused(gitleaksCheck, "dir", "repo") || refused(gitleaksCheck, "git", "--report-path", "-", "repo") ||
		refused(gitleaksCheck, "version") || !refused(gitleaksCheck, "version", "--config=x") {
		t.Error("gitleaks subcommand check")
	}
	if refused(gitList, "--git-dir=/r/.git", "--work-tree=/r", "ls-files", "-z") || !refused(gitList, "--git-dir=/r/.git", "config", "x") {
		t.Error("git check")
	}
	if refused(sshKeygenCheck, "-y", "-P", "", "-f", "k") || refused(sshKeygenCheck, "-l", "-f", "k.pub") {
		t.Error("ssh-keygen read-only shapes refused")
	}
	if !refused(sshKeygenCheck, "-p", "-f", "k") || !refused(sshKeygenCheck, "-y", "-P", "guess", "-f", "k") {
		t.Error("ssh-keygen may change a key or try a passphrase")
	}
}

func TestSettings(t *testing.T) {
	s, err := parseSettings(map[string]any{"repos_root": "~/code", "skip_git_history": true, "gitleaks_workers": 2.0, "gitleaks_timeout": "90s"}, "/h")
	if err != nil || s.reposRoot != "/h/code" || !s.skipHistory || s.workers != 2 || s.timeout != 90*time.Second {
		t.Fatalf("settings %+v err %v", s, err)
	}
	if _, err := parseSettings(map[string]any{"gitleaks_timeout": "soon"}, "/h"); err == nil {
		t.Error("bad timeout accepted")
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
	fx.keyPEM, _ = fakePEM("RSA", nil)
	sshPEM, _ := fakePEM("OPENSSH", opensshBlob("none"))
	saPEM, _ := fakePEM("", nil)
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

type recorder struct {
	mu       sync.Mutex
	findings []finding.Finding
	statuses []finding.Status
}

func (r *recorder) Finding(f finding.Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f.Connector = name
	f.Fill(time.Now())
	r.findings = append(r.findings, f)
}
func (r *recorder) Status(s finding.Status) {
	r.mu.Lock()
	r.statuses = append(r.statuses, s)
	r.mu.Unlock()
}
func (r *recorder) Log(string) {}

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
		KeyPath:  func(home string) string { return filepath.Join(home, ".config", "securizame", "fingerprint.key") },
		CacheDir: DefaultCacheDir,
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
	all, _ := json.Marshal(rec.findings)
	for _, s := range fx.secrets {
		for _, piece := range []string{s, pemBody(s)} {
			if len(piece) >= 6 && strings.Contains(string(all), piece) {
				t.Fatalf("a raw secret reached the output")
			}
		}
	}

	byKey := map[string][]finding.Finding{}
	for _, f := range rec.findings {
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

	gen := one("generic-api-key ~/src/shop/app.js gitleaks")
	if gen.Severity != finding.SevInfo {
		t.Errorf("generic match severity %s", gen.Severity)
	}
	if len(byKey["generic-api-key ~/src/shop/README.md gitleaks"]) != 0 {
		t.Error("placeholder from gitleaks kept")
	}
	if a := one("assignment ~/src/shop/.env scan"); a.Severity != finding.SevInfo {
		t.Errorf("assignment severity %s", a.Severity)
	}

	ssh := one("ssh-key ~/.ssh/id_open ssh")
	if ssh.Kind != finding.KindExposure || evidence(ssh, "note") != "ED25519 256 no passphrase" || ssh.Severity != finding.SevMedium {
		t.Errorf("ssh key: %s %s %v", ssh.Kind, ssh.Severity, ssh.Evidence)
	}
	if strings.Contains(string(all), "someone@laptop") {
		t.Error("ssh key comment leaked")
	}

	if len(rec.statuses) != 1 || rec.statuses[0].State != finding.StateOK || !strings.Contains(rec.statuses[0].Detail, "gitleaks: 1 repositories (0 unchanged, 0 incremental, 1 full), 0 failed") {
		t.Errorf("statuses %+v", rec.statuses)
	}
	if st, err := os.Stat(filepath.Join(fx.home, ".config", "securizame", "fingerprint.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("fingerprint key not created 0600: %v", err)
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
		for _, f := range rec.findings {
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
	if len(rec.statuses) != 1 || rec.statuses[0].State != finding.StateUnsupported || len(rec.findings) != 0 {
		t.Errorf("statuses %+v findings %d", rec.statuses, len(rec.findings))
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
	for _, s := range rec.statuses {
		failed = failed || (s.State == finding.StateError && s.Account == "~/src/shop")
	}
	if !failed {
		t.Errorf("no error status for the failed repository: %+v", rec.statuses)
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
	if a := action(readable); a != "" {
		t.Fatalf("noise in a readable file must not offer a fix, got %q", a)
	}
	readable.Type = "anthropic"
	if a := action(readable); a != "file.chmod600" {
		t.Fatalf("a real key in a readable file should offer chmod 600, got %q", a)
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
	if err := c.Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, f := range rec.findings {
		if IsTrail(evidence(f, "kind")) && evidence(f, "source") == "scan" {
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
