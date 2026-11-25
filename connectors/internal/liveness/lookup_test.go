package liveness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/sshkey"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/testcorpus"
)

// cliFake is a CLI that answers by command line and records every one. Its errors echo every
// argument, as a CLI's stderr may: the lookups must keep none of it.
type cliFake struct {
	mu      sync.Mutex
	calls   [][]string
	answers func(args []string) (string, error)
}

func (f *cliFake) Run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, args)
	f.mu.Unlock()
	out, err := f.answers(args)
	if err != nil {
		return nil, &cli.Error{Cmd: "fake", Stderr: err.Error() + " args: " + strings.Join(args, " "), Err: errors.New("exit status 254")}
	}
	return []byte(out), nil
}

func (f *cliFake) called(sub string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if j := strings.Join(c, " "); strings.Contains(j, sub) {
			out = append(out, j)
		}
	}
	return out
}

func awsDenied(action string) error {
	return fmt.Errorf("An error occurred (AccessDenied) when calling the %s operation: not authorized to perform: %s", action, action)
}

// noLeak fails when any of values, or any 12-character run of one, is in the results or the stats.
func noLeak(t *testing.T, got map[string]secretrisk.Liveness, st Stats, values ...string) {
	t.Helper()
	raw, _ := json.Marshal(got)
	out := string(raw) + st.String()
	for _, v := range values {
		for i := 0; i+12 <= len(v); i += 4 {
			if strings.Contains(out, v[i:i+12]) {
				t.Fatalf("a part of a secret reached the output: %s", out)
			}
		}
	}
}

func lookupChecker(o Owner, cfg Config) *Checker {
	cfg.Enabled = true
	return &Checker{Config: cfg, Owner: o, Interval: time.Hour} // a lookup never waits on the limiter
}

func TestLookupAWSKeys(t *testing.T) {
	const prod, partial, other = "111111111111", "222222222222", "333333333333"
	acct := func(s string) uint64 {
		var n uint64
		fmt.Sscan(s, &n)
		return n
	}
	active := testcorpus.AWSKeyID("AKIA", acct(prod), false, 1)
	inactive := testcorpus.AWSKeyID("AKIA", acct(prod), false, 2)
	deleted := testcorpus.AWSKeyID("AKIA", acct(prod), false, 3)
	unreadable := testcorpus.AWSKeyID("AKIA", acct(partial), false, 1)
	elsewhere := testcorpus.AWSKeyID("AKIA", acct(other), false, 1)
	oldFormat := testcorpus.AWSKeyID("AKIA", 8<<36, false, 1) // fifth character I: no account inside
	oldDenied := testcorpus.AWSKeyID("AKIA", 8<<36, false, 2)
	if _, ok := attribution.AWSAccountFromKeyID(oldFormat); ok {
		t.Fatal("the old-format key id decodes")
	}
	aws := &cliFake{answers: func(a []string) (string, error) {
		profile := ""
		if i := slices.Index(a, "--profile"); i >= 0 {
			profile = a[i+1]
		}
		cmd := strings.Join(a[:2], " ")
		switch {
		case cmd == "configure list-profiles":
			return "prod\npartial\nexpired\nprod-again\n", nil
		case profile == "expired":
			return "", errors.New("An error occurred (ExpiredToken) when calling the GetCallerIdentity operation")
		case cmd == "sts get-caller-identity":
			return map[string]string{"prod": `{"Account":"` + prod + `"}`, "prod-again": `{"Account":"` + prod + `"}`, "partial": `{"Account":"` + partial + `"}`}[profile], nil
		case cmd == "iam list-users" && profile == "partial":
			return "", awsDenied("iam:ListUsers")
		case cmd == "iam list-users":
			return `{"Users":[{"UserName":"alice"},{"UserName":"bob"}]}`, nil
		case cmd == "iam list-access-keys" && a[3] == "alice":
			return `{"AccessKeyMetadata":[{"AccessKeyId":"` + active + `","Status":"Active"},{"AccessKeyId":"` + inactive + `","Status":"Inactive"}]}`, nil
		case cmd == "iam list-access-keys":
			return `{"AccessKeyMetadata":[]}`, nil
		case cmd == "iam get-account-summary":
			return `{"SummaryMap":{"AccountAccessKeysPresent":0}}`, nil
		case cmd == "sts get-access-key-info" && a[3] == oldFormat:
			return `{"Account":"` + prod + `"}`, nil
		case cmd == "sts get-access-key-info":
			return "", awsDenied("sts:GetAccessKeyInfo")
		}
		return "", errors.New("unexpected")
	}}
	c := lookupChecker(Owner{AWS: aws}, Config{})
	temporary := testcorpus.AWSKeyID("ASIA", acct(prod), false, 4) // in a complete inventory's account, yet never listed
	ids := []string{active, inactive, deleted, unreadable, elsewhere, oldFormat, oldDenied, temporary}
	var probes []Probe
	for i, id := range ids {
		probes = append(probes, Probe{Fingerprints: []string{fmt.Sprint(i)}, Type: "aws-access-key-id", Value: id})
	}
	got, st := c.Check(context.Background(), probes)
	noLeak(t, got, st, ids...)

	want := []struct {
		state   secretrisk.LiveState
		reason  string
		account string
	}{
		{secretrisk.Live, "Active, IAM user alice of account " + prod, "aws:" + prod},
		{secretrisk.Dead, "Inactive, IAM user alice of account " + prod, "aws:" + prod},
		{secretrisk.Dead, "not among the access keys of account " + prod + ": deleted", "aws:" + prod},
		{secretrisk.Unknown, "account " + partial + "'s access keys could not all be read", "aws:" + partial},
		{secretrisk.Unknown, "account " + other + ", which none of your AWS profiles reaches", "aws:" + other},
		{secretrisk.Dead, "not among the access keys of account " + prod + ": deleted", "aws:" + prod},
		{secretrisk.Unknown, "its account is not known", ""},
		{secretrisk.Unknown, "temporary credentials, which no IAM inventory lists", ""},
	}
	for i, w := range want {
		r := got[fmt.Sprint(i)]
		if r.State != w.state || r.Reason != w.reason || r.Account != w.account || !r.ByOwner || r.Provider != "aws-keys" {
			t.Errorf("key %d: %+v, want %s %q %s", i, r, w.state, w.reason, w.account)
		}
	}
	if st.Asked != 8 || st.Live != 1 || st.Dead != 3 || st.Unknown != 4 {
		t.Errorf("stats %+v", st)
	}
	line := st.String()
	for _, h := range []string{"profile expired does not sign in (ExpiredToken)", "profile partial may not call iam:ListUsers", "SecurityAudit",
		"profile prod may not call sts:GetAccessKeyInfo"} {
		if !strings.Contains(line, h) {
			t.Errorf("hints lack %q: %s", h, line)
		}
	}
	// The inventory is read once for every probe; an account two profiles reach, once.
	if n := len(aws.called("iam list-users")); n != 2 {
		t.Errorf("list-users ran %d times", n)
	}
	// The key id goes to a command only for the old-format ones.
	for _, id := range ids {
		calls := aws.called(id)
		if (id == oldFormat || id == oldDenied) != (len(calls) == 1) || len(calls) == 1 && !strings.HasPrefix(calls[0], "sts get-access-key-info") {
			t.Errorf("commands with a key id: %d", len(calls))
		}
	}

	// Root keys present: an id no IAM user has may be the root user's.
	root := &cliFake{answers: func(a []string) (string, error) {
		if strings.Join(a[:2], " ") == "iam get-account-summary" {
			return `{"SummaryMap":{"AccountAccessKeysPresent":1}}`, nil
		}
		return aws.answers(a)
	}}
	got, _ = lookupChecker(Owner{AWS: root}, Config{AWSProfiles: []string{"prod"}}).Check(context.Background(), probes[2:3])
	if r := got["2"]; r.State != secretrisk.Unknown || !strings.Contains(r.Reason, "root user has keys") {
		t.Errorf("root keys: %+v", r)
	}
	if len(root.called("configure list-profiles")) != 0 {
		t.Error("configured profiles were not used")
	}
}

// No aws CLI, or no profile: unknown, with a hint, never a failed run.
func TestLookupAWSDegrades(t *testing.T) {
	id := testcorpus.AWSKeyID("AKIA", 111111111111, false, 1)
	probe := []Probe{{Fingerprints: []string{"k"}, Type: "aws-access-key-id", Value: id}}
	for name, o := range map[string]Owner{
		"no runner":     {},
		"not installed": {AWS: cli.RunnerFunc(func(context.Context, ...string) ([]byte, error) { return nil, fmt.Errorf("aws: %w", exec.ErrNotFound) })},
		"no profiles":   {AWS: &cliFake{answers: func([]string) (string, error) { return "\n", nil }}},
	} {
		got, st := lookupChecker(o, Config{}).Check(context.Background(), probe)
		if r := got["k"]; r.State != secretrisk.Unknown || r.Account != "aws:111111111111" {
			t.Errorf("%s: %+v", name, r)
		}
		noLeak(t, got, st, id)
	}
}

// opensshBody wraps a public key in an unencrypted OpenSSH private key container; the private
// section is filler, which the lookup never reads.
func opensshBody(pub sshkey.Public) string {
	str := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	b := []byte("openssh-key-v1\x00")
	b = append(b, str([]byte("none"))...)
	b = append(b, str([]byte("none"))...)
	b = append(b, str(nil)...)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, str(pub.Blob)...)
	b = append(b, str([]byte("private section, not read"))...)
	return base64.StdEncoding.EncodeToString(b)
}

type testKey struct {
	pkcs8, openssh, line string
}

func newTestKey(t *testing.T) testKey {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	body := base64.StdEncoding.EncodeToString(der)
	pub, _, err := sshkey.FromPrivate(body)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{pkcs8: body, openssh: opensshBody(pub), line: pub.Type + " " + base64.StdEncoding.EncodeToString(pub.Blob)}
}

func TestLookupSSHKeys(t *testing.T) {
	keys := map[string]testKey{}
	for _, n := range []string{"github", "signing", "deploy", "authorized", "host", "localpub", "nowhere", "pem"} {
		keys[n] = newTestKey(t)
	}
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(ssh, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("authorized_keys", "# mine\n"+`no-pty `+keys["authorized"].line+" me@laptop\n")
	write("work.pub", keys["localpub"].line+" me@work\n")

	signingScope := true
	gh := &cliFake{answers: func(a []string) (string, error) {
		path := a[len(a)-1]
		list := func(k testKey, title string) string {
			return fmt.Sprintf(`[{"id":1,"key":%q,"title":%q}]`, k.line, title)
		}
		switch path {
		case "user":
			return `{"login":"octocat"}`, nil
		case "user/keys":
			return list(keys["github"], "laptop") + "[]", nil // --paginate prints one array per page
		case "user/ssh_signing_keys":
			if !signingScope {
				return "", errors.New("HTTP 404: Not Found (needs the read:ssh_signing_key scope)")
			}
			return list(keys["signing"], "signer"), nil
		case "user/repos?affiliation=owner&sort=pushed&per_page=30":
			return `[{"full_name":"octocat/shop","owner":{"login":"octocat"}},{"full_name":"octocat/locked","owner":{"login":"octocat"}}]`, nil
		case "repos/octocat/shop/keys":
			return list(keys["deploy"], "ci"), nil
		}
		return "", errors.New("HTTP 403")
	}}
	sshRunner := &cliFake{answers: func(a []string) (string, error) {
		if slices.Contains(a, "build1") {
			return keys["host"].line + " deploy\n", nil
		}
		return "", errors.New("Permission denied (publickey)")
	}}
	o := Owner{GH: gh, SSH: sshRunner, Home: home}
	cfg := Config{SSHHosts: []string{"build1", "deploy@down"}}
	var probes []Probe
	var bodies []string
	for n, k := range keys {
		p := Probe{Fingerprints: []string{n}, Type: "private-key", Value: k.openssh}
		if n == "pem" {
			p.Value = k.pkcs8
		}
		probes = append(probes, p, Probe{Fingerprints: []string{n + "/ssh"}, Type: "ssh-key", Value: k.pkcs8})
		bodies = append(bodies, k.pkcs8, k.openssh)
	}
	encrypted := base64.StdEncoding.EncodeToString(must(asn1.Marshal(struct {
		Algo pkix.AlgorithmIdentifier
		Data []byte
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}}, []byte("ciphertext")})))
	probes = append(probes, Probe{Fingerprints: []string{"encrypted"}, Type: "private-key", Value: encrypted},
		Probe{Fingerprints: []string{"cut"}, Type: "private-key", Value: keys["nowhere"].openssh[:40]})
	bodies = append(bodies, encrypted)

	got, st := lookupChecker(o, cfg).Check(context.Background(), probes)
	noLeak(t, got, st, bodies...)
	want := map[string]struct {
		state           secretrisk.LiveState
		reason, account string
	}{
		"github":     {secretrisk.Live, `GitHub SSH key "laptop"`, "github:octocat"},
		"signing":    {secretrisk.Live, `GitHub signing key "signer"`, "github:octocat"},
		"deploy":     {secretrisk.Live, `deploy key "ci" of octocat/shop`, "github:octocat"},
		"authorized": {secretrisk.Live, "authorized on this machine (~/.ssh/authorized_keys)", ""},
		"host":       {secretrisk.Live, "authorized on host build1", ""},
		"localpub":   {secretrisk.Unknown, "the public half of ~/.ssh/work.pub on this machine, registered nowhere segurata can see", ""},
		"nowhere":    {secretrisk.Unregistered, "registered nowhere segurata can see: your GitHub SSH and signing keys, the deploy keys of 1 repositories, authorized_keys here and on 1 hosts", ""},
		"pem":        {secretrisk.Unknown, "not an OpenSSH key: it may sign TLS certificates or JWTs, which segurata cannot look up", ""},
		"pem/ssh":    {secretrisk.Unregistered, "", ""}, // from ~/.ssh: an SSH key whatever its container
		"encrypted":  {secretrisk.Unknown, "encrypted, and no passphrase is at hand", ""},
		"cut":        {secretrisk.Unknown, "not a whole private key segurata can read", ""},
	}
	for fp, w := range want {
		r := got[fp]
		if r.State != w.state || w.reason != "" && r.Reason != w.reason || r.Account != w.account || !r.ByOwner || r.Provider != "ssh-keys" {
			t.Errorf("%s: %+v, want %s %q %s", fp, r, w.state, w.reason, w.account)
		}
		if w.state == secretrisk.Live && got[fp+"/ssh"].State != secretrisk.Live {
			t.Errorf("%s: the same key in a PEM container: %+v", fp, got[fp+"/ssh"])
		}
	}
	if !strings.Contains(st.String(), "ssh: deploy@down: authorized_keys not read") {
		t.Errorf("no hint for the host: %s", st)
	}
	if n := len(gh.called("user/keys")); n != 1 {
		t.Errorf("GitHub keys listed %d times", n)
	}
	for _, c := range sshRunner.calls {
		if !slices.Contains(c, "BatchMode=yes") || c[len(c)-2] != "cat" {
			t.Errorf("ssh %v", c)
		}
	}

	// Without the signing keys, a key found nowhere is unknown: GitHub's lists are incomplete.
	signingScope = false
	got, st = lookupChecker(o, Config{}).Check(context.Background(), probes)
	if r := got["nowhere"]; r.State != secretrisk.Unknown || r.Reason != "your GitHub keys could not be listed" {
		t.Errorf("incomplete GitHub lists: %+v", r)
	}
	if got["github"].State != secretrisk.Live || !strings.Contains(st.String(), "gh auth refresh -h github.com -s read:ssh_signing_key") {
		t.Errorf("a registered key is still found, with a hint: %+v %s", got["github"], st)
	}
}

func TestLookupGuards(t *testing.T) {
	for _, args := range [][]string{
		{"api", "-X", "POST", "user/keys"},
		{"api", "user/keys", "-f", "title=x"},
		{"api", "graphql"},
		{"api", "--paginate", "user/keys", "--method", "DELETE"},
		{"api", "repos/a/b/keys/1"},
		{"repo", "list"},
	} {
		if ghReadOnly.Check(args) == nil {
			t.Errorf("gh %v allowed", args)
		}
	}
	for _, args := range [][]string{{"api", "user"}, {"api", "--paginate", "user/keys"}, {"api", "repos/octo-cat/my.repo/keys"}} {
		if err := ghReadOnly.Check(args); err != nil {
			t.Errorf("gh %v refused", args)
		}
	}
	if sshReadOnly.Check(sshArgs("me@host-1.example")) != nil {
		t.Error("ssh refused")
	}
	for _, args := range [][]string{
		append(sshArgs("host")[:len(sshArgs("host"))-1], "rm"),
		sshArgs("-oProxyCommand=sh"),
		{"host", "cat", ".ssh/authorized_keys"},
	} {
		if sshReadOnly.Check(args) == nil {
			t.Errorf("ssh %v allowed", args)
		}
	}
	for _, args := range [][]string{{"iam", "delete-access-key"}, {"iam", "update-access-key"}, {"sts", "assume-role"}} {
		if awsReadOnly.Check(args) == nil {
			t.Errorf("aws %v allowed", args)
		}
	}
}

// A lookup's result is cached by fingerprint like a provider's; unregistered holds a day.
func TestLookupCache(t *testing.T) {
	k := newTestKey(t)
	home := t.TempDir()
	cache := LoadCache(filepath.Join(home, "liveness.json"))
	gh := &cliFake{answers: func(a []string) (string, error) {
		if a[len(a)-1] == "user" {
			return `{"login":"octocat"}`, nil
		}
		return "[]", nil
	}}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	c := lookupChecker(Owner{GH: gh, Home: home}, Config{})
	c.Cache, c.Now = cache, func() time.Time { return now }
	probe := []Probe{{Fingerprints: []string{"k"}, Type: "private-key", Value: k.openssh}}
	if got, _ := c.Check(context.Background(), probe); got["k"].State != secretrisk.Unregistered {
		t.Fatalf("%+v", got["k"])
	}
	calls := len(gh.calls)
	if _, st := c.Check(context.Background(), probe); st.Cached != 1 || len(gh.calls) != calls {
		t.Errorf("not cached: %+v", st)
	}
	if err := cache.Save(now); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(home, "liveness.json"))
	if strings.Contains(string(raw), k.pkcs8[len(k.pkcs8)-24:]) || strings.Contains(string(raw), k.openssh[len(k.openssh)-24:]) || !strings.Contains(string(raw), `"by_owner": true`) {
		t.Errorf("cache file: %s", raw)
	}
	c.Now = func() time.Time { return now.Add(LiveTTL + time.Minute) }
	if _, st := c.Check(context.Background(), probe); st.Cached != 0 {
		t.Errorf("an unregistered result outlived a day: %+v", st)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
