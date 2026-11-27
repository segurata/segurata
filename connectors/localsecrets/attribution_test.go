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
	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
	"github.com/segurata/segurata/internal/testcorpus"
)

func TestAttributeEnrichesEvidenceWithoutTheKeyID(t *testing.T) {
	dir := t.TempDir()
	id := testcorpus.AWSKeyID("AKIA", 123456789012, false, 9)
	secretKey := fake("", 40)
	creds := filepath.Join(dir, "credentials")
	if err := os.WriteFile(creds, []byte("[default]\naws_access_key_id = "+id+"\naws_secret_access_key = "+secretKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sa := filepath.Join(dir, "sa.json")
	if err := os.WriteFile(sa, []byte(`{"type": "service_account", "project_id": "acme-prod-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &scan{}
	cases := []struct {
		name  string
		path  string
		ev    secretrisk.Evidence
		value string
		want  attribution.Claims
	}{
		{"key id", creds, secretrisk.Evidence{Source: "scan", Type: "aws-access-key-id"}, id, attribution.Claims{AWSAccount: "123456789012"}},
		{"secret key: the key id next to it", creds, secretrisk.Evidence{Source: "scan", Type: "aws-secret-key"}, secretKey, attribution.Claims{AWSAccount: "123456789012"}},
		{"service account: its project", sa, secretrisk.Evidence{Source: "scan", Type: "gcp-service-account"}, "body", attribution.Claims{GCPProject: "acme-prod-1"}},
		{"no context for other services", creds, secretrisk.Evidence{Source: "scan", Type: "anthropic"}, fake("sk-ant-api03-", 80), attribution.Claims{}},
		{"slack webhook", creds, secretrisk.Evidence{Source: "scan", Type: "slack-webhook"}, "https://hooks.slack.com/services/T0ABCDEF1/B0ABCDEF1/" + fake("", 24), attribution.Claims{SlackTeam: "T0ABCDEF1"}},
		{"history: author kept, file not read", creds, secretrisk.Evidence{Source: "gitleaks", Type: "aws-secret-key", Claims: attribution.Claims{AuthorEmail: "me@x.com"}}, secretKey, attribution.Claims{AuthorEmail: "me@x.com"}},
	}
	for _, c := range cases {
		ev := c.ev
		s.attribute(c.path, &ev, c.value)
		if ev.Claims != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, ev.Claims, c.want)
		}
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), id) || strings.Contains(string(raw), secretKey) {
			t.Errorf("%s: the key id or value reached the evidence: %s", c.name, raw)
		}
	}
}

func TestLeakClaims(t *testing.T) {
	id := testcorpus.AWSKeyID("AKIA", 222233334444, false, 1)
	l := leak{Match: "aws_secret_access_key = x", Line: "AWS_ACCESS_KEY_ID=" + id + " aws_secret_access_key = x", Email: "Me@X.com"}
	if c := leakClaims(l, secretrisk.Evidence{Type: "aws-secret-key"}); c != (attribution.Claims{AWSAccount: "222233334444", AuthorEmail: "Me@X.com"}) {
		t.Errorf("aws: %+v", c)
	}
	if c := leakClaims(l, secretrisk.Evidence{Type: "stripe-live"}); c != (attribution.Claims{AuthorEmail: "Me@X.com"}) {
		t.Errorf("stripe: %+v", c)
	}
}

// genKey writes a fresh key pair with ssh-keygen under dir and returns the private key's PEM body
// and the public line.
func genKey(t *testing.T, dir, name string, args ...string) (body, pub string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if out, err := exec.Command("ssh-keygen", append([]string{"-q", "-C", "test", "-f", path}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	priv, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return pemBody(string(priv)), strings.TrimSpace(string(p))
}

// A private key is the owner's when its public half is in ~/.ssh or on one of their GitHub users;
// an unknown or unreadable one claims nothing about whose it is.
func TestSSHKeyClaims(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	home, keys := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	local, _ := genKey(t, filepath.Join(home, ".ssh"), "id_ed25519", "-t", "ed25519", "-N", "")
	onGitHub, onGitHubPub := genKey(t, keys, "gh", "-t", "ed25519", "-N", "")
	nowhere, _ := genKey(t, keys, "nowhere", "-t", "ed25519", "-N", "")
	withPassphrase, _ := genKey(t, keys, "pass", "-t", "ed25519", "-N", "a passphrase") // OpenSSH keeps the public half in clear
	encryptedPEM, _ := genKey(t, keys, "pem", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "a passphrase")

	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	cacheDir := filepath.Join(home, ".cache", "segurata")
	if err := statefile.WriteJSON(filepath.Join(cacheDir, "github-owners.json"), ownersCache{Login: "octocat", Orgs: []string{"acme-org"}, At: now}); err != nil {
		t.Fatal(err)
	}
	var calls []string
	gh := cli.RunnerFunc(func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch strings.Join(args, " ") {
		case "api --paginate users/octocat/keys":
			raw, _ := json.Marshal([]map[string]any{{"id": 1, "key": onGitHubPub}})
			return append(raw, []byte(`[]`)...), nil
		case "api --paginate users/old-me/keys":
			return nil, &cli.Error{Cmd: "gh", Err: errors.New("exit 1"), Stderr: "gh: Not Found (HTTP 404)"}
		}
		return nil, errors.New("unexpected gh call")
	})
	newScan := func() *scan {
		return &scan{ctx: context.Background(), home: home, now: now, emit: &recorder{}, cfg: settings{ownedOwners: []string{"acme-org", "old-me"}},
			c: &Connector{GH: gh, LookPath: func(string) (string, error) { return "/bin/true", nil }, CacheDir: defaultCacheDir}}
	}
	s := newScan()
	for _, c := range []struct{ name, body, want string }{
		{"in ~/.ssh", local, "file:~/.ssh/id_ed25519.pub"},
		{"on the owner's GitHub user", onGitHub, "github:octocat"},
		{"nowhere", nowhere, ""},
		{"passphrase, public half in clear", withPassphrase, ""},
		{"encrypted PEM", encryptedPEM, attribution.SSHKeyUnreadable},
		{"not a key", "not base64 at all", attribution.SSHKeyUnreadable},
	} {
		ev := secretrisk.Evidence{Source: "scan", Type: privateKeyType}
		s.attribute(filepath.Join(keys, "x"), &ev, c.body)
		if ev.Claims.SSHKey != c.want {
			t.Errorf("%s: %q, want %q", c.name, ev.Claims.SSHKey, c.want)
		}
		if raw, _ := json.Marshal(ev); strings.Contains(string(raw), c.body[:min(len(c.body), 40)]) {
			t.Errorf("%s: key material in the evidence", c.name)
		}
	}
	if want := []string{"api --paginate users/octocat/keys", "api --paginate users/old-me/keys"}; !slices.Equal(calls, want) {
		t.Errorf("gh calls %q, want %q (organizations are not asked)", calls, want)
	}
	ev := secretrisk.Evidence{Source: "ssh", Type: "ssh-key"}
	newScan().attribute(filepath.Join(keys, "gh"), &ev, onGitHub)
	if ev.Claims.SSHKey != "github:octocat" || len(calls) != 2 {
		t.Errorf("cached: %q after %d gh calls", ev.Claims.SSHKey, len(calls))
	}
	fileacltest.AssertPrivate(t, filepath.Join(cacheDir, "github-ssh-keys.json"))
	other := secretrisk.Evidence{Source: "scan", Type: "stripe-live"}
	if newScan().attribute("x", &other, "sk_live_x"); other.Claims.SSHKey != "" {
		t.Error("an SSH claim on a non-key")
	}
}
