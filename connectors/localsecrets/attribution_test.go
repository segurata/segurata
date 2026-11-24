package localsecrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
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
