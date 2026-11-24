package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

func TestExpectedRulesMatchStateAccountAndDetail(t *testing.T) {
	st := finding.Status{Connector: "google-personal", Account: "colleague@example.com", State: finding.StateReauth, Detail: "Google asks to verify it's you"}
	cases := []struct {
		rule Expected
		want bool
	}{
		{Expected{Reason: "r"}, true},
		{Expected{State: finding.StateReauth, Reason: "r"}, true},
		{Expected{State: finding.StateSignedOut, Reason: "r"}, false},
		{Expected{Account: "*@example.com", Reason: "r"}, true},
		{Expected{Account: "david@*", Reason: "r"}, false},
		{Expected{Detail: "verify it's you", Reason: "r"}, true},
		{Expected{Detail: "/^Google asks .* you$/", Reason: "r"}, true},
		{Expected{Detail: "/^verify/", Reason: "r"}, false},
	}
	for _, c := range cases {
		if got := c.rule.Matches(st, st.State); got != c.want {
			t.Errorf("%+v: %v", c.rule, got)
		}
	}
}

func TestExpectFollowsTodaysConfig(t *testing.T) {
	cfg := Config{Connectors: map[string]ConnectorConfig{
		"anthropic:personal": {Expected: []Expected{{State: finding.StateMissingCredentials, Reason: "ephemeral key on purpose"}}},
	}}
	st := finding.Status{Connector: "anthropic", Instance: "personal", State: finding.StateMissingCredentials, Detail: "x"}
	cfg.Expect(&st)
	if st.State != finding.StateExpected || st.Was != finding.StateMissingCredentials || st.Expected != "ephemeral key on purpose" {
		t.Fatalf("%+v", st)
	}
	cfg.Expect(&st) // idempotent
	if st.State != finding.StateExpected || st.Was != finding.StateMissingCredentials {
		t.Fatalf("second pass %+v", st)
	}
	other := finding.Status{Connector: "anthropic", State: finding.StateMissingCredentials}
	if cfg.Expect(&other); other.State != finding.StateMissingCredentials {
		t.Errorf("a rule of anthropic:personal matched the unnamed instance: %+v", other)
	}
	// The rule is gone: a status read back from a run gets its own state again.
	(Config{}).Expect(&st)
	if st.State != finding.StateMissingCredentials || st.Was != "" || st.Expected != "" {
		t.Errorf("undo %+v", st)
	}
	ok := finding.Status{Connector: "anthropic", Instance: "personal", State: finding.StateOK}
	if cfg.Expect(&ok); ok.State != finding.StateOK {
		t.Error("ok became expected")
	}
}

func TestLoadRejectsABadExpectedRule(t *testing.T) {
	for name, body := range map[string]string{
		"no reason":   `{"connectors": {"aws": {"expected": [{"state": "error"}]}}}`,
		"bad regexp":  `{"connectors": {"aws": {"expected": [{"detail": "/(/", "reason": "r"}]}}}`,
		"bad glob":    `{"connectors": {"aws": {"expected": [{"account": "[", "reason": "r"}]}}}`,
		"ok expected": `{"connectors": {"aws": {"expected": [{"state": "ok", "reason": "r"}]}}}`,
		// A write credential under secrets would be resolved by every inventory.
		"write key as an inventory secret": `{"connectors": {"openai": {"secrets": {"OPENAI_ADMIN_WRITE_KEY": "env:X"}}}}`,
	} {
		p := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestAddExpectedKeepsTheFileInOrder(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	orig := `{"cdp_url": "http://127.0.0.1:9222",
 "connectors": {"openai": {"secrets": {"OPENAI_ADMIN_KEY": "keychain:segurata-openai-admin"}},
   "anthropic:personal": {"secrets": {"ANTHROPIC_ADMIN_KEY": "env:ANTHROPIC_ADMIN_KEY"}, "config": {"b": 1, "a": 2}}}}`
	if err := os.WriteFile(p, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	rule := Expected{State: finding.StateMissingCredentials, Reason: "ephemeral key on purpose"}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	changed, backup, err := AddExpected(p, "anthropic:personal", rule, now)
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if b, _ := os.ReadFile(backup); string(b) != orig {
		t.Error("backup is not the previous config")
	}
	got, _ := os.ReadFile(p)
	want := `{
  "cdp_url": "http://127.0.0.1:9222",
  "connectors": {
    "openai": {
      "secrets": {
        "OPENAI_ADMIN_KEY": "keychain:segurata-openai-admin"
      }
    },
    "anthropic:personal": {
      "secrets": {
        "ANTHROPIC_ADMIN_KEY": "env:ANTHROPIC_ADMIN_KEY"
      },
      "config": {
        "b": 1,
        "a": 2
      },
      "expected": [
        {
          "state": "missing_credentials",
          "reason": "ephemeral key on purpose"
        }
      ]
    }
  }
}
`
	if string(got) != want {
		t.Errorf("config:\n%s", got)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	cfg, err := Load(p)
	if err != nil || len(cfg.Instances("anthropic")[0].Expected) != 1 {
		t.Fatalf("%v %+v", err, cfg)
	}
	if changed, _, err := AddExpected(p, "anthropic:personal", rule, now.Add(time.Second)); changed || err != nil {
		t.Errorf("the same rule twice: %v %v", changed, err)
	}
	// A new instance key and a missing file.
	fresh := filepath.Join(dir, "new", "config.json")
	if _, _, err := AddExpected(fresh, "aws", Expected{State: finding.StateError, Detail: "AccessDenied", Reason: "limited IAM user"}, now); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(fresh); !strings.Contains(string(b), `"aws": {`) {
		t.Errorf("new file:\n%s", b)
	}
	if _, _, err := AddExpected(p, "aws", Expected{State: finding.StateError}, now); err == nil {
		t.Error("a rule without a reason was written")
	}
}
