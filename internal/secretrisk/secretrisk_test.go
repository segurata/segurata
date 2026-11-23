package secretrisk

import (
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestPriorityMatrix(t *testing.T) {
	cases := []struct {
		i    Impact
		e    Exposure
		want Priority
	}{
		{High, Remote, P0}, {High, Shared, P1}, {High, Local, P2},
		{Medium, Remote, P1}, {Medium, Shared, P2}, {Medium, Local, P3},
		{Low, Remote, P2}, {Low, Shared, P3}, {Low, Local, P3},
		{Noise, Remote, ""}, {Noise, Local, ""},
	}
	for _, c := range cases {
		if got := PriorityOf(c.i, c.e); got != c.want {
			t.Errorf("%s × %d = %q, want %q", c.i, c.e, got, c.want)
		}
	}
}

func TestSeverityAndRank(t *testing.T) {
	if SeverityOf(P0) != finding.SevCritical || SeverityOf(P3) != finding.SevLow || SeverityOf("") != finding.SevInfo {
		t.Error("severity mapping")
	}
	if !(P0.Rank() < P1.Rank() && P3.Rank() < Priority("").Rank()) {
		t.Error("rank order")
	}
}

func TestWhere(t *testing.T) {
	cases := []struct {
		source, kind, mode string
		tracked, remote    bool
		level              Exposure
		label              string
	}{
		{"gitleaks", "repo", "", true, true, Remote, "git+remote"},
		{"scan", "transcript", "600", false, false, Remote, "transcript"},
		{"gitleaks", "repo", "", true, false, Shared, "git"},
		{"scan", "config", "644", false, false, Shared, "readable"},
		{"scan", "config", "640", false, false, Shared, "readable"},
		{"scan", "history", "600", false, false, Local, "history"},
		{"scan", "log", "600", false, false, Local, "log"},
		{"scan", "repo", "600", false, false, Local, "local"},
	}
	for _, c := range cases {
		s := Where(c.source, c.kind, c.mode, c.tracked, c.remote)
		if s.Level != c.level || s.Label != c.label || s.Phrase == "" {
			t.Errorf("%+v: got %+v", c, s)
		}
	}
}

func TestImpactTable(t *testing.T) {
	cases := map[string]Impact{
		"stripe-live": High, "aws-access-key-id": High, "gcp-service-account": High, "private-key": High,
		"github": High, "google-refresh-token": High, "google-oauth-client-secret": High, "cloudflare-token": High, "ssh-key": High,
		"anthropic": Medium, "openai-project": Medium, "xai": Medium, "openrouter": Medium, "notion": Medium,
		"slack-token": Medium, "slack-webhook": Medium, "sendgrid": Medium, "npm-token": Medium, "telegram-bot": Medium, "stripe-webhook": Medium,
		"sentry-dsn": Low, "google-api-key": Low, "stripe-test": Low, "jwt": Low,
		"assignment": Noise, "generic-api-key": Noise,
		"vault-service-token": Medium, // unknown gitleaks rule
	}
	for typ, want := range cases {
		if got := Lookup(typ).Impact; got != want {
			t.Errorf("%s impact %s, want %s", typ, got, want)
		}
	}
	if u := Lookup("vault-service-token"); u.Service != "vault" || !strings.Contains(u.Label, "gitleaks") {
		t.Errorf("unknown rule entry %+v", u)
	}
	if ImpactOf(Evidence{Type: "jwt", Public: true}) != Noise || ImpactOf(Evidence{Type: "private-key", Encrypted: true}) != Noise {
		t.Error("public or encrypted values must be noise")
	}
}

func TestEveryRotateURLIsHTTPS(t *testing.T) {
	for typ, info := range catalog {
		if info.RotateURL != "" && !strings.HasPrefix(info.RotateURL, "https://") {
			t.Errorf("%s: rotate url %q", typ, info.RotateURL)
		}
		if info.Service == "" || info.Label == "" {
			t.Errorf("%s: incomplete entry", typ)
		}
	}
}

func TestReasonInPlainWords(t *testing.T) {
	got := Reason(Lookup("stripe-live"), Where("scan", "transcript", "600", false, false))
	if got != "Stripe live secret key; pasted into an agent transcript, so it reached the model provider" {
		t.Errorf("reason %q", got)
	}
}

func TestTemporaryAWSCredentialsAreLowImpact(t *testing.T) {
	temp := Evidence{Type: "aws-access-key-id", Redacted: "ASIA…(20)"}
	long := Evidence{Type: "aws-access-key-id", Redacted: "AKIA…(20)"}
	if ImpactOf(temp) != Low || ImpactOf(long) != High {
		t.Fatalf("ASIA (STS, expires) must be low and AKIA high: %v %v", ImpactOf(temp), ImpactOf(long))
	}
	if PriorityOf(ImpactOf(temp), Remote) == PriorityOf(ImpactOf(long), Remote) {
		t.Fatal("a pushed temporary credential must rank below a pushed long-lived key")
	}
	if !strings.Contains(TypeFor(temp.Type, temp.Redacted).Label, "Temporary") {
		t.Fatal("the reason must say it is temporary")
	}
}
