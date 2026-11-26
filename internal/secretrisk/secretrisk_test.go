package secretrisk

import (
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestPriority(t *testing.T) {
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
	if SeverityOf(P0) != finding.SevCritical || SeverityOf(P3) != finding.SevLow || SeverityOf("") != finding.SevInfo {
		t.Error("severity mapping")
	}
	if !(P0.Rank() < P1.Rank() && P3.Rank() < Priority("").Rank()) {
		t.Error("rank order")
	}
	for in, want := range map[Priority]Priority{P0: P1, P1: P2, P2: P3, P3: P3, "": ""} {
		if got := in.Lower(); got != want {
			t.Errorf("%q.Lower() = %q, want %q", in, got, want)
		}
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
	got := Reason(lookup("stripe-live"), Where("scan", "transcript", "600", false, false))
	if got != "Stripe live secret key; pasted into an agent transcript, so it reached the model provider" {
		t.Errorf("reason %q", got)
	}
}

func TestImpactTable(t *testing.T) {
	cases := map[string]Impact{
		"stripe-live": High, "aws-secret-key": High, "aws-access-key-id": Low, "gcp-service-account": High, "private-key": High,
		"github": High, "google-refresh-token": High, "google-oauth-client-secret": High, "cloudflare-token": High, "ssh-key": High,
		"anthropic": Medium, "openai-project": Medium, "xai": Medium, "openrouter": Medium, "notion": Medium,
		"slack-token": Medium, "slack-webhook": Medium, "sendgrid": Medium, "npm-token": Medium, "telegram-bot": Medium, "stripe-webhook": Medium,
		"sentry-dsn": Low, "google-api-key": Low, "stripe-test": Low, "jwt": Low,
		"assignment": Noise, "generic-api-key": Noise,
		"vault-service-token": Medium, // unknown gitleaks rule
	}
	for typ, want := range cases {
		if got := lookup(typ).Impact; got != want {
			t.Errorf("%s impact %s, want %s", typ, got, want)
		}
	}
	if u := lookup("vault-service-token"); u.Service != "vault" || !strings.Contains(u.Label, "gitleaks") {
		t.Errorf("unknown rule entry %+v", u)
	}
	if ImpactOf(Evidence{Type: "jwt", Public: true}) != Noise || ImpactOf(Evidence{Type: "private-key", Encrypted: true}) != Noise {
		t.Error("public or encrypted values must be noise")
	}
	if ImpactOf(Evidence{Type: "sourcegraph-access-token", Redacted: "…ca5(40)"}) != Noise {
		t.Error("a bare 40-hex match is a hash more often than a token")
	}
	if ImpactOf(Evidence{Type: "sourcegraph-access-token", Redacted: "sgp_…ab12(49)"}) == Noise {
		t.Error("a prefixed Sourcegraph token is a real secret")
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

func TestAWSKeyIDsAreLowImpact(t *testing.T) {
	temp := Evidence{Type: "aws-access-key-id", Redacted: "ASIA…(20)"}
	long := Evidence{Type: "aws-access-key-id", Redacted: "AKIA…(20)"}
	secret := Evidence{Type: "aws-secret-key", Redacted: "…(40)"}
	if ImpactOf(temp) != Low || ImpactOf(long) != Low || ImpactOf(secret) != High {
		t.Fatalf("key ids (ASIA expires, AKIA signs nothing alone) low, the secret key high: %v %v %v", ImpactOf(temp), ImpactOf(long), ImpactOf(secret))
	}
	if !strings.HasPrefix(TypeFor(temp.Type, temp.Redacted).Label, "Temporary AWS credential") ||
		TypeFor(long.Type, long.Redacted).Label != "AWS access key id (signs nothing without its secret key)" {
		t.Fatal("each says why it is low")
	}
	if PriorityOf(ImpactOf(long), Remote) != P2 || PriorityOf(ImpactOf(secret), Remote) != P0 {
		t.Fatal("a pushed key id is P2, a pushed secret key P0")
	}
}

func TestGuidesAreShortCitedAndInTheCatalog(t *testing.T) {
	for typ, g := range guides {
		if _, ok := Known(typ); !ok {
			t.Errorf("guide for %q, which is not in the catalog", typ)
		}
		if !strings.HasPrefix(g.Doc, "https://") {
			t.Errorf("%s: guide cites no documentation", typ)
		}
		if len(g.Steps) < 2 || len(g.Steps) > 4 {
			t.Errorf("%s: %d steps, want 2 to 4", typ, len(g.Steps))
		}
		for _, s := range g.Steps {
			if len(s) > 110 {
				t.Errorf("%s: step too long: %q", typ, s)
			}
		}
	}
	for _, typ := range []string{"stripe-live", "aws-access-key-id", "gcp-service-account", "github-pat", "google-refresh-token",
		"google-oauth-client-secret", "cloudflare-token", "anthropic", "openai-project", "xai", "openrouter", "notion",
		"slack-token", "slack-webhook", "sendgrid", "npm-token", "telegram-bot", "sentry-token"} {
		if _, ok := GuideFor(typ); !ok {
			t.Errorf("no guide for %s", typ)
		}
	}
}

func TestIsShellRC(t *testing.T) {
	for p, want := range map[string]bool{"~/.zshrc": true, "/Users/x/.bash_profile": true, ".profile": true,
		"~/src/app/.env": false, "~/.zshrc.bak": false, "~/dotfiles/zshrc": false} {
		if IsShellRC(p) != want {
			t.Errorf("IsShellRC(%q) != %v", p, want)
		}
	}
}

func TestUpstreamOnly(t *testing.T) {
	key := Evidence{Type: "aws-access-key-id", Redacted: "AKIA…(20)", Source: "gitleaks", Kind: "repo", Path: "~/src/lms/app.py", Tracked: true, Remote: true}
	for _, c := range []struct {
		origin string
		reused bool
		typ    string
		want   bool
	}{
		{OriginThirdParty, false, "aws-access-key-id", true},
		{OriginForkUpstream, false, "aws-access-key-id", true},
		{OriginThirdParty, true, "aws-access-key-id", false}, // already the owner's
		{OriginOwned, false, "aws-access-key-id", false},
		{OriginThirdParty, false, "generic-api-key", false}, // noise wherever it is
	} {
		e := key
		e.Origin, e.Reused, e.Type = c.origin, c.reused, c.typ
		if got := UpstreamOnly(e); got != c.want {
			t.Errorf("UpstreamOnly(%s, reused %v, %s) = %v", c.origin, c.reused, c.typ, got)
		}
	}
}

func TestLivenessTrusted(t *testing.T) {
	for _, c := range []struct {
		l    Liveness
		want bool
	}{
		{Liveness{State: Dead}, false}, // rules 1: may be a bare 401
		{Liveness{State: Dead, Rules: LivenessRules}, true},
		{Liveness{State: Dead, ByOwner: true}, true},
		{Liveness{State: Live}, true},
		{Liveness{State: Unknown}, true},
	} {
		if got := c.l.Trusted(); got != c.want {
			t.Errorf("%+v: %v", c.l, got)
		}
	}
}
