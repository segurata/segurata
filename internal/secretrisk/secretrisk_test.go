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

// fakeValue is an obviously fake, high-entropy value generated at run time.
func fakeValue(prefix string, n int) string {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
	b := []byte(prefix)
	for i := 0; i < n; i++ {
		b = append(b, alphabet[(i*7+len(prefix)*3+i*i)%len(alphabet)])
	}
	return string(b)
}

func TestRedactShowsOnlyPrefixTailAndLength(t *testing.T) {
	key := fakeValue("sk_live_", 40)
	got := Redact("stripe-live", "sk_live_|rk_live_", key)
	if want := "sk_live_…" + key[len(key)-4:] + "(48)"; got != want {
		t.Errorf("redact %q, want %q", got, want)
	}
	if got := Redact("url-credentials", "", fakeValue("", 30)); got != "…(30)" {
		t.Errorf("password-like hint %q", got)
	}
	if got := Redact("telegram-bot", "", fakeValue("", 12)); got != "…(12)" {
		t.Errorf("short value hint %q", got)
	}
}

func TestParseHintReadsWhatRedactWrote(t *testing.T) {
	key := fakeValue("sk_live_", 40)
	h, ok := ParseHint(Redact("stripe-live", "sk_live_", key))
	if !ok || h.Prefix != "sk_live_" || h.Tail != key[len(key)-4:] || h.Len != 48 {
		t.Fatalf("hint %+v ok=%v", h, ok)
	}
	if !h.Fits(key) || h.Fits(key[:47]) || h.Fits("rk"+key[2:]) {
		t.Error("Fits accepts the wrong values")
	}
	if h, ok := ParseHint("…(30)"); !ok || h.Prefix != "" || h.Tail != "" || h.Len != 30 {
		t.Errorf("length-only hint %+v ok=%v", h, ok)
	}
	for _, bad := range []string{"", "PEM", "…", "sk_…(x)", "sk_live_…abcd(3)"} {
		if _, ok := ParseHint(bad); ok {
			t.Errorf("ParseHint(%q) accepted", bad)
		}
	}
}

// Every connector writes its key hints in Redact's format, whatever the provider shows: what is
// known in front, at most the last four characters, and the length or "(?)" when it is not given.
func TestProviderHintsShareRedactsFormat(t *testing.T) {
	stars := func(n int) string { return strings.Repeat("*", n) }
	for _, c := range []struct {
		name, masked string
		n            int
		want         string
	}{
		{"openrouter label", "sk-or-v1-27e...d4d", 0, "sk-or-v1-27e…d4d(?)"},
		{"anthropic partial_key_hint", "sk-ant-api03-R2D...igAA", 0, "sk-ant-api03-R2D…igAA(?)"},
		// OpenAI masks one star per hidden character, so its length is the value's.
		{"openai redacted_value", "sk-proj-" + stars(152) + "j_MA", 164, "sk-proj-…j_MA(164)"},
		{"a longer tail keeps its last four", "ab...123456", 0, "ab…3456(?)"},
		{"ellipsis", "sk-…wxyz", 0, "sk-…wxyz(?)"},
		{"a length shorter than what is shown is dropped", "sk-or-v1-27e...d4d", 5, "sk-or-v1-27e…d4d(?)"},
		{"nothing masked", "plain", 0, ""},
		{"only a mask", "***", 0, ""},
	} {
		if got := Masked(c.masked, c.n); got != c.want {
			t.Errorf("%s: Masked(%q, %d) = %q, want %q", c.name, c.masked, c.n, got, c.want)
		}
	}
	if got := RedactID("AKIA|ASIA", "AKIAEXAMPLEEXAMPWXYZ"); got != "AKIA…WXYZ(20)" {
		t.Errorf("RedactID = %q", got)
	}
	if got := RedactID("", "abc"); got != "…(3)" {
		t.Errorf("short id = %q", got)
	}
	if got := (Hint{Prefix: "nR4"}).String(); got != "nR4…(?)" {
		t.Errorf("prefix-only hint %q", got)
	}
}

func TestParseHintReadsAnUnknownLength(t *testing.T) {
	h, ok := ParseHint("sk-or-v1-27e…d4d(?)")
	if !ok || h.Prefix != "sk-or-v1-27e" || h.Tail != "d4d" || h.Len != 0 {
		t.Fatalf("hint %+v ok=%v", h, ok)
	}
	if h.Fits("sk-or-v1-27e" + strings.Repeat("0", 58) + "d4d") {
		t.Error("a hint without a length fits a value")
	}
	if _, ok := ParseHint("…(?)"); ok {
		t.Error("a hint that shows nothing and no length was accepted")
	}
	local, _ := ParseHint("sk-or-v1-…fd4d(73)")
	if !local.Agrees(h) || !h.Agrees(local) {
		t.Error("an unknown length disagrees")
	}
	other, _ := ParseHint("sk-or-v1-…0000(73)")
	short, _ := ParseHint("sk-or-v1-…fd4d(72)")
	if other.Agrees(h) || short.Agrees(local) {
		t.Error("another tail or length agrees")
	}
}

// ReadHint reads Redact's format and the providers' raw masked forms that findings written before
// every connector used Redact's format still carry.
func TestReadHint(t *testing.T) {
	for in, want := range map[string]Hint{
		"AKIA…(20)":               {Prefix: "AKIA", Len: 20},
		"sk-or-v1-27e...d4d":      {Prefix: "sk-or-v1-27e", Tail: "d4d"},
		"sk-or-v1-27e…d4d(?)":     {Prefix: "sk-or-v1-27e", Tail: "d4d"},
		"sk-proj-********xxkA":    {Prefix: "sk-proj-", Tail: "xxkA"},
		"sk-ant-api03-R2D...igAA": {Prefix: "sk-ant-api03-R2D", Tail: "igAA"},
		"sk-or-v1-…fd4d(73)":      {Prefix: "sk-or-v1-", Tail: "fd4d", Len: 73},
		"sk-proj-****…****j_MA":   {Prefix: "sk-proj-", Tail: "j_MA"},
	} {
		if got, ok := ReadHint(in); !ok || got != want {
			t.Errorf("ReadHint(%q) = %+v %v, want %+v", in, got, ok, want)
		}
	}
	if _, ok := ReadHint("PEM"); ok {
		t.Error("PEM is not a hint of one value")
	}
	if !(Hint{Prefix: "AKIA", Len: 20}).Agrees(Hint{Prefix: "AKIARB", Len: 20}) ||
		(Hint{Prefix: "AKIA", Len: 20}).Agrees(Hint{Tail: "NCZX", Len: 40}) {
		t.Error("Agrees")
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

func TestHexLookalikesAreNoiseUnlessPrefixed(t *testing.T) {
	if ImpactOf(Evidence{Type: "sourcegraph-access-token", Redacted: "…ca5(40)"}) != Noise {
		t.Fatal("a bare 40-hex match is a hash more often than a token")
	}
	if ImpactOf(Evidence{Type: "sourcegraph-access-token", Redacted: "sgp_…ab12(49)"}) == Noise {
		t.Fatal("a prefixed Sourcegraph token is a real secret")
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

func TestPriorityLower(t *testing.T) {
	for in, want := range map[Priority]Priority{P0: P1, P1: P2, P2: P3, P3: P3, "": ""} {
		if got := in.Lower(); got != want {
			t.Errorf("%q.Lower() = %q, want %q", in, got, want)
		}
	}
}
