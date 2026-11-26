package secretrisk

import (
	"strings"
	"testing"
)

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
