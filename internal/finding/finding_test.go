package finding

import (
	"strings"
	"testing"
	"time"
)

func TestStableIDIsDeterministicAndSeparatesParts(t *testing.T) {
	a := StableID("google", "x@y", "oauth_grant", "1")
	if a != StableID("google", "x@y", "oauth_grant", "1") {
		t.Fatal("same input gave different ids")
	}
	// Without a separator "ab"+"c" and "a"+"bc" would collide.
	if StableID("ab", "c") == StableID("a", "bc") {
		t.Fatal("part boundaries are not part of the id")
	}
	if len(a) != 16 {
		t.Fatalf("id length %d, want 16", len(a))
	}
}

func TestRedactNeverReturnsTheSecret(t *testing.T) {
	for _, s := range []string{"", "short", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"} {
		r := Redact(s)
		if len(s) > 12 && strings.Contains(r, s[6:]) {
			t.Fatalf("Redact(%d chars) leaks the tail: %q", len(s), r)
		}
		if len(s) <= 12 && s != "" && strings.Contains(r, s) {
			t.Fatalf("Redact leaks a short secret: %q", r)
		}
	}
	if got := Redact("sk-ant-api03-abcdefghijklmnop"); got != "sk-ant…(29)" {
		t.Fatalf("got %q", got)
	}
}

func TestFillKeepsConnectorChoicesAndSetsDerivedFields(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.FixedZone("x", 3600))
	f := Finding{Connector: "c", Account: "a", Resource: Resource{Type: "t", ID: "1"}}
	f.Fill(now)
	if f.Type != "finding" || f.ID != StableID("c", "a", "t", "1") || !f.ObservedAt.Equal(now) || f.ObservedAt.Location() != time.UTC {
		t.Fatalf("unexpected fill: %+v", f)
	}
	g := Finding{ID: "custom"}
	g.Fill(now)
	if g.ID != "custom" {
		t.Fatal("Fill overwrote an explicit id")
	}
}

func TestSeverityRank(t *testing.T) {
	order := []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Fatalf("%s should outrank %s", order[i], order[i-1])
		}
	}
	if Severity("bogus").Rank() != 0 {
		t.Fatal("unknown severity should rank lowest")
	}
}
