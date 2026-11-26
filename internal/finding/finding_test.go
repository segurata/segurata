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
	f := Finding{Connector: "c", Account: "a", Resource: Resource{Type: "t", ID: "1"}, Remediation: Remediation{Summary: "by hand", Automatable: true}}
	f.Fill(now)
	if f.Type != "finding" || f.ID != StableID("c", "a", "t", "1") || !f.ObservedAt.Equal(now) || f.ObservedAt.Location() != time.UTC {
		t.Fatalf("unexpected fill: %+v", f)
	}
	labelled := Finding{Connector: "c", Instance: "work", Account: "a", Resource: Resource{Type: "t", ID: "1"}}
	labelled.Fill(now)
	if labelled.ID != StableID("work", "c", "a", "t", "1") {
		t.Fatal("an instance's findings must not share ids with the unnamed instance's")
	}
	custom := Finding{ID: "custom", Remediation: Remediation{Action: "macos.firewall.enable"}}
	custom.Fill(now)
	if custom.ID != "custom" {
		t.Fatal("Fill overwrote an explicit id")
	}
	if f.Remediation.Automatable || !custom.Remediation.Automatable {
		t.Fatal("automatable must be true iff an action is set")
	}
}

func TestSeverityRankPickAndValid(t *testing.T) {
	order := []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical}
	var picked string
	for i, s := range order {
		if i > 0 && s.Rank() <= order[i-1].Rank() {
			t.Fatalf("%s should outrank %s", s, order[i-1])
		}
		if !s.Valid() {
			t.Errorf("%s is not valid", s)
		}
		picked += s.Pick("h", "m", "l")
	}
	if picked != "llmhh" {
		t.Fatalf("Pick: %q", picked)
	}
	for _, bogus := range []Severity{"bogus", "High", ""} {
		if bogus.Rank() != 0 || bogus.Valid() {
			t.Errorf("%q must rank lowest and be invalid", bogus)
		}
	}
}

// Label spells a connector instance as the command line and the config do.
func TestLabel(t *testing.T) {
	if Label("aws", "") != "aws" || Label("openrouter", "work") != "openrouter:work" {
		t.Errorf("%q %q", Label("aws", ""), Label("openrouter", "work"))
	}
	if f := (Finding{Connector: "openrouter", Instance: "work"}); f.Selector() != "openrouter:work" {
		t.Errorf("selector %q", f.Selector())
	}
}
