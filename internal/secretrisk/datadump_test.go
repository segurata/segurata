package secretrisk

import "testing"

func TestMatchesInsideADumpAreNoiseUnlessRecognisable(t *testing.T) {
	cases := []struct {
		typ, redacted string
		want          Impact
	}{
		{"sourcegraph-access-token", "…(40)", Noise},
		{"generic-api-key", "…(32)", Noise},
		{"jwt", "eyJ…(220)", Noise},
		{"anthropic", "sk-ant-…abcd(108)", Noise},
		{"aws-access-key-id", "AKIA…(20)", Low}, // recognisable: keeps its own (low) impact
		{"stripe-live", "sk_live_…a1b2(107)", High},
		{"github", "ghp_…a1b2(40)", High},
		{"private-key", "PEM", High},
	}
	for _, c := range cases {
		in := Evidence{Type: c.typ, Redacted: c.redacted, InDataDump: true}
		if got := ImpactOf(in); got != c.want {
			t.Errorf("%s in a dump: %s, want %s", c.typ, got, c.want)
		}
		in.InDataDump = false
		if c.want == Noise && c.typ == "anthropic" && ImpactOf(in) != Medium {
			t.Errorf("outside a dump %s keeps its impact", c.typ)
		}
	}
}

func TestHumanSize(t *testing.T) {
	if HumanSize(3*1024+512) != "3.5 KB" || HumanSize(900) != "900 B" || HumanSize(1536<<20) != "1.5 GB" {
		t.Error("HumanSize")
	}
}
