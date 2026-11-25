package secretrisk

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// Evidence travels as a finding's map: Map writes it and EvidenceOf reads it back unchanged,
// liveness included, and a map without a fingerprint is not secret evidence.
func TestEvidenceRoundTripsThroughAFinding(t *testing.T) {
	ev := Evidence{Source: "scan", Kind: "config", Type: "openai-project", Redacted: "sk-proj-…a1b2(164)",
		Path: "~/.zshrc", Line: 3, Fingerprint: "0123456789abcdef", Count: 2,
		Liveness: &Liveness{State: Live, CheckedAt: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC), Provider: "openai"}}
	ev.AuthorEmail = "me@example.com"
	f := finding.Finding{Evidence: ev.Map()}
	raw, err := json.Marshal(f.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f.Evidence); err != nil { // as a run file gives it back
		t.Fatal(err)
	}
	got, ok := EvidenceOf(f)
	if !ok || !reflect.DeepEqual(got, ev) {
		t.Fatalf("EvidenceOf = %+v, %v; want %+v", got, ok, ev)
	}
	for _, bad := range []map[string]any{nil, {"path": "~/.zshrc"}, {"fingerprint": 7}} {
		if _, ok := EvidenceOf(finding.Finding{Evidence: bad}); ok {
			t.Errorf("%v read as secret evidence", bad)
		}
	}
}
