package tracker

import (
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

// The same Prowler check failing in several projects is one item listing them.
func TestProwlerFailuresGroupPerCheckAcrossProjects(t *testing.T) {
	mk := func(check, project string) finding.Finding {
		return finding.Finding{ID: check + project, Connector: "prowler", Account: "me@x.com", Scope: project, Kind: finding.KindSetting,
			Severity: finding.SevMedium, Title: "No metric filter in " + project,
			Resource: finding.Resource{Type: "prowler_check", ID: check + ":" + project},
			Evidence: map[string]any{"check_id": check, "check_title": "Log metric filter for audit changes", "project": project}}
	}
	var r *rule
	for i := range rules {
		if rules[i].connectors != nil && rules[i].connectors[0] == "prowler" {
			r = &rules[i]
		}
	}
	if r == nil {
		t.Fatal("no prowler rule")
	}
	k1, _ := groupKey(mk("logging_metric_audit", "p1"), r)
	k2, _ := groupKey(mk("logging_metric_audit", "p2"), r)
	k3, _ := groupKey(mk("iam_other_check", "p1"), r)
	if k1 != k2 || k1 == k3 {
		t.Fatalf("keys: %q %q %q", k1, k2, k3)
	}
	_, p := groupKey(mk("logging_metric_audit", "p1"), r)
	p.add(mk("logging_metric_audit", "p1"))
	p.add(mk("logging_metric_audit", "p2"))
	if got := prowlerCheckTitle(&p); !strings.Contains(got, "fails in 2 projects") || !strings.Contains(got, "Log metric filter") {
		t.Fatalf("title %q", got)
	}
}
