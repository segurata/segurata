package tracker

import (
	"strings"
	"testing"
	"time"

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

// A check that a project's profile lowered in most projects but not in one: the item keeps the
// worst project's priority (that project needs the fix), and the title says how the projects split
// by severity, so "fails in 3 projects" at P2 does not read as three projects of P2 work.
func TestAGroupAcrossScopesShowsItsSeveritySplit(t *testing.T) {
	out := t.TempDir()
	mk := func(project string, sev finding.Severity) finding.Finding {
		f := fnd("prowler", "", "me@x.com", "prowler_check", "logging_sink_created:"+project, project, sev, "No log sink in "+project, t0)
		f.Scope = project
		f.Evidence = map[string]any{"check_id": "logging_sink_created", "check_title": "Log sink created", "project": project}
		return f
	}
	writeRun(t, out, t0, "prowler.jsonl", mk("prod", finding.SevMedium), mk("idle1", finding.SevLow), mk("idle2", finding.SevLow),
		mk("empty", finding.SevInfo), okStatus("prowler", "me@x.com"))
	tr := New(t0)
	syncOrDie(t, tr, out, t0.Add(time.Hour))
	it := byTitle(t, tr, "Log sink created fails in 3 projects")
	if !strings.HasSuffix(it.Title, "(1 medium, 2 low)") || it.Priority != "P2" {
		t.Errorf("%q %s", it.Title, it.Priority)
	}
	// One severity across the group: no split.
	writeRun(t, out, t0.Add(24*time.Hour), "prowler.jsonl", mk("prod", finding.SevLow), mk("idle1", finding.SevLow), okStatus("prowler", "me@x.com"))
	syncOrDie(t, tr, out, t0.Add(25*time.Hour))
	if strings.Contains(it.Title, "low)") {
		t.Errorf("split shown for one severity: %q", it.Title)
	}
}
