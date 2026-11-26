package connector_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// A finding or status that carries a secret the core handed the connector is dropped and fails the
// run; scopes, logs, errors and doctor checks pass with the value redacted. A value too short to
// tell from ordinary text is left alone.
func TestScrubEmitterDropsRecordsThatCarryASecret(t *testing.T) {
	const value = "sk-synthetic-scrub-0123456789"
	secrets := map[string]string{"K": value, "SHORT": "abc"}
	var rec recorder
	var scopes []string
	e := connector.NewScrubEmitter(scopeRecorder{&rec, &scopes}, secrets)
	e.Finding(finding.Finding{Title: "clean abc"})
	e.Finding(finding.Finding{Title: "clean", Evidence: map[string]any{"k": value}})
	e.Status(finding.Status{Account: "a", State: finding.StateOK})
	e.Status(finding.Status{Account: "b", Detail: "bad " + value})
	e.Scope("repo:"+value, false, "saw "+value)
	e.Log("using " + value)
	if len(rec.findings) != 1 || rec.findings[0].Title != "clean abc" || len(rec.statuses) != 1 || rec.statuses[0].Account != "a" {
		t.Fatalf("findings %+v, statuses %+v", rec.findings, rec.statuses)
	}
	if strings.Join(scopes, "|") != "repo:…6789(29) saw …6789(29)" || rec.logs[0] != "using …6789(29)" {
		t.Errorf("scopes %q, logs %q", scopes, rec.logs)
	}
	err := e.Err(errors.New("failed with " + value))
	if err == nil || strings.Contains(err.Error(), value) || !strings.Contains(err.Error(), "2 records carried a secret") {
		t.Errorf("Err = %v", err)
	}
	if clean := connector.NewScrubEmitter(&recorder{}, secrets); clean.Err(nil) != nil {
		t.Error("a clean run failed")
	}

	checks := []connector.Check{{What: "token " + value, Detail: "rejected " + value, Fix: "rotate " + value}}
	connector.ScrubChecks(checks, secrets)
	if c := checks[0]; strings.Contains(c.What+c.Detail+c.Fix, value) {
		t.Errorf("doctor check kept the secret: %+v", c)
	}
}

type scopeRecorder struct {
	*recorder
	scopes *[]string
}

func (s scopeRecorder) Scope(id string, _ bool, reason string) {
	*s.scopes = append(*s.scopes, id+" "+reason)
}

func TestPlanAndDescriptionHelpers(t *testing.T) {
	p := connector.Plan{Commands: []connector.Step{{Argv: []string{"true"}}, {Argv: []string{"login"}, Terminal: true}}}
	if p.NeedsSudo() || !p.NeedsTerminal() {
		t.Errorf("plan %+v", p)
	}
	if p.Commands[0].Sudo = true; !p.NeedsSudo() {
		t.Error("a sudo step was missed")
	}
	if got := (connector.Call{Method: "DELETE", URL: "https://api.example.com/keys/1", Secret: "ADMIN_WRITE_KEY"}).String(); got != "DELETE https://api.example.com/keys/1 (with ADMIN_WRITE_KEY)" {
		t.Errorf("call %q", got)
	}
	want := "chmod 600 '/tmp/a b' (now 644)"
	if runtime.GOOS == "windows" {
		want = "make '/tmp/a b' private: protected access list, full control for you and SYSTEM only (now readable by other accounts)"
	}
	if got := (connector.FileChange{Path: "/tmp/a b", Mode: 0o600, Was: 0o644}).String(); got != want {
		t.Errorf("file change %q", got)
	}
	for timeout, want := range map[string]string{"6h": "6h0m0s", "": "0s", "-1h": "0s", "soon": "0s"} {
		if got := (connector.Description{Timeout: timeout}).RunTimeout().String(); got != want {
			t.Errorf("RunTimeout(%q) = %s", timeout, got)
		}
	}
	if !(connector.Description{Needs: []string{"cli:gh", "cdp"}}).NeedsCDP() || (connector.Description{Needs: []string{"cdpx"}}).NeedsCDP() {
		t.Error("NeedsCDP")
	}
}
