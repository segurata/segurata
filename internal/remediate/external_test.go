package remediate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/finding"
)

var pluginFinding = finding.Finding{ID: "f1", Connector: "demo", Account: "me", Severity: finding.SevHigh, Title: "Token never expires",
	Remediation: finding.Remediation{Action: "demo.token.revoke", Automatable: true}}

const goodPlan = `{"action":"demo.token.revoke","summary":"Revoke the token.","commands":[{"argv":["demo-cli","tokens","revoke","t1"]}],"side_effects":["Scripts using the token stop working."]}`

// demoPlugin answers plan with the given replies in turn (the last one repeats) and records each
// apply's stdin in the returned file.
func demoPlugin(t *testing.T, replies ...string) (*connector.External, string) {
	t.Helper()
	dir := t.TempDir()
	for i, r := range replies {
		if err := os.WriteFile(filepath.Join(dir, "plan"+string(rune('0'+i))), []byte(r+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	applied := filepath.Join(dir, "applied")
	e := connectortest.Plugin(t, "demo", `d='`+dir+`'
case "$1" in
describe) echo '{"name":"demo","protocol":2,"remediates":["demo.token.revoke"]}';;
plan)
  cat >/dev/null
  n=$(cat "$d/n" 2>/dev/null || echo 0)
  f="$d/plan$n"; [ -f "$f" ] || f=$(ls "$d"/plan* | tail -1)
  cat "$f"; echo $((n+1)) > "$d/n";;
apply) cat > '`+applied+`'; echo '{"type":"log","msg":"revoked t1"}';;
esac
`)
	return e, applied
}

func TestExternalRemediationShowsConfirmsAndApplies(t *testing.T) {
	e, applied := demoPlugin(t, goodPlan)
	r, err := For(pluginFinding, []connector.Connector{e}, func(finding.Finding) (connector.Credentials, error) {
		return connector.Credentials{Request: connector.Request{Secrets: map[string]string{"DEMO_TOKEN": "s3cret"}}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	io := quietIO()
	if err := Execute(context.Background(), pluginFinding, r, Options{IO: io, TTY: true}, neverReinventory(t)); err != nil {
		t.Fatal(err)
	}
	if out := io.Out.(*bytes.Buffer).String(); !strings.Contains(out, "demo-cli tokens revoke t1") || !strings.Contains(out, "Dry run") {
		t.Fatalf("plan not shown:\n%s", out)
	}
	if _, err := os.Stat(applied); err == nil {
		t.Fatal("dry run applied")
	}
	io = quietIO()
	io.In = strings.NewReader("n\n")
	if err := Execute(context.Background(), pluginFinding, r, Options{Apply: true, TTY: true, IO: io}, neverReinventory(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(applied); err == nil {
		t.Fatal("applied without a yes")
	}
	io = quietIO()
	io.In = strings.NewReader("y\n")
	if err := Execute(context.Background(), pluginFinding, r, Options{Apply: true, TTY: true, IO: io}, results("other")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(applied)
	if err != nil {
		t.Fatal("apply never ran")
	}
	if !strings.Contains(string(raw), `"summary":"Revoke the token."`) || !strings.Contains(string(raw), `"DEMO_TOKEN":"s3cret"`) {
		t.Fatalf("apply did not get the plan and secrets: %s", raw)
	}
	if out := io.Out.(*bytes.Buffer).String(); !strings.Contains(out, "demo: revoked t1") || !strings.Contains(out, "Fixed") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestExternalApplyRefusesAPlanThatChangedSinceShown(t *testing.T) {
	changed := strings.Replace(goodPlan, "t1", "t2", 1)
	e, applied := demoPlugin(t, goodPlan, changed)
	r := external{conn: e}
	err := Execute(context.Background(), pluginFinding, r, Options{Apply: true, Yes: true, IO: quietIO()}, neverReinventory(t))
	if err == nil || !strings.Contains(err.Error(), "plan changed") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, err := os.Stat(applied); err == nil {
		t.Fatal("applied a plan nobody saw")
	}
}

func TestExternalPlansAreVetted(t *testing.T) {
	refused := []struct{ why, reply, err string }{
		{"sudo step", `{"action":"demo.token.revoke","summary":"x","commands":[{"argv":["/bin/rm","x"],"sudo":true}]}`, errPluginSudo.Error()},
		{"needs_sudo", `{"action":"demo.token.revoke","summary":"x","needs_sudo":true}`, errPluginSudo.Error()},
		{"other action", `{"action":"demo.other","summary":"x"}`, `planned action "demo.other"`},
		{"no summary", `{"action":"demo.token.revoke","summary":" "}`, "without a summary"},
		{"empty command", `{"action":"demo.token.revoke","summary":"x","commands":[{"argv":[]}]}`, "empty command"},
		{"empty undo argv", `{"action":"demo.token.revoke","summary":"x","undo":[{"argv":[""]}]}`, "empty command"},
	}
	replies := make([]string, len(refused))
	for i, c := range refused {
		replies[i] = c.reply
	}
	e, _ := demoPlugin(t, replies...) // answers each plan with the next reply
	for _, c := range refused {
		_, err := (external{conn: e}).Plan(context.Background(), pluginFinding)
		if err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: want %q, got %v", c.why, c.err, err)
		}
		if c.err == errPluginSudo.Error() && !errors.Is(err, errPluginSudo) {
			t.Errorf("%s: want errPluginSudo wrapped, got %v", c.why, err)
		}
	}
}

func TestForExternalNeedsADeclaredAction(t *testing.T) {
	e, _ := demoPlugin(t, goodPlan)
	req := func(finding.Finding) (connector.Credentials, error) { return connector.Credentials{}, nil }
	undeclared := pluginFinding
	undeclared.Remediation.Action = "demo.other"
	if _, err := For(undeclared, []connector.Connector{e}, req); err == nil || !strings.Contains(err.Error(), "remediates") {
		t.Fatalf("undeclared action: %v", err)
	}
	if _, err := For(pluginFinding, []connector.Connector{e}, func(finding.Finding) (connector.Credentials, error) {
		return connector.Credentials{}, errors.New("secret missing")
	}); err == nil || !strings.Contains(err.Error(), "secret missing") {
		t.Fatalf("a request that cannot be built must stop the remediation: %v", err)
	}
	v1 := connectortest.Plugin(t, "demo", `case "$1" in describe) echo '{"name":"demo","protocol":1}';; esac
`)
	if _, err := For(pluginFinding, []connector.Connector{v1}, req); err == nil || !strings.Contains(err.Error(), "remediates") {
		t.Fatalf("a protocol 1 connector declares no remediation: %v", err)
	}
}
