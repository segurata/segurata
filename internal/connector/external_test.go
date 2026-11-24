package connector_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/finding"
)

func describing(js string) string { return "case \"$1\" in describe) echo '" + js + "';; esac\n" }

func TestLoadExternalChecksTheDescription(t *testing.T) {
	refused := map[string]string{
		"protocol 3":               `{"name":"x","protocol":3}`,
		"protocol 0":               `{"name":"x","protocol":0}`,
		"remediates on protocol 1": `{"name":"x","protocol":1,"remediates":["x.fix"]}`,
		"empty remediation":        `{"name":"x","protocol":2,"remediates":[""]}`,
		"no name":                  `{"protocol":2}`,
		"not json":                 `nope`,
		"another file's name":      `{"name":"openai","protocol":2}`,
	}
	for why, js := range refused {
		if _, err := connector.LoadExternal(connectortest.Script(t, "x", describing(js))); err == nil {
			t.Errorf("%s: loaded", why)
		}
	}
	for _, js := range []string{`{"name":"x","protocol":1}`, `{"name":"x","protocol":2,"remediates":["x.fix"]}`} {
		if _, err := connector.LoadExternal(connectortest.Script(t, "x", describing(js))); err != nil {
			t.Errorf("%s: %v", js, err)
		}
	}
}

// The name in describe must be the file's suffix and a plain lowercase word, since it picks the
// secrets the core hands over and names the run file.
func TestLoadExternalRefusesABadName(t *testing.T) {
	for _, name := range []string{"Upper", "under_score", "prowler.orig", "-lead"} {
		js := `{"name":"` + name + `","protocol":2}`
		if _, err := connector.LoadExternal(connectortest.Script(t, name, describing(js))); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

type builtin struct{ name string }

func (b builtin) Describe() connector.Description { return connector.Description{Name: b.name} }
func (builtin) Inventory(context.Context, connector.Request, connector.Emitter) error {
	return nil
}

// Discover keeps one connector per name: a built-in beats a plugin, an earlier PATH directory beats
// a later one, and a file whose name is not a connector name never runs.
func TestDiscoverKeepsOneConnectorPerName(t *testing.T) {
	connector.Register(builtin{"discoverbuiltin"})
	ran := filepath.Join(t.TempDir(), "ran")
	first, second := t.TempDir(), t.TempDir()
	plugin := func(dir, file, name string) {
		t.Helper()
		body := "echo " + file + " >> '" + ran + "'\n" + describing(`{"name":"`+name+`","protocol":2}`)
		if err := os.WriteFile(filepath.Join(dir, "segurata-"+file), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("shell script connector")
	}
	plugin(first, "discoverbuiltin", "discoverbuiltin")
	plugin(first, "zzz", "discoverbuiltin")
	plugin(first, "dup", "dup")
	plugin(second, "dup", "dup")
	plugin(second, "dup.orig", "dup")
	t.Setenv("PATH", first+string(os.PathListSeparator)+second)

	got := connector.Discover()
	if len(got) != 1 || got[0].Path != filepath.Join(first, "segurata-dup") || got[0].Describe().Name != "dup" {
		t.Fatalf("discovered %+v", got)
	}
	raw, _ := os.ReadFile(ran)
	if strings.Contains(string(raw), "discoverbuiltin") || strings.Contains(string(raw), "orig") {
		t.Fatalf("ran a plugin it should have skipped unseen:\n%s", raw)
	}
}

// A connector gets the protocol version it declared, never a newer one it may not know.
func TestInventorySendsTheConnectorsOwnProtocol(t *testing.T) {
	for _, v := range []string{"1", "2"} {
		e := connectortest.Plugin(t, "v", `case "$1" in
describe) echo '{"name":"v","protocol":`+v+`}';;
inventory) req=$(cat); case "$req" in *'"protocol":`+v+`'*) echo '{"type":"log","msg":"ok"}';; *) echo "got $req" >&2; exit 3;; esac;;
esac
`)
		var logs recorder
		if err := e.Inventory(context.Background(), connector.Request{Protocol: connector.ProtocolVersion}, &logs); err != nil {
			t.Fatalf("protocol %s: %v", v, err)
		}
		if len(logs.logs) != 1 || logs.logs[0] != "ok" {
			t.Fatalf("protocol %s: logs %v", v, logs.logs)
		}
	}
}

type recorder struct{ logs []string }

func (r *recorder) Finding(finding.Finding)    {}
func (r *recorder) Status(finding.Status)      {}
func (r *recorder) Scope(string, bool, string) {}
func (r *recorder) Log(m string)               { r.logs = append(r.logs, m) }

func TestRequestPlanDecodesStrictly(t *testing.T) {
	plugin := func(reply string) *connector.External {
		return connectortest.Plugin(t, "p", `case "$1" in
describe) echo '{"name":"p","protocol":2,"remediates":["p.fix"]}';;
plan) cat >/dev/null; echo '`+reply+`';;
esac
`)
	}
	f := finding.Finding{Remediation: finding.Remediation{Action: "p.fix"}}
	got, err := plugin(`{"action":"p.fix","summary":"Do it.","commands":[{"argv":["/usr/bin/true"]}],"needs_sudo":true}`).
		RequestPlan(context.Background(), connector.RemediationRequest{Finding: f})
	if err != nil || got.Action != "p.fix" || !got.SudoRequested || len(got.Commands) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, bad := range []string{`{"action":"p.fix","summary":"x","surprise":1}`, `{"action":"p.fix","summary":"x"} {}`, `not json`} {
		if _, err := plugin(bad).RequestPlan(context.Background(), connector.RemediationRequest{Finding: f}); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	v1 := connectortest.Plugin(t, "old", describing(`{"name":"old","protocol":1}`))
	if _, err := v1.RequestPlan(context.Background(), connector.RemediationRequest{Finding: f}); err == nil {
		t.Fatal("a protocol 1 connector has no plan")
	}
}

func TestRequestApplySendsThePlanAndStreamsLogs(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "stdin")
	e := connectortest.Plugin(t, "a", `case "$1" in
describe) echo '{"name":"a","protocol":2,"remediates":["a.fix"]}';;
apply) cat > '`+seen+`'; echo '{"type":"log","msg":"step one"}'; echo 'garbage'; echo "warning" >&2;;
esac
`)
	p := connector.Plan{Action: "a.fix", Summary: "Fix."}
	var out, errw bytes.Buffer
	req := connector.RemediationRequest{Request: connector.Request{Secrets: map[string]string{"K": "v"}}, Finding: finding.Finding{ID: "f1"}, Plan: &p}
	if err := e.RequestApply(context.Background(), req, &out, &errw); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(seen)
	for _, want := range []string{`"protocol":2`, `"plan":{"action":"a.fix"`, `"secrets":{"K":"v"}`, `"finding":{`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("apply stdin lacks %s: %s", want, raw)
		}
	}
	if !strings.Contains(out.String(), "a: step one") || !strings.Contains(out.String(), "non-log line ignored") || errw.String() != "warning\n" {
		t.Fatalf("out=%q err=%q", out.String(), errw.String())
	}
	if err := e.RequestApply(context.Background(), connector.RemediationRequest{}, &out, &errw); err == nil {
		t.Fatal("apply without a plan must fail")
	}
	failing := connectortest.Plugin(t, "b", `case "$1" in
describe) echo '{"name":"b","protocol":2,"remediates":["b.fix"]}';;
apply) cat >/dev/null; exit 4;;
esac
`)
	if err := failing.RequestApply(context.Background(), req, &out, &errw); err == nil {
		t.Fatal("a non-zero exit is a failed apply")
	}
}
