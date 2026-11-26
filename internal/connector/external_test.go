package connector_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/proc/proctest"
)

func describing(js string) string { return "case \"$1\" in describe) echo '" + js + "';; esac\n" }

// The name in describe must be the file's suffix and a plain lowercase word: it picks the secrets
// the core hands over and names the run file.
func TestLoadExternalChecksTheDescription(t *testing.T) {
	cases := []struct {
		why, file, js string
		ok            bool
	}{
		{"protocol 3", "x", `{"name":"x","protocol":3}`, false},
		{"protocol 0", "x", `{"name":"x","protocol":0}`, false},
		{"remediates on protocol 1", "x", `{"name":"x","protocol":1,"remediates":["x.fix"]}`, false},
		{"empty remediation", "x", `{"name":"x","protocol":2,"remediates":[""]}`, false},
		{"no name", "x", `{"protocol":2}`, false},
		{"not json", "x", `nope`, false},
		{"another file's name", "x", `{"name":"openai","protocol":2}`, false},
		{"theme id not a word", "x", `{"name":"x","protocol":2,"theme":{"id":"My Theme"}}`, false},
		{"area id not a word", "x", `{"name":"x","protocol":2,"covers":[{"id":""}]}`, false},
		{"upper case name", "Upper", `{"name":"Upper","protocol":2}`, false},
		{"underscore name", "under_score", `{"name":"under_score","protocol":2}`, false},
		{"dotted name", "prowler.orig", `{"name":"prowler.orig","protocol":2}`, false},
		{"leading dash", "-lead", `{"name":"-lead","protocol":2}`, false},
		{"protocol 1", "x", `{"name":"x","protocol":1}`, true},
		{"remediates on protocol 2", "x", `{"name":"x","protocol":2,"remediates":["x.fix"]}`, true},
		{"theme and areas", "x", `{"name":"x","protocol":1,"theme":{"id":"cloud"},"covers":[{"id":"hibp"}]}`, true},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			t.Parallel()
			_, err := connector.LoadExternal(connectortest.Script(t, c.file, describing(c.js)))
			if (err == nil) != c.ok {
				t.Errorf("%s: err = %v", c.js, err)
			}
		})
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
	plugin := func(dir, file, name string) string {
		t.Helper()
		return proctest.Script(t, dir, "segurata-"+file, "echo "+file+" >> '"+ran+"'\n"+describing(`{"name":"`+name+`","protocol":2}`))
	}
	plugin(first, "discoverbuiltin", "discoverbuiltin")
	plugin(first, "zzz", "discoverbuiltin")
	dup := plugin(first, "dup", "dup")
	plugin(second, "dup", "dup")
	plugin(second, "dup.orig", "dup")
	t.Setenv("PATH", first+string(os.PathListSeparator)+second)

	got := connector.Discover()
	if len(got) != 1 || got[0].Path != dup || got[0].Describe().Name != "dup" {
		t.Fatalf("discovered %+v", got)
	}
	raw, _ := os.ReadFile(ran)
	if strings.Contains(string(raw), "discoverbuiltin") || strings.Contains(string(raw), "orig") {
		t.Fatalf("ran a plugin it should have skipped unseen:\n%s", raw)
	}
}

// A plugin that hangs or floods its output must not hang or exhaust the core. The sleep runs in a
// child that keeps the pipes open after the plugin itself is killed.
func TestPluginSubprocessesAreBounded(t *testing.T) {
	t.Run("hung describe", func(t *testing.T) {
		start := time.Now()
		if _, err := connector.LoadExternalWithin(connectortest.Script(t, "slow", `sleep 30; `+describing(`{"name":"slow","protocol":2}`)), 200*time.Millisecond); err == nil || !strings.Contains(err.Error(), "no answer within") {
			t.Errorf("a describe that hangs: %v", err)
		}
		if took := time.Since(start); took > 10*time.Second {
			t.Errorf("a hung describe held LoadExternal for %v", took)
		}
	})
	big := `{"name":"big","protocol":2,"summary":"` + strings.Repeat("x", 2<<20) + `"}`
	if _, err := connector.LoadExternal(connectortest.Script(t, "big", describing(big))); err == nil || strings.Contains(err.Error(), "no answer within") {
		t.Errorf("a 2 MiB describe: %v", err)
	}
	noisy := connectortest.Plugin(t, "noisy", `case "$1" in
describe) echo '{"name":"noisy","protocol":2}';;
inventory) cat >/dev/null; head -c 3000000 /dev/zero | tr '\0' x >&2;;
esac
`)
	if err := noisy.Inventory(context.Background(), connector.Request{}, &recorder{}); err == nil {
		t.Error("3 MB of stderr was accepted")
	}
}

// A relative PATH entry would load plugins from whatever directory segurata runs in.
func TestDiscoverSkipsRelativePathEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	proctest.Script(t, filepath.Join(dir, "bin"), "segurata-local", describing(`{"name":"local","protocol":2}`))
	t.Chdir(dir)
	t.Setenv("PATH", "bin")
	if got := connector.Discover(); len(got) != 0 {
		t.Fatalf("discovered %s from a relative PATH entry", got[0].Path)
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

type recorder struct {
	logs     []string
	findings []finding.Finding
	statuses []finding.Status
}

func (r *recorder) Finding(f finding.Finding)  { r.findings = append(r.findings, f) }
func (r *recorder) Status(s finding.Status)    { r.statuses = append(r.statuses, s) }
func (r *recorder) Scope(string, bool, string) {}
func (r *recorder) Log(m string)               { r.logs = append(r.logs, m) }

// A record the core cannot use must fail the run: dropping it would close its item as verified.
func TestInventoryFailsOnMalformedRecords(t *testing.T) {
	good := `{"type":"finding","account":"a","resource":{"type":"t","id":"ok"},"kind":"grant","severity":"high","title":"ok"}`
	malformed := map[string]string{
		"not json":            `not json`,
		"evidence shape":      `{"type":"finding","account":"a","resource":{"type":"t","id":"x"},"severity":"high","evidence":"text"}`,
		"capitalised":         `{"type":"finding","account":"a","resource":{"type":"t","id":"x"},"severity":"High"}`,
		"no severity":         `{"type":"finding","account":"a","resource":{"type":"t","id":"x"}}`,
		"remediation level":   `{"type":"finding","account":"a","resource":{"type":"t","id":"x"},"severity":"low","remediation":{"severity":"urgent"}}`,
		"status shape":        `{"type":"status","account":["a"],"state":"ok"}`,
		"scope shape":         `{"type":"scope","scope":"repo:a/b","inspected":"no"}`,
		"unknown record type": `{"type":"Finding","account":"a"}`,
	}
	for why, line := range malformed {
		t.Run(why, func(t *testing.T) {
			t.Parallel()
			e := connectortest.Plugin(t, "m", `case "$1" in
describe) echo '{"name":"m","protocol":2}';;
inventory) cat >/dev/null; echo '`+good+`'; echo '`+line+`';;
esac
`)
			var rec recorder
			err := e.Inventory(context.Background(), connector.Request{}, &rec)
			if err == nil || !strings.Contains(err.Error(), "1 malformed record") {
				t.Errorf("err = %v", err)
			}
			if len(rec.findings) != 1 || rec.findings[0].Resource.ID != "ok" {
				t.Errorf("findings %+v; the well-formed one must still arrive", rec.findings)
			}
		})
	}
}

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

// plan and apply get the instance's secrets too: what they print reaches the owner's terminal,
// so a value echoed in a log line, on stderr or in the run's error shows redacted, and a plan
// that carries one is refused, since it cannot be shown.
func TestPlanAndApplyNeverShowTheSecretsTheyGot(t *testing.T) {
	const value = "sk-synthetic-remediation-0123456789"
	e := connectortest.Plugin(t, "s", `v=$(sed 's/.*"K":"\([^"]*\)".*/\1/')
case "$1" in
describe) echo '{"name":"s","protocol":2,"remediates":["s.fix"]}';;
plan) echo "plan saw $v" >&2; echo '{"action":"s.fix","summary":"Rotate '"$v"'."}';;
apply) echo '{"type":"log","msg":"rotating '"$v"'"}'; printf 'half %s' "$v" >&2; printf ' line\nwarn %s\n' "$v" >&2; echo "fail $v" >&2; exit 2;;
esac
`)
	p := connector.Plan{Action: "s.fix", Summary: "Fix."}
	req := connector.RemediationRequest{Request: connector.Request{Secrets: map[string]string{"K": value}}, Finding: finding.Finding{ID: "f"}, Plan: &p}
	_, err := e.RequestPlan(context.Background(), req)
	if err == nil || strings.Contains(err.Error(), value) {
		t.Fatalf("a plan carrying the secret: err = %v", err)
	}
	var out, errw bytes.Buffer
	err = e.RequestApply(context.Background(), req, &out, &errw)
	if err == nil {
		t.Fatal("exit 2 is a failed apply")
	}
	for where, text := range map[string]string{"stdout": out.String(), "stderr": errw.String(), "error": err.Error()} {
		if strings.Contains(text, value) {
			t.Errorf("the secret reached %s: %q", where, text)
		}
	}
	if want := "half …6789(35) line\nwarn …6789(35)\nfail …6789(35)\n"; errw.String() != want {
		t.Errorf("stderr = %q, want %q", errw.String(), want)
	}
	if !strings.Contains(out.String(), "s: rotating …6789(35)") {
		t.Errorf("stdout = %q", out.String())
	}

	failing := connectortest.Plugin(t, "f", `v=$(sed 's/.*"K":"\([^"]*\)".*/\1/')
case "$1" in
describe) echo '{"name":"f","protocol":2,"remediates":["f.fix"]}';;
plan) echo "cannot plan $v" >&2; exit 3;;
esac
`)
	if _, err := failing.RequestPlan(context.Background(), req); err == nil || strings.Contains(err.Error(), value) || !strings.Contains(err.Error(), "cannot plan …6789(35)") {
		t.Fatalf("plan error = %v", err)
	}
}

// A plugin whose child keeps stdout open must not outlive its context: the scanner reading that
// stdout would otherwise wait for the child, however short the timeout.
func TestInventoryReturnsWhenAChildHoldsStdout(t *testing.T) {
	e := connectortest.Plugin(t, "held", `case "$1" in
describe) echo '{"name":"held","protocol":2}';;
inventory) cat >/dev/null; sleep 20 & wait;;
esac
`)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := e.Inventory(ctx, connector.Request{}, &recorder{}); err == nil {
		t.Fatal("a plugin killed by its timeout succeeded")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Inventory blocked for %s on the child holding stdout", took)
	}
}
