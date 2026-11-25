package run

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/proc/proctest"
)

type fake struct{ got connector.Request }

func (f *fake) Describe() connector.Description {
	return connector.Description{Name: "fake", Version: "0", Protocol: 1}
}

func (f *fake) Inventory(_ context.Context, req connector.Request, emit connector.Emitter) error {
	f.got = req
	emit.Status(finding.Status{Account: "acct", State: finding.StateOK})
	emit.Finding(finding.Finding{Account: "acct", Resource: finding.Resource{Type: "key", ID: "k1"}, Kind: finding.KindCredential, Severity: finding.SevHigh, Title: "old key"})
	return nil
}

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestInventoryWritesRecordsResolvesSecretsAndProtectsOutput(t *testing.T) {
	t.Setenv("SEGURATA_TEST_SECRET", "s3cret")
	key := fingerprint.FromBytes([]byte("0123456789abcdef0123456789abcdef"))
	defer func(old func() (fingerprint.Key, bool)) { FingerprintKey = old }(FingerprintKey)
	FingerprintKey = func() (fingerprint.Key, bool) { return key, true }
	cfg := config.Config{CDPURL: "http://cdp", Connectors: map[string]config.ConnectorConfig{
		"fake": {Secrets: map[string]string{"OK": "env:SEGURATA_TEST_SECRET", "BAD": "env:SEGURATA_TEST_UNSET"}},
	}}
	fk := &fake{}
	res, err := Inventory(context.Background(), cfg, mustTargets(t, cfg, fk), t.TempDir(), nil, nil)
	if err != nil || len(res) != 1 || res[0].Err != nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if fk.got.Secrets["OK"] != "s3cret" || fk.got.CDPURL != "http://cdp" || fk.got.Protocol != connector.ProtocolVersion {
		t.Fatalf("request not built right: %+v", fk.got)
	}
	if _, leaked := fk.got.Secrets["BAD"]; leaked {
		t.Fatal("an unresolved secret reached the connector")
	}
	lines := readLines(t, res[0].File)
	if len(lines) != 4 { // missing_credentials status, ok status, finding, run_end
		t.Fatalf("got %d lines: %v", len(lines), lines)
	}
	if end := lines[3]; end["type"] != "run_end" || end["complete"] != false || end["connector"] != "fake" {
		t.Fatalf("an unresolved secret leaves the run incomplete: %v", end)
	}
	// run_end names the fingerprint of each resolved secret, never its value, so the tracker can
	// match a leaked copy with the key a connector is using.
	if fps, _ := lines[3]["secret_fingerprints"].(map[string]any); len(fps) != 1 || fps["OK"] != key.Of("s3cret") {
		t.Fatalf("secret fingerprints in run_end: %v", lines[3]["secret_fingerprints"])
	}
	if lines[0]["state"] != "missing_credentials" || !strings.HasPrefix(lines[0]["detail"].(string), "BAD:") {
		t.Fatalf("first line should report the missing secret: %v", lines[0])
	}
	f := lines[2]
	if f["type"] != "finding" || f["connector"] != "fake" || f["id"] != finding.StableID("fake", "acct", "key", "k1") {
		t.Fatalf("finding not filled: %v", f)
	}
	raw, _ := os.ReadFile(res[0].File)
	if strings.Contains(string(raw), "s3cret") {
		t.Fatal("secret value written to output")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(res[0].File)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("output mode %v, want 0600", st.Mode().Perm())
		}
	}
}

func TestExternalConnectorSpeaksTheProtocol(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script connector")
	}
	dir := t.TempDir()
	script := `#!/bin/sh
case "$1" in
describe) echo '{"name":"ext","version":"1.0","protocol":1,"summary":"test","needs":[],"theme":{"id":"breaches","title":"Breaches"}}';;
inventory)
  req=$(cat)
  case "$req" in *'"protocol":1'*) ;; *) echo "bad request" >&2; exit 3;; esac
  echo '{"type":"status","account":"a","state":"reauth","detail":"sign in again"}'
  echo '{"type":"finding","connector":"spoofed","account":"a","resource":{"type":"oauth_grant","id":"g","name":"App"},"kind":"grant","severity":"medium","title":"App has Drive","track":{"group":"check","key":"drive","title":"{count} have Drive"}}'
  echo '{"type":"scope","scope":"repo:a/b","inspected":false,"reason":"rate limit"}'
  echo '{"type":"log","msg":"done"}';;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "segurata-ext"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	var ext *connector.External
	for _, e := range connector.Discover() {
		if e.Describe().Name == "ext" {
			ext = e
		}
	}
	if ext == nil {
		t.Fatal("external connector not discovered")
	}
	res, err := Inventory(context.Background(), config.Config{}, mustTargets(t, config.Config{}, ext), t.TempDir(), nil, nil)
	if err != nil || res[0].Err != nil {
		t.Fatalf("err=%v resErr=%v", err, res[0].Err)
	}
	r := res[0]
	if len(r.Statuses) != 1 || r.Statuses[0].State != finding.StateReauth {
		t.Fatalf("statuses: %+v", r.Statuses)
	}
	if len(r.Findings) != 1 || r.Findings[0].Connector != "ext" || r.Findings[0].ID == "" {
		t.Fatalf("findings: %+v (connector name must come from describe, not the record)", r.Findings)
	}
	if tr := r.Findings[0].Track; tr == nil || *tr != (finding.Track{Group: finding.GroupCheck, Key: "drive", Title: "{count} have Drive"}) {
		t.Fatalf("track: %+v", tr)
	}
	if r.End.Theme != (finding.Theme{ID: "breaches", Title: "Breaches"}) {
		t.Fatalf("run_end theme: %+v", r.End.Theme)
	}
	// Nothing said ok, so everything is uninspected; the scope record still reaches run_end.
	if sk := r.End.Scopes.Skipped; len(sk) != 3 || sk[0].Scope != finding.ScopeAll || sk[1].Scope != "a" ||
		sk[2] != (finding.Skipped{Scope: "repo:a/b", Reason: "rate limit"}) {
		t.Fatalf("run_end scopes: %+v", r.End.Scopes)
	}
}

func mustTargets(t *testing.T, cfg config.Config, conns ...connector.Connector) []Target {
	t.Helper()
	ts, err := Targets(cfg, conns, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// Two accounts of one provider: each instance gets its own secrets, output file and finding ids.
func TestInstancesRunSeparatelyWithTheirOwnSecrets(t *testing.T) {
	t.Setenv("SEGURATA_TEST_A", "key-a")
	t.Setenv("SEGURATA_TEST_B", "key-b")
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{
		"fake:work":     {Secrets: map[string]string{"K": "env:SEGURATA_TEST_A"}},
		"fake:personal": {Secrets: map[string]string{"K": "env:SEGURATA_TEST_B"}},
	}}
	seen := map[string]string{}
	var mu sync.Mutex
	rec := recordingFake{onReq: func(req connector.Request) { mu.Lock(); seen[req.Secrets["K"]] = "x"; mu.Unlock() }}
	ts, err := Targets(cfg, []connector.Connector{rec}, nil)
	if err != nil || len(ts) != 2 || ts[0].Label() != "fake:personal" || ts[1].Label() != "fake:work" {
		t.Fatalf("targets %v, %v", ts, err)
	}
	res, err := Inventory(context.Background(), cfg, ts, t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("each instance must get its own secret, saw %v", seen)
	}
	if filepath.Base(res[0].File) != "fake-personal.jsonl" || filepath.Base(res[1].File) != "fake-work.jsonl" {
		t.Fatalf("files %s %s", res[0].File, res[1].File)
	}
	a, b := res[0].Findings[0], res[1].Findings[0]
	if a.Instance != "personal" || b.Instance != "work" || a.ID == b.ID {
		t.Fatalf("instances must be labelled and ids distinct: %+v %+v", a, b)
	}

	one, err := Targets(cfg, []connector.Connector{rec}, []string{"fake:work"})
	if err != nil || len(one) != 1 || one[0].Instance.Label != "work" {
		t.Fatalf("selector name:label: %v %v", one, err)
	}
	both, _ := Targets(cfg, []connector.Connector{rec}, []string{"fake"})
	if len(both) != 2 {
		t.Fatalf("selector name should pick every instance, got %d", len(both))
	}
	if _, err := Targets(cfg, []connector.Connector{rec}, []string{"fake:nope"}); err == nil {
		t.Fatal("unknown instance should be an error")
	}
}

// One instance named twice on the command line runs once.
func TestTargetsRunEachInstanceOnce(t *testing.T) {
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"fake:work": {}, "fake:personal": {}}}
	ts, err := Targets(cfg, []connector.Connector{&fake{}}, []string{"fake:work", "fake", "fake:work"})
	if err != nil || len(ts) != 2 || ts[0].Label() != "fake:work" || ts[1].Label() != "fake:personal" {
		t.Fatalf("targets %v, %v", ts, err)
	}
}

// Two runs of one instance at once (a manual run alongside the scheduled one) each write their own
// partial file, so the file left behind is one whole run and neither run fails.
func TestConcurrentRunsOfOneInstanceNeverTearTheFile(t *testing.T) {
	const n = 400
	out, cfg := t.TempDir(), config.Config{}
	var started sync.WaitGroup
	started.Add(2)
	inv := emitting(func(_ context.Context, e connector.Emitter) error {
		e.Status(finding.Status{Account: "acct", State: finding.StateOK})
		started.Done()
		started.Wait() // both runs have their partial file open
		for i := range n {
			e.Finding(finding.Finding{Account: "acct", Resource: finding.Resource{Type: "key", ID: fmt.Sprint(i)},
				Severity: finding.SevLow, Title: strings.Repeat("x", i%97)})
		}
		return nil
	})
	var wg sync.WaitGroup
	var results [2][]*Result
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = Inventory(context.Background(), cfg, mustTargets(t, cfg, inv), out, nil, nil)
		}()
	}
	wg.Wait()
	for _, res := range results {
		if res[0].Err != nil {
			t.Fatalf("run failed: %v", res[0].Err)
		}
	}
	lines := readLines(t, results[0][0].File)
	if len(lines) != n+2 || lines[len(lines)-1]["type"] != "run_end" {
		t.Fatalf("got %d lines, want %d ending in run_end", len(lines), n+2)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(results[0][0].File), "*.partial")); len(left) > 0 {
		t.Fatalf("partial files left behind: %v", left)
	}
}

type recordingFake struct{ onReq func(connector.Request) }

func (recordingFake) Describe() connector.Description {
	return connector.Description{Name: "fake", Version: "0", Protocol: 1}
}

func (r recordingFake) Inventory(_ context.Context, req connector.Request, emit connector.Emitter) error {
	r.onReq(req)
	emit.Finding(finding.Finding{Account: "same-account-name", Resource: finding.Resource{Type: "key", ID: "k"}, Severity: finding.SevLow, Title: "t"})
	return nil
}

// emitting is a connector whose inventory is a function.
type emitting func(ctx context.Context, emit connector.Emitter) error

func (emitting) Describe() connector.Description {
	return connector.Description{Name: "fake", Version: "0", Protocol: 1}
}

func (e emitting) Inventory(ctx context.Context, _ connector.Request, emit connector.Emitter) error {
	return e(ctx, emit)
}

// Every run ends with a run_end record: complete only when nothing was skipped and the connector
// did not fail. A run killed before it is written has none (see Read).
func TestRunEndRecordsCoverage(t *testing.T) {
	ok := func(emit connector.Emitter, account string) {
		emit.Status(finding.Status{Account: account, State: finding.StateOK})
	}
	cases := []struct {
		name     string
		inv      emitting
		cancel   bool
		complete bool
		skipped  []string
	}{
		{"complete", func(_ context.Context, e connector.Emitter) error { ok(e, "a"); ok(e, "b"); return nil }, false, true, nil},
		{"account signed out", func(_ context.Context, e connector.Emitter) error {
			ok(e, "a")
			e.Status(finding.Status{Account: "b", State: finding.StateSignedOut, Detail: "sign in"})
			return nil
		}, false, false, []string{"b"}},
		{"status narrowed to a project", func(_ context.Context, e connector.Emitter) error {
			ok(e, "a")
			e.Status(finding.Status{Account: "a", Scope: "proj-1", State: finding.StateError, Detail: "permission denied"})
			return nil
		}, false, false, []string{"proj-1"}},
		{"declared skip", func(_ context.Context, e connector.Emitter) error {
			ok(e, "a")
			e.Scope("repo:a/x", false, "rate limit")
			e.Scope("repo:a/y", true, "")
			return nil
		}, false, false, []string{"repo:a/x"}},
		{"connector failed to start", func(context.Context, connector.Emitter) error { return errors.New("no browser") }, false, false, []string{finding.ScopeAll}},
		{"no status said ok", func(context.Context, connector.Emitter) error { return nil }, false, false, []string{finding.ScopeAll}},
		{"interrupted", func(_ context.Context, e connector.Emitter) error { ok(e, "a"); return nil }, true, false, []string{finding.ScopeAll}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if c.cancel {
				cancel()
			}
			res, _ := Inventory(ctx, config.Config{}, mustTargets(t, config.Config{}, c.inv), t.TempDir(), nil, nil)
			end := res[0].End
			lines := readLines(t, res[0].File)
			if last := lines[len(lines)-1]; last["type"] != "run_end" || last["complete"] != c.complete {
				t.Fatalf("last line %v", last)
			}
			var got []string
			for _, s := range end.Scopes.Skipped {
				got = append(got, s.Scope)
			}
			if end.Complete != c.complete || strings.Join(got, ",") != strings.Join(c.skipped, ",") || end.Scopes.SkippedCount != len(c.skipped) {
				t.Fatalf("run_end %+v", end)
			}
			if end.StartedAt.IsZero() || end.EndedAt.Before(end.StartedAt) {
				t.Fatalf("times %v %v", end.StartedAt, end.EndedAt)
			}
		})
	}
}

// A connector that skips thousands of scopes is capped in the record, and then counts as having
// inspected nothing: the cut entries could be any of its findings.
func TestRunEndCapsLists(t *testing.T) {
	inv := emitting(func(_ context.Context, e connector.Emitter) error {
		for i := range 300 {
			e.Status(finding.Status{Account: fmt.Sprintf("ok-%d", i), State: finding.StateOK})
			e.Scope(fmt.Sprintf("repo:%d", i), false, "rate limit")
		}
		return nil
	})
	res, _ := Inventory(context.Background(), config.Config{}, mustTargets(t, config.Config{}, inv), t.TempDir(), nil, nil)
	sc := res[0].End.Scopes
	if len(sc.Inspected) != 50 || sc.InspectedCount != 300 || len(sc.Skipped) != 200 || sc.SkippedCount != 300 {
		t.Fatalf("caps: %d/%d inspected, %d/%d skipped", len(sc.Inspected), sc.InspectedCount, len(sc.Skipped), sc.SkippedCount)
	}
	end := res[0].End
	if _, none := finding.CoverageOf(&end).NoneChecked(); !none {
		t.Fatal("a truncated skipped list must not let anything count as inspected")
	}
}

// While a run is in progress (or if it dies before run_end), the day's earlier finished file must
// stay as it was; the new run only replaces it once finished.
func TestUnfinishedRunKeepsTheEarlierFile(t *testing.T) {
	out := t.TempDir()
	cfg := config.Config{}
	first, err := Inventory(context.Background(), cfg, mustTargets(t, cfg, &fake{}), out, nil, nil)
	if err != nil || first[0].Err != nil {
		t.Fatalf("first run: %v %v", err, first[0].Err)
	}
	before, _ := os.ReadFile(first[0].File)

	var during []byte
	probe := probingFake{check: func() { during, _ = os.ReadFile(first[0].File) }}
	second, err := Inventory(context.Background(), cfg, mustTargets(t, cfg, probe), out, nil, nil)
	if err != nil || second[0].Err != nil {
		t.Fatalf("second run: %v %v", err, second[0].Err)
	}
	if !bytes.Equal(before, during) {
		t.Fatal("the finished file changed while the next run was still writing")
	}
	after, _ := os.ReadFile(first[0].File)
	if bytes.Equal(before, after) || !bytes.Contains(after, []byte("run_end")) {
		t.Fatal("the finished second run did not replace the file")
	}
	if left, _ := filepath.Glob(first[0].File + ".*.partial"); len(left) > 0 {
		t.Fatalf("partial files left behind: %v", left)
	}
}

type probingFake struct{ check func() }

func (probingFake) Describe() connector.Description {
	return connector.Description{Name: "fake", Version: "0", Protocol: 1}
}

func (p probingFake) Inventory(_ context.Context, _ connector.Request, emit connector.Emitter) error {
	emit.Status(finding.Status{Account: "acct", State: finding.StateOK})
	emit.Finding(finding.Finding{Account: "acct", Resource: finding.Resource{Type: "key", ID: "new"}, Severity: finding.SevLow, Title: "new"})
	p.check()
	return nil
}

// needy needs a secret and says how to set it up; it reports a missing secret itself, as the AI
// connectors do, so a second status would show up if the core called it without the secret.
type needy struct{ called bool }

func (n *needy) Describe() connector.Description {
	return connector.Description{Name: "needy", Version: "0", Protocol: 1, Needs: []string{"secret:NEEDY_KEY"}}
}

func (n *needy) SetupHint(secret string) string {
	if secret != "NEEDY_KEY" {
		return ""
	}
	return "create a key at https://example.com/keys"
}

func (n *needy) Inventory(_ context.Context, req connector.Request, emit connector.Emitter) error {
	n.called = true
	if req.Secrets["NEEDY_KEY"] == "" {
		emit.Status(finding.Status{Account: "organization", State: finding.StateMissingCredentials, Detail: "set NEEDY_KEY"})
	}
	return nil
}

func TestAnUnresolvedRequiredSecretIsOneCoreStatusWithTheConnectorsHint(t *testing.T) {
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{
		"needy:personal": {Secrets: map[string]string{"NEEDY_KEY": "env:SEGURATA_TEST_UNSET_NEEDY"}},
	}}
	n := &needy{}
	res, err := Inventory(context.Background(), cfg, mustTargets(t, cfg, n), t.TempDir(), nil, nil)
	if err != nil || res[0].Err != nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if n.called {
		t.Error("Inventory ran without the secret it needs")
	}
	lines := readLines(t, res[0].File)
	if len(lines) != 2 {
		t.Fatalf("want one status and run_end, got %v", lines)
	}
	st := lines[0]
	detail, _ := st["detail"].(string)
	if st["state"] != "missing_credentials" || st["instance"] != "personal" ||
		!strings.HasPrefix(detail, "NEEDY_KEY: environment variable SEGURATA_TEST_UNSET_NEEDY is not set") ||
		!strings.HasSuffix(detail, "; create a key at https://example.com/keys") {
		t.Errorf("status: %v", st)
	}
	if end := lines[1]; end["type"] != "run_end" || end["complete"] != false {
		t.Errorf("run_end: %v", end)
	}
}

func TestAMissingSecretReferenceIsLeftToTheConnector(t *testing.T) {
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"needy": {}}}
	n := &needy{}
	res, _ := Inventory(context.Background(), cfg, mustTargets(t, cfg, n), t.TempDir(), nil, nil)
	if !n.called || len(res[0].Statuses) != 1 || res[0].Statuses[0].Detail != "set NEEDY_KEY" {
		t.Errorf("called=%v statuses=%v", n.called, res[0].Statuses)
	}
}

// The core marks a status the config expects as it is written: state expected, the original state
// and the reason kept, and the scope still not inspected.
func TestExpectedStatusesAreMarkedAndStayUninspected(t *testing.T) {
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{
		"needy:personal": {Secrets: map[string]string{"NEEDY_KEY": "env:SEGURATA_TEST_UNSET_NEEDY"},
			Expected: []config.Expected{{State: finding.StateMissingCredentials, Reason: "ephemeral key on purpose"}}},
	}}
	res, _ := Inventory(context.Background(), cfg, mustTargets(t, cfg, &needy{}), t.TempDir(), nil, nil)
	lines := readLines(t, res[0].File)
	st := lines[0]
	if st["state"] != "expected" || st["was"] != "missing_credentials" || st["expected"] != "ephemeral key on purpose" {
		t.Errorf("status %v", st)
	}
	if end := lines[len(lines)-1]; end["complete"] != false {
		t.Errorf("an expected status counted as inspected: %v", end)
	}
	var b bytes.Buffer
	Summary(&b, res, finding.SevLow)
	if !strings.Contains(b.String(), "~ needy:personal: 1 expected (by your config: ephemeral key on purpose)") || strings.Contains(b.String(), "missing_credentials") {
		t.Errorf("summary:\n%s", b.String())
	}
}

// Write credentials are references for the remediation to resolve at apply time: neither an
// inventory request nor the remediation's credentials resolve them up front.
func TestRemediationSecretsAreNeverResolvedForARequest(t *testing.T) {
	t.Setenv("SEGURATA_TEST_READ", "read-value")
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"openai": {
		Secrets:            map[string]string{"OPENAI_ADMIN_KEY": "env:SEGURATA_TEST_READ"},
		RemediationSecrets: map[string]string{"OPENAI_ADMIN_WRITE_KEY": "env:SEGURATA_TEST_WRITE_UNSET"},
	}}}
	req, errs := NewRequest(context.Background(), cfg, cfg.Instances("openai")[0])
	if len(errs) > 0 || req.Secrets["OPENAI_ADMIN_KEY"] != "read-value" || len(req.Secrets) != 1 {
		t.Fatalf("inventory request: %v %v", req.Secrets, errs)
	}
	cs, errs := InstanceCredentials(context.Background(), cfg, "openai", "")
	if len(errs) > 0 {
		t.Fatalf("an unset write reference must not fail before apply: %v", errs)
	}
	if !cs.HasWrite("OPENAI_ADMIN_WRITE_KEY") || cs.HasWrite("OTHER_WRITE_KEY") {
		t.Fatal("HasWrite must tell configured references from missing ones")
	}
	if _, err := cs.Write(context.Background(), "OPENAI_ADMIN_WRITE_KEY"); err == nil || !strings.Contains(err.Error(), "SEGURATA_TEST_WRITE_UNSET") {
		t.Fatalf("resolving an unset write reference: %v", err)
	}
	t.Setenv("SEGURATA_TEST_WRITE_UNSET", "write-value")
	if v, err := cs.Write(context.Background(), "OPENAI_ADMIN_WRITE_KEY"); err != nil || v != "write-value" {
		t.Fatalf("Write resolves at call time: %q %v", v, err)
	}
}

// flaky fails the writes numbered in fail (1-based) with ENOSPC and keeps the rest.
type flaky struct {
	buf  bytes.Buffer
	n    int
	fail map[int]bool
}

func (w *flaky) Write(p []byte) (int, error) {
	w.n++
	if w.fail[w.n] {
		return 0, syscall.ENOSPC
	}
	return w.buf.Write(p)
}

// A record the sink could not write makes the run fail: run_end carries the error, so the
// findings that were lost never count as resolved.
func TestALostRecordFailsTheRun(t *testing.T) {
	w := &flaky{fail: map[int]bool{2: true}}
	s := &sink{name: "fake", out: w, res: &Result{}}
	s.Status(finding.Status{Account: "acct", State: finding.StateOK})
	s.Finding(finding.Finding{Account: "acct", Resource: finding.Resource{Type: "key", ID: "lost"}, Severity: finding.SevHigh, Title: "lost"})
	ended, err := s.end(context.Background(), time.Now(), nil, nil)
	if !errors.Is(err, syscall.ENOSPC) || !ended {
		t.Fatalf("end: ended=%v err=%v", ended, err)
	}
	if s.res.End.Complete || !strings.Contains(s.res.End.Error, "no space left") {
		t.Fatalf("run_end %+v", s.res.End)
	}
	if !bytes.Contains(w.buf.Bytes(), []byte(`"error":"writing the run file: no space left`)) {
		t.Fatalf("the written run_end does not carry the error:\n%s", w.buf.String())
	}

	// run_end itself lost: the run did not end.
	w = &flaky{fail: map[int]bool{2: true}}
	s = &sink{name: "fake", out: w, res: &Result{}}
	s.Status(finding.Status{Account: "acct", State: finding.StateOK})
	if ended, err := s.end(context.Background(), time.Now(), nil, nil); ended || err == nil {
		t.Fatalf("lost run_end: ended=%v err=%v", ended, err)
	}
}

// A connector instance that hangs is stopped at its deadline (the instance's timeout, else the
// connector's own default, else DefaultTimeout), and its run ends failed so nothing closes.
func TestAHungInstanceTimesOutAndClosesNothing(t *testing.T) {
	hang := emitting(func(ctx context.Context, e connector.Emitter) error {
		e.Status(finding.Status{Account: "acct", State: finding.StateOK})
		<-ctx.Done()
		return nil
	})
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"fake": {Timeout: "50ms"}}}
	res, err := Inventory(context.Background(), cfg, mustTargets(t, cfg, hang), t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	end := res[0].End
	if end.Complete || !strings.Contains(end.Error, "timed out after 50ms") || !strings.Contains(end.Error, "connectors.fake.timeout") {
		t.Fatalf("run_end %+v", end)
	}
}

type slow struct{ emitting }

func (slow) Describe() connector.Description {
	return connector.Description{Name: "fake", Version: "0", Protocol: 1, Timeout: "6h"}
}

func TestTheTimeoutComesFromTheInstanceThenTheConnector(t *testing.T) {
	for _, c := range []struct {
		conn connector.Connector
		cfg  config.ConnectorConfig
		want time.Duration
	}{
		{&fake{}, config.ConnectorConfig{}, DefaultTimeout},
		{slow{}, config.ConnectorConfig{}, 6 * time.Hour},
		{slow{}, config.ConnectorConfig{Timeout: "90m"}, 90 * time.Minute},
		{&fake{}, config.ConnectorConfig{Timeout: "2h"}, 2 * time.Hour},
	} {
		tg := Target{Connector: c.conn, Instance: config.Instance{ConnectorConfig: c.cfg}}
		if got := tg.Timeout(); got != c.want {
			t.Errorf("%s with %+v: %s, want %s", c.conn.Describe().Timeout, c.cfg, got, c.want)
		}
	}
}

// An external connector that hangs in a child it did not exec is stopped too.
func TestAHungExternalConnectorTimesOut(t *testing.T) {
	script := proctest.Hung(t, "segurata-hang", `[ "$1" = describe ] && { echo '{"name":"hang","version":"1","protocol":1,"summary":"t","needs":[]}'; exit 0; }`)
	t.Setenv("PATH", filepath.Dir(script)+string(os.PathListSeparator)+os.Getenv("PATH"))
	var conns []connector.Connector
	for _, e := range connector.Discover() {
		if e.Describe().Name == "hang" {
			conns = append(conns, e)
		}
	}
	if len(conns) != 1 {
		t.Fatal("external connector not discovered")
	}
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"hang": {Timeout: "200ms"}}}
	start := time.Now()
	res, err := Inventory(context.Background(), cfg, mustTargets(t, cfg, conns...), t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > proc.WaitDelay+5*time.Second {
		t.Fatalf("took %s", took)
	}
	if end := res[0].End; end.Complete || !strings.Contains(end.Error, "timed out") {
		t.Fatalf("run_end %+v", end)
	}
}

// observed_at belongs to the core: a connector's own value, a future one above all, is replaced
// with the time the record was written.
// tracked is a built-in connector that declares a shared theme and how its findings group.
type tracked struct{ emitting }

func (tracked) Describe() connector.Description {
	return connector.Description{Name: "fake", Version: "0", Protocol: 1, Theme: finding.Theme{ID: finding.ThemeCloud.ID},
		Covers: []finding.Area{{ID: "breaches"}}}
}

func (tracked) Track(f finding.Finding) *finding.Track {
	return &finding.Track{Group: finding.GroupProject, Key: f.Account + "/" + f.Instance}
}

// The core sets Track on each finding of a built-in connector that declares it, unless the finding
// carries its own, and writes the declared theme, resolved, and covered areas in run_end.
func TestTheCoreStampsTrackAndTheme(t *testing.T) {
	c := tracked{func(_ context.Context, e connector.Emitter) error {
		e.Status(finding.Status{Account: "acct", State: finding.StateOK})
		e.Finding(finding.Finding{Account: "acct", Resource: finding.Resource{Type: "key", ID: "a"}, Severity: finding.SevLow, Title: "a"})
		e.Finding(finding.Finding{Account: "acct", Resource: finding.Resource{Type: "key", ID: "b"}, Severity: finding.SevLow, Title: "b",
			Track: &finding.Track{Group: finding.GroupFinding}})
		return nil
	}}
	res, _ := Inventory(context.Background(), config.Config{}, mustTargets(t, config.Config{}, c), t.TempDir(), nil, nil)
	fs := res[0].Findings
	if fs[0].Track == nil || fs[0].Track.Key != "acct/" || fs[1].Track.Group != finding.GroupFinding {
		t.Fatalf("tracks: %+v %+v", fs[0].Track, fs[1].Track)
	}
	if res[0].End.Theme != finding.ThemeCloud || len(res[0].End.Covers) != 1 || res[0].End.Covers[0].ID != "breaches" {
		t.Fatalf("theme %+v, covers %+v", res[0].End.Theme, res[0].End.Covers)
	}
	lines := readLines(t, res[0].File)
	if end := lines[len(lines)-1]; end["theme"].(map[string]any)["title"] != finding.ThemeCloud.Title {
		t.Fatalf("run_end written: %v", end)
	}
}

func TestTheCoreStampsObservedAt(t *testing.T) {
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	inv := emitting(func(_ context.Context, e connector.Emitter) error {
		e.Status(finding.Status{Account: "acct", State: finding.StateOK})
		e.Finding(finding.Finding{Account: "acct", Resource: finding.Resource{Type: "key", ID: "k"}, Severity: finding.SevLow, Title: "t", ObservedAt: future})
		return nil
	})
	before := time.Now()
	res, _ := Inventory(context.Background(), config.Config{}, mustTargets(t, config.Config{}, inv), t.TempDir(), nil, nil)
	if got := res[0].Findings[0].ObservedAt; got.Before(before.Add(-time.Second)) || got.After(time.Now()) {
		t.Fatalf("observed_at %v", got)
	}
}
