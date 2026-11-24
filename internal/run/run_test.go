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
	"testing"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
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
describe) echo '{"name":"ext","version":"1.0","protocol":1,"summary":"test","needs":[]}';;
inventory)
  req=$(cat)
  case "$req" in *'"protocol":1'*) ;; *) echo "bad request" >&2; exit 3;; esac
  echo '{"type":"status","account":"a","state":"reauth","detail":"sign in again"}'
  echo 'not json'
  echo '{"type":"finding","connector":"spoofed","account":"a","resource":{"type":"oauth_grant","id":"g","name":"App"},"kind":"grant","severity":"medium","title":"App has Drive"}'
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
// did not fail. A run killed before it is written has none (see remediate.ReadRun).
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
	if _, err := os.Stat(first[0].File + ".partial"); err == nil {
		t.Fatal("the partial file was left behind")
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
