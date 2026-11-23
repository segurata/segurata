package run

import (
	"bufio"
	"context"
	"encoding/json"
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
	t.Setenv("SECURIZAME_TEST_SECRET", "s3cret")
	cfg := config.Config{CDPURL: "http://cdp", Connectors: map[string]config.ConnectorConfig{
		"fake": {Secrets: map[string]string{"OK": "env:SECURIZAME_TEST_SECRET", "BAD": "env:SECURIZAME_TEST_UNSET"}},
	}}
	fk := &fake{}
	res, err := Inventory(context.Background(), cfg, mustTargets(t, cfg, fk), t.TempDir(), nil, nil)
	if err != nil || len(res) != 1 || res[0].Err != nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if fk.got.Secrets["OK"] != "s3cret" || fk.got.CDPURL != "http://cdp" || fk.got.Protocol != 1 {
		t.Fatalf("request not built right: %+v", fk.got)
	}
	if _, leaked := fk.got.Secrets["BAD"]; leaked {
		t.Fatal("an unresolved secret reached the connector")
	}
	lines := readLines(t, res[0].File)
	if len(lines) != 3 { // missing_credentials status, ok status, finding
		t.Fatalf("got %d lines: %v", len(lines), lines)
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
  echo '{"type":"log","msg":"done"}';;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "securizame-ext"), []byte(script), 0o755); err != nil {
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
	t.Setenv("SECURIZAME_TEST_A", "key-a")
	t.Setenv("SECURIZAME_TEST_B", "key-b")
	cfg := config.Config{Connectors: map[string]config.ConnectorConfig{
		"fake:work":     {Secrets: map[string]string{"K": "env:SECURIZAME_TEST_A"}},
		"fake:personal": {Secrets: map[string]string{"K": "env:SECURIZAME_TEST_B"}},
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
