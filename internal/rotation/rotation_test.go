package rotation

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/tracker"
)

var t0 = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

func ev(fp, typ, path, source, kind, mode string, tracked, remote bool) secretrisk.Evidence {
	return secretrisk.Evidence{Fingerprint: fp, Type: typ, Path: path, Source: source, Kind: kind, Mode: mode,
		Tracked: tracked, Remote: remote, Redacted: "hint-" + typ, Bucket: "b", Count: 1}
}

func writeFindings(t *testing.T, path string, evs ...secretrisk.Evidence) {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, e := range evs {
		raw, _ := json.Marshal(e)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		_ = enc.Encode(finding.Finding{Type: "finding", Connector: tracker.SecretsConnector, Evidence: m, ObservedAt: t0})
	}
	_ = enc.Encode(finding.Status{Type: "status", Connector: tracker.SecretsConnector, State: finding.StateOK})
	_ = enc.Encode(finding.Finding{Type: "finding", Connector: "aws", Evidence: map[string]any{"fingerprint": "zzzz"}})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCommands(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFindings(t, filepath.Join(out, "2026-11-01", "local-secrets.jsonl"),
		ev("1111111111111111", "anthropic", "~/old", "scan", "config", "600", false, false))
	writeFindings(t, filepath.Join(out, "2026-11-23", "local-secrets.jsonl"),
		ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/src/shop/.env", "scan", "repo", "600", false, false),
		ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/src/shop/x.env", "gitleaks", "repo", "", true, true),
		ev("bbbbbbbbbbbbbbbb", "sentry-dsn", "~/src/blog/.env", "scan", "repo", "600", false, false))
	state := filepath.Join(dir, "state", "tracker.json")
	run := func(args ...string) (string, string, int) {
		var o, e bytes.Buffer
		code := CLI{Out: &o, Err: &e, Paths: tracker.Paths{Tracker: state}, Now: func() time.Time { return t0 }}.Run(args)
		return o.String(), e.String(), code
	}

	o, e, code := run("sync", "--out", out)
	if code != 0 || !strings.Contains(o, "2 secrets (2 new") || !strings.Contains(o, "P0 1") {
		t.Fatalf("sync: %d %q %q", code, o, e)
	}
	if st, err := os.Stat(state); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v", err)
	}
	o, _, _ = run("list", "--priority", "P0,P1")
	if !strings.Contains(o, "aaaaaaaa") || strings.Contains(o, "bbbbbbbb") || !strings.Contains(o, "git+remote") || !strings.Contains(o, "1 items") {
		t.Errorf("list P0,P1:\n%s", o)
	}
	o, _, _ = run("list", "--service", "sentry")
	if !strings.Contains(o, "bbbbbbbb") || strings.Contains(o, "aaaaaaaa") {
		t.Errorf("list --service:\n%s", o)
	}
	o, _, code = run("show", "aaaa")
	for _, want := range []string{"rotate at:   https://dashboard.stripe.com/apikeys", "~/src/shop/.env", "committed to a git repository with a remote", "found"} {
		if code != 0 || !strings.Contains(o, want) {
			t.Errorf("show lacks %q:\n%s", want, o)
		}
	}
	if _, _, code := run("done", "aaaa", "--note", "rolled in the dashboard"); code != 0 {
		t.Fatal("done failed")
	}
	if _, e, code := run("snooze", "bbbb"); code == 0 || !strings.Contains(e, "--until") {
		t.Errorf("snooze without --until: %d %q", code, e)
	}
	if _, _, code := run("snooze", "bbbb", "--until", "2027-01-01"); code != 0 {
		t.Error("snooze failed")
	}
	o, _, _ = run("list")
	if !strings.Contains(o, "0 items") {
		t.Errorf("default list should hide rotated and snoozed:\n%s", o)
	}
	o, _, _ = run("list", "--all")
	if !strings.Contains(o, "rotated") || !strings.Contains(o, "snoozed") {
		t.Errorf("list --all:\n%s", o)
	}
	if _, _, code := run("ignore", "bbbb", "--reason", "public DSN"); code != 0 {
		t.Error("ignore failed")
	}
	if _, _, code := run("reopen", "bbbb"); code != 0 {
		t.Error("reopen failed")
	}
	o, _, _ = run("sync", "--from", filepath.Join(out, "2026-11-23", "local-secrets.jsonl"))
	if !strings.Contains(o, "1 reopened") {
		t.Errorf("rotated secret still present should reopen: %q", o)
	}
	o, _, _ = run("show", "aaaa")
	if !strings.Contains(o, tracker.StillPresent) || !strings.Contains(o, "rolled in the dashboard") {
		t.Errorf("show after reopen:\n%s", o)
	}
	if _, e, code := run("show", "ffff"); code != 1 || !strings.Contains(e, "no item") {
		t.Errorf("unknown id: %d %q", code, e)
	}
	if _, _, code := run("bogus"); code != 2 {
		t.Error("unknown subcommand accepted")
	}
	if _, e, code := run("sync", "--out", filepath.Join(dir, "none")); code != 1 || !strings.Contains(e, "securizame inventory") {
		t.Errorf("sync without runs: %d %q", code, e)
	}
	other := filepath.Join(dir, "other")
	if err := os.MkdirAll(filepath.Join(other, "2026-11-23"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(other, "2026-11-23", "macos.jsonl"), []byte(`{"type":"status","connector":"macos","state":"ok"}`+"\n"), 0o600)
	if _, e, code := run("sync", "--out", other); code != 1 || !strings.Contains(e, "securizame inventory local-secrets") {
		t.Errorf("sync without a local-secrets run: %d %q", code, e)
	}
}

func TestBulkByPath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "f.jsonl")
	writeFindings(t, src,
		ev("1111111111111111", "private-key", "~/src/app/log/test.log", "scan", "log", "644", false, false),
		ev("2222222222222222", "private-key", "~/src/app/log/test.log", "scan", "log", "644", false, false),
		ev("3333333333333333", "private-key", "~/src/app/log/test.log", "scan", "log", "644", false, false),
		ev("3333333333333333", "private-key", "~/.ssh/id_x", "ssh", "config", "600", false, false),
		ev("4444444444444444", "github", "~/src/app/log/test.log.old", "scan", "log", "644", false, false))
	state := filepath.Join(dir, "tracker.json")
	run := func(args ...string) (string, string, int) {
		var o, e bytes.Buffer
		code := CLI{Out: &o, Err: &e, Paths: tracker.Paths{Tracker: state}, Now: func() time.Time { return t0 }}.Run(args)
		return o.String(), e.String(), code
	}
	run("sync", "--from", src)
	o, e, code := run("ignore", "--path", "~/src/app/log/test.log", "--reason", "test fixtures")
	if code != 0 || !strings.Contains(o, "2 items") {
		t.Fatalf("bulk ignore: %d %q %q", code, o, e)
	}
	l, _ := tracker.Load(state)
	for id, want := range map[string]tracker.Status{"1111": tracker.Ignored, "2222": tracker.Ignored, "3333": tracker.Open, "4444": tracker.Open} {
		if it, _ := l.FindRotate(id); it.Status != want {
			t.Errorf("%s: %s, want %s", id, it.Status, want)
		}
	}
	if _, _, code := run("reopen", "--path", "~/src/app/log/"); code != 0 {
		t.Error("bulk reopen")
	}
	if _, e, code := run("done", "1111", "--path", "~/src"); code != 2 || !strings.Contains(e, "usage") {
		t.Errorf("id and --path together: %d %q", code, e)
	}
	if _, e, code := run("snooze", "--path", "~/nowhere", "--until", "2027-01-01"); code != 1 || !strings.Contains(e, "no open item") {
		t.Errorf("empty selection: %d %q", code, e)
	}
}
