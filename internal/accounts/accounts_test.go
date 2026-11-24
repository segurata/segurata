package accounts

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runtest"
	"github.com/segurata/segurata/internal/tracker"
)

var t0 = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

func st(connector, account string, state finding.State) finding.Status {
	return finding.Status{Type: "status", Connector: connector, Account: account, State: state, Detail: string(state)}
}

type fixture struct {
	dir, out, cfg, trk string
}

func newFixture(t *testing.T, cfg string) *fixture {
	t.Helper()
	dir := t.TempDir()
	x := &fixture{dir: dir, out: filepath.Join(dir, "out"), cfg: filepath.Join(dir, "config.json"), trk: filepath.Join(dir, "home", "tracker.json")}
	if err := os.WriteFile(x.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *fixture) run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var o, e bytes.Buffer
	code := CLI{Out: &o, Err: &e, Config: x.cfg, Paths: tracker.Paths{Tracker: x.trk}, Now: func() time.Time { return t0.Add(48 * time.Hour) },
		Email: func() string { return "me@x.com" }}.Run(args)
	return o.String(), e.String(), code
}

func (x *fixture) sync(t *testing.T) *tracker.Tracker {
	t.Helper()
	tr, err := tracker.LoadOrNew(tracker.Paths{Tracker: x.trk}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Sync(tracker.SyncOptions{OutDir: x.out}, t0.Add(47*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tr.Save(x.trk); err != nil {
		t.Fatal(err)
	}
	return tr
}

func (x *fixture) setupItem(t *testing.T, account string) *tracker.Item {
	t.Helper()
	tr, err := tracker.Load(x.trk)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range tr.Items {
		if it.Kind == tracker.KindSetup && strings.Contains(it.Key, "|"+account+"|") {
			return it
		}
	}
	t.Fatalf("no setup item for %s", account)
	return nil
}

func (x *fixture) accounts(t *testing.T, key string) ([]string, bool) {
	t.Helper()
	cfg, err := config.Load(x.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Accounts(key)
}

func TestListWatchUnwatch(t *testing.T) {
	x := newFixture(t, `{"connectors": {"google-personal": {"config": {"accounts": ["me@x.com", "anna@x.com"]}}}}`)
	runtest.Write(t, filepath.Join(x.out, "2026-11-23", "google-personal.jsonl"),
		st("google-personal", "me@x.com", finding.StateOK), st("google-personal", "anna@x.com", finding.StateReauth), st("google-personal", "old@x.com", finding.StateOK))
	runtest.Write(t, filepath.Join(x.out, "2026-11-24", "google-personal.jsonl"),
		st("google-personal", "me@x.com", finding.StateOK), st("google-personal", "anna@x.com", finding.StateReauth),
		finding.Skipped{Scope: "old@x.com", Reason: "not in connectors.google-personal.config.accounts"})
	x.sync(t)

	o, e, code := x.run(t, "list", "google-personal", "--out", x.out)
	if code != 0 {
		t.Fatalf("list: %q", e)
	}
	for _, want := range []string{`google-personal (connectors."google-personal".config.accounts: 2 watched)`, "anna@x.com  yes", "me@x.com    yes",
		"old@x.com   no       skipped: not in connectors.google-personal.config.accounts"} {
		if !strings.Contains(o, want) {
			t.Errorf("list lacks %q:\n%s", want, o)
		}
	}

	o, e, code = x.run(t, "unwatch", "google-personal", "anna@x.com", "--out", x.out)
	if code != 0 || !strings.Contains(o, "is now: me@x.com") || !strings.Contains(o, "kept as") || !strings.Contains(o, ": ignored") {
		t.Fatalf("unwatch: %q %q", o, e)
	}
	if list, _ := x.accounts(t, "google-personal"); !slices.Equal(list, []string{"me@x.com"}) {
		t.Errorf("accounts after unwatch: %v", list)
	}
	if it := x.setupItem(t, "anna@x.com"); it.Status != tracker.Ignored {
		t.Errorf("anna's setup item: %s", it.Status)
	}
	if _, e, code := x.run(t, "unwatch", "google-personal", "me@x.com", "--out", x.out); code != 1 || !strings.Contains(e, "empty") {
		t.Errorf("unwatching the last account: %d %q", code, e)
	}

	o, e, code = x.run(t, "watch", "google-personal", "anna@x.com", "--out", x.out)
	if code != 0 || !strings.Contains(o, "is now: me@x.com, anna@x.com") || !strings.Contains(o, ": open") {
		t.Fatalf("watch: %q %q", o, e)
	}
	if it := x.setupItem(t, "anna@x.com"); it.Status != tracker.Open {
		t.Errorf("anna's setup item after watch: %s", it.Status)
	}
	if o, _, _ := x.run(t, "watch", "google-personal", "ANNA@x.com"); !strings.Contains(o, "already in") {
		t.Errorf("watch twice: %q", o)
	}
	if _, e, code := x.run(t, "watch", "aws", "123"); code != 1 || !strings.Contains(e, "no accounts list") {
		t.Errorf("aws watch: %d %q", code, e)
	}
}

// Without a list, unwatch writes one: every person's account seen but the one taken out.
func TestUnwatchWithoutAListWritesOne(t *testing.T) {
	x := newFixture(t, `{"connectors": {"gcp": {"config": {"gcloud_path": "/x/gcloud"}}}}`)
	runtest.Write(t, filepath.Join(x.out, "2026-11-24", "gcp.jsonl"),
		st("gcp", "a@x.com", finding.StateOK), st("gcp", "b@x.com", finding.StateReauth), st("gcp", "bot@p.iam.gserviceaccount.com", finding.StateOK))
	if o, e, code := x.run(t, "list", "gcp", "--out", x.out); code != 0 || !strings.Contains(o, "no accounts list: every account is watched") {
		t.Fatalf("list: %q %q", o, e)
	}
	if o, e, code := x.run(t, "unwatch", "gcp", "b@x.com", "--out", x.out); code != 0 || !strings.Contains(o, "is now: a@x.com\n") {
		t.Fatalf("unwatch: %q %q", o, e)
	}
	if o, _, _ := x.run(t, "watch", "gcp", "b@x.com"); !strings.Contains(o, "is now: a@x.com, b@x.com") {
		t.Errorf("watch: %q", o)
	}
}

func TestOwned(t *testing.T) {
	x := newFixture(t, `{"owned": {"aws_accounts": ["111111111111"]}}`)
	runtest.Write(t, filepath.Join(x.out, "2026-11-24", "aws.jsonl"), st("aws", "012345678901", finding.StateNoScope))
	x.sync(t)
	o, e, code := x.run(t, "owned", "--out", x.out)
	for _, want := range []string{"aws_accounts (2):", "012345678901  (tracker, runs in " + x.out + ")", "111111111111  (config)",
		"me@x.com  (git config user.email)", "slack_teams (0):", "none known: set owned.slack_teams"} {
		if code != 0 || !strings.Contains(o, want) {
			t.Errorf("owned lacks %q: %q %q", want, o, e)
		}
	}
}
