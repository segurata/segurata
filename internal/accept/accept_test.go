package accept

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/tracker"
)

var now = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

// debugPort is the finding the owner keeps on purpose.
func debugPort() finding.Finding {
	f := finding.Finding{Connector: "macos", Account: "Mac", Resource: finding.Resource{Type: "macos_setting", ID: "brave-remote-debugging"},
		Severity: finding.SevHigh, Title: "Brave runs with a remote debugging port", Remediation: finding.Remediation{Summary: "by hand"}}
	f.Fill(now)
	return f
}

func firewall() finding.Finding {
	f := finding.Finding{Connector: "macos", Account: "Mac", Resource: finding.Resource{Type: "macos_setting", ID: "firewall"},
		Severity: finding.SevMedium, Title: "The firewall is off", Remediation: finding.Remediation{Action: "macos.firewall.enable", Summary: "turn it on"}}
	f.Fill(now)
	return f
}

func TestAcceptValidatesAndReplaces(t *testing.T) {
	tr := tracker.New(now)
	f := debugPort()
	if _, err := tr.AcceptFinding(f, "  ", "", now); err == nil {
		t.Error("accepted without a reason")
	}
	if _, err := tr.AcceptFinding(f, "agents", "2026-13-01", now); err == nil {
		t.Error("accepted with a bad date")
	}
	if _, err := tr.AcceptFinding(f, "agents", "2026-11-23", now); err == nil {
		t.Error("accepted until yesterday")
	}
	if _, err := tr.AcceptFinding(f, "agents", "2026-11-24", now); err != nil {
		t.Errorf("today is still in force: %v", err)
	}
	if _, err := tr.AcceptFinding(f, "AI agents drive Brave", "", now); err != nil {
		t.Fatal(err)
	}
	items := tr.AcceptedItems()
	if len(items) != 1 || items[0].Accepted.Reason != "AI agents drive Brave" || items[0].Accepted.Until != "" || items[0].Title != f.Title ||
		items[0].Findings[0].Connector != "macos" || items[0].Status != tracker.Accepted {
		t.Fatalf("items %+v", items)
	}
}

func TestExpiryAndAnnotation(t *testing.T) {
	tr := tracker.New(now)
	f := debugPort()
	if _, err := tr.AcceptFinding(f, "agents", "2026-11-30", now); err != nil {
		t.Fatal(err)
	}
	at := now
	annotate := tr.Annotator(func() time.Time { return at })
	annotate(&f)
	if !f.Hidden() || f.Accepted.Reason != "agents" || f.Accepted.Until != "2026-11-30" || f.DisplayTitle() != f.Title {
		t.Fatalf("in force: %+v", f.Accepted)
	}
	at = time.Date(2026, 11, 30, 23, 59, 0, 0, time.UTC)
	if annotate(&f); !f.Hidden() {
		t.Fatal("expired on its last day")
	}
	at = at.Add(2 * time.Minute)
	annotate(&f)
	if f.Hidden() || !f.Accepted.Expired || !strings.HasSuffix(f.DisplayTitle(), "(acceptance expired)") {
		t.Fatalf("after its last day: %+v %q", f.Accepted, f.DisplayTitle())
	}
	other := firewall()
	other.Accepted = &finding.Acceptance{Reason: "stale, from an old run"}
	annotate(&other)
	if other.Accepted != nil {
		t.Fatal("the tracker is the source of truth: a finding it does not hold accepted must have the field cleared")
	}
}

func TestUnacceptByPrefix(t *testing.T) {
	tr := tracker.New(now)
	for _, id := range []string{"aaaa1111", "aaaa2222", "bbbb0000"} {
		f := debugPort()
		f.ID = id
		if _, err := tr.AcceptFinding(f, "kept", "", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tr.Unaccept("aaaa", now); err == nil {
		t.Error("ambiguous prefix removed something")
	}
	if _, err := tr.Unaccept("cc", now); err == nil {
		t.Error("unknown id removed something")
	}
	it, err := tr.Unaccept("bb", now)
	if err != nil || it.Findings[0].ID != "bbbb0000" || it.Status != tracker.Open || len(tr.AcceptedItems()) != 2 {
		t.Fatalf("%v %v %v", it, err, tr.AcceptedItems())
	}
}

func writeRun(t *testing.T, out string, fs ...finding.Finding) {
	t.Helper()
	dir := filepath.Join(out, now.Format(time.DateOnly))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, f := range fs {
		_ = enc.Encode(f)
	}
	if err := os.WriteFile(filepath.Join(dir, "macos.jsonl"), b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCommands(t *testing.T) {
	tmp := t.TempDir()
	out, state := filepath.Join(tmp, "out"), filepath.Join(tmp, "home", "tracker.json")
	dbg, fw := debugPort(), firewall()
	writeRun(t, out, dbg, fw)
	cli := func(cmd string, args ...string) (string, string, int) {
		var o, e bytes.Buffer
		c := CLI{Out: &o, Err: &e, Paths: tracker.Paths{Tracker: state}, Now: func() time.Time { return now }}
		code := c.Unaccept
		if cmd == "accept" {
			code = c.Accept
		}
		rc := code(args)
		return o.String(), e.String(), rc
	}
	if _, e, code := cli("accept", dbg.ID[:6], "--out", out); code != 1 || !strings.Contains(e, "--reason") {
		t.Errorf("accept without --reason: %d %q", code, e)
	}
	if _, _, code := cli("accept"); code != 2 {
		t.Errorf("accept without id: %d", code)
	}
	if _, e, code := cli("accept", "ffff", "--reason", "x", "--out", out); code != 1 || !strings.Contains(e, "no finding") {
		t.Errorf("unknown id: %d %q", code, e)
	}
	o, e, code := cli("accept", dbg.ID[:6], "--reason", "AI agents drive Brave", "--out", out)
	if code != 0 || !strings.Contains(o, "Accepted "+dbg.ID) || !strings.Contains(o, "no end date") {
		t.Fatalf("accept: %d %q %q", code, o, e)
	}
	if st, err := os.Stat(state); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v", err)
	}
	o, _, _ = cli("accept", "--list")
	if !strings.Contains(o, dbg.ID) || !strings.Contains(o, "reason: AI agents drive Brave") || !strings.Contains(o, "1 accepted findings") {
		t.Errorf("list:\n%s", o)
	}
	if _, _, code := cli("unaccept", dbg.ID[:4]); code != 0 {
		t.Fatal("unaccept failed")
	}
	if tr, _ := tracker.Load(state); len(tr.AcceptedItems()) != 0 {
		t.Fatalf("still accepted: %+v", tr.AcceptedItems())
	}
}

// emits is a connector that reports fixed findings.
type emits []finding.Finding

func (emits) Describe() connector.Description {
	return connector.Description{Name: "macos", Protocol: 1}
}
func (e emits) Inventory(_ context.Context, _ connector.Request, emit connector.Emitter) error {
	for _, f := range e {
		f.ID, f.Connector = "", ""
		emit.Finding(f)
	}
	return nil
}

func TestInventoryKeepsAcceptedFindingsInTheJSONLButHidesThemFromSummaryAndList(t *testing.T) {
	tr := tracker.New(now)
	dbg, fw := debugPort(), firewall()
	if _, err := tr.AcceptFinding(dbg, "AI agents drive Brave", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.AcceptFinding(fw, "old", "2026-11-24", now); err != nil {
		t.Fatal(err)
	}
	later := func() time.Time { return now.AddDate(0, 0, 2) } // the firewall acceptance has expired
	c := emits{dbg, fw}
	cfg := config.Config{}
	targets, err := run.Targets(cfg, []connector.Connector{c}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := run.Inventory(context.Background(), cfg, targets, t.TempDir(), nil, tr.Annotator(later))
	if err != nil || res[0].Err != nil {
		t.Fatal(err, res[0].Err)
	}
	raw, _ := os.ReadFile(res[0].File)
	if !strings.Contains(string(raw), `"accepted":{"reason":"AI agents drive Brave"`) || !strings.Contains(string(raw), `"expired":true`) {
		t.Fatalf("jsonl lacks the acceptance:\n%s", raw)
	}
	var sum bytes.Buffer
	run.Summary(&sum, res, finding.SevLow)
	got := sum.String()
	if strings.Contains(got, dbg.Title) || !strings.Contains(got, "1 accepted findings hidden; see securizame accept --list") ||
		!strings.Contains(got, fw.Title+" (acceptance expired)") {
		t.Errorf("summary:\n%s", got)
	}

	if _, err := tr.AcceptFinding(fw, "kept off on purpose", "", now); err != nil {
		t.Fatal(err)
	}
	all := []finding.Finding{dbg, fw}
	annotate := tr.Annotator(func() time.Time { return now })
	for i := range all {
		annotate(&all[i])
	}
	var list bytes.Buffer
	remediate.List(&list, all, finding.SevInfo)
	if strings.Contains(list.String(), fw.ID) || !strings.Contains(list.String(), "0 automatable findings") || !strings.Contains(list.String(), "1 accepted findings hidden") {
		t.Errorf("remediate --list:\n%s", list.String())
	}
}
