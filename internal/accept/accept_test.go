package accept

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fileacl/fileacltest"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/runtest"
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

func writeRun(t *testing.T, out string, fs ...finding.Finding) {
	t.Helper()
	recs := make([]any, len(fs))
	for i, f := range fs {
		recs[i] = f
	}
	runtest.Write(t, filepath.Join(out, now.Format(time.DateOnly), "macos.jsonl"), recs...)
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
	// A run dated after the clock's today was written while the clock was wrong: it is not the latest.
	future := firewall()
	future.ID, future.Resource.ID, future.Title = "", "future", "From a run dated tomorrow"
	future.Fill(now)
	runtest.Write(t, filepath.Join(out, now.AddDate(0, 0, 1).Format(time.DateOnly), "macos.jsonl"), future)
	if _, e, code := cli("accept", future.ID, "--reason", "x", "--out", out); code != 1 || !strings.Contains(e, "no finding") {
		t.Errorf("a finding from a future-dated run: %d %q", code, e)
	}
	o, e, code := cli("accept", dbg.ID[:6], "--reason", "AI agents drive Brave", "--out", out)
	if code != 0 || !strings.Contains(o, "Accepted "+dbg.ID) || !strings.Contains(o, "no end date") {
		t.Fatalf("accept: %d %q %q", code, o, e)
	}
	fileacltest.AssertPrivate(t, state)
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
	res, err := run.Inventory(context.Background(), cfg, targets, t.TempDir(), nil, run.Lent{Annotate: tr.Annotator(later)})
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
	if strings.Contains(got, dbg.Title) || !strings.Contains(got, "1 accepted findings hidden; see segurata accept --list") ||
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
