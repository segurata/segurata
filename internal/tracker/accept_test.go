package tracker

import (
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// debugPort is a finding the owner keeps on purpose.
func debugPort(now time.Time) finding.Finding {
	return fnd("macos", "", "Mac", "macos_setting", "brave-remote-debugging", "", finding.SevHigh, "Brave runs with a remote debugging port", now)
}

func TestAcceptValidatesAndReplaces(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	tr := New(now)
	f := debugPort(now)
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
		items[0].Findings[0].Connector != "macos" || items[0].Status != Accepted {
		t.Fatalf("items %+v", items)
	}
}

func TestExpiryAndAnnotation(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	tr := New(now)
	f := debugPort(now)
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
	other := fnd("macos", "", "Mac", "macos_setting", "firewall", "", finding.SevMedium, "The firewall is off", now)
	other.Accepted = &finding.Acceptance{Reason: "stale, from an old run"}
	annotate(&other)
	if other.Accepted != nil {
		t.Fatal("the tracker is the source of truth: a finding it does not hold accepted must have the field cleared")
	}
}

func TestUnacceptByPrefix(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	tr := New(now)
	for _, id := range []string{"aaaa1111", "aaaa2222", "bbbb0000"} {
		f := debugPort(now)
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
	if err != nil || it.Findings[0].ID != "bbbb0000" || it.Status != Open || len(tr.AcceptedItems()) != 2 {
		t.Fatalf("%v %v %v", it, err, tr.AcceptedItems())
	}
}
