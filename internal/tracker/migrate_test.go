package tracker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// legacyFixture writes a rotations.json and an accepted.json in their former formats: an open, a
// rotated (with rotated locations and a history-only note), a snoozed and an ignored secret, and
// one accepted risk with an end date.
func legacyFixture(t *testing.T) (ledger, accepted string) {
	t.Helper()
	dir := t.TempDir()
	day := func(d int) time.Time { return t0.AddDate(0, 0, d) }
	loc := func(path, source, kind string) map[string]any {
		return map[string]any{"path": path, "line": 3, "bucket": "3-local", "tracked": false, "mode": "600", "source": source, "kind": kind, "last_seen": day(0)}
	}
	item := func(id, status, prio string, first time.Time, history []map[string]any, extra map[string]any) map[string]any {
		m := map[string]any{"id": id, "fingerprint": id + "0123456789abcdef"[:16-len(id)], "service": "stripe", "type": "stripe-live",
			"redacted": "sk_live_…" + id[:4] + "(107)", "impact": "high", "priority": prio, "reasons": []string{"reason of " + id},
			"status": status, "first_seen": first, "last_seen": day(0), "locations": []map[string]any{loc("~/src/"+id+"/.env", "scan", "repo")},
			"used_in": []string{"~/src/" + id + "/.env"}, "rotate_url": "https://dashboard.stripe.com/apikeys", "history": history}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	ev := func(at time.Time, action, note string) map[string]any {
		return map[string]any{"at": at, "action": action, "note": note}
	}
	items := []map[string]any{
		item("dddd0004", "ignored", "P1", day(-1), []map[string]any{ev(day(-1), "found", "found in 1 place"), ev(day(0), "ignore", "test fixture")}, nil),
		item("aaaa0001", "open", "P0", day(-9), []map[string]any{ev(day(-9), "found", "found in 2 places"), ev(day(-8), "next", ""),
			ev(day(-7), "redacted", "redacted from 3 trail files")}, nil),
		item("bbbb0002", "rotated", "P1", day(-5), []map[string]any{ev(day(-5), "found", "found in 1 place"), ev(day(-4), "done", "rolled"),
			ev(day(-3), "history-only", "old value still in history")}, map[string]any{"rotated_locations": []string{"scan:~/src/bbbb0002/.env"}}),
		item("cccc0003", "snoozed", "P2", day(-2), []map[string]any{ev(day(-2), "found", "found in 1 place"), ev(day(-1), "snooze", "until 2027-01-01 later")},
			map[string]any{"snoozed_until": "2027-01-01"}),
	}
	ledger = filepath.Join(dir, "state", "rotations.json")
	accepted = filepath.Join(dir, "config", "accepted.json")
	writeJSONFile(t, ledger, map[string]any{"version": 1, "items": items})
	writeJSONFile(t, accepted, map[string]any{"version": 1, "entries": []map[string]any{{"id": "5c7ae3818002130e", "connector": "macos",
		"title": "Brave runs with a remote debugging port", "reason": "AI agents drive Brave", "accepted_at": day(-1), "until": "2027-03-31"}}})
	return ledger, accepted
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	raw, _ := json.MarshalIndent(v, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationImportsEverythingAndRetiresTheOldFiles(t *testing.T) {
	ledger, accepted := legacyFixture(t)
	path := filepath.Join(t.TempDir(), "home", "tracker.json")
	paths := Paths{Tracker: path, LegacyLedger: ledger, LegacyAccepted: accepted}
	var note bytes.Buffer
	tr, err := LoadOrMigrate(paths, t0, &note)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note.String(), "Imported 4 rotation items and 1 accepted risks") {
		t.Errorf("notice %q", note.String())
	}
	for _, old := range []string{ledger, accepted} {
		if _, err := os.Stat(old); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s not renamed", old)
		}
		if _, err := os.Stat(old + ".migrated-2026-11-23"); err != nil {
			t.Errorf("%s: %v", old, err)
		}
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("tracker: %v", err)
	}

	// Ids follow first sighting, after the seeded decisions.
	want := []struct {
		short  string
		status Status
		prio   string
	}{{"aaaa0001", Open, "P0"}, {"bbbb0002", Done, "P1"}, {"cccc0003", Snoozed, "P2"}, {"dddd0004", Ignored, "P1"}}
	for i, w := range want {
		it, err := tr.FindRotate(w.short)
		if err != nil {
			t.Fatal(err)
		}
		if it.ID != formatID(len(seedDecisions)+i+1) || it.Status != w.status || string(it.Priority) != w.prio || it.Key != "rotate:"+it.Fingerprint {
			t.Errorf("%s: %s %s %s %s", w.short, it.ID, it.Status, it.Priority, it.Key)
		}
		if it.Secret.Reasons[0] != "reason of "+w.short || it.Secret.UsedIn[0] != "~/src/"+w.short+"/.env" || it.Theme != "rotations" {
			t.Errorf("%s: stored values not kept: %+v", w.short, it.Secret)
		}
	}
	open, _ := tr.FindRotate("aaaa0001")
	var actions []string
	for _, e := range open.History {
		actions = append(actions, e.Event+"/"+e.Action+"/"+e.Detail)
	}
	if strings.Join(actions, "|") != "found/found/found in 2 places|note/next/|note/redacted/redacted from 3 trail files" {
		t.Errorf("history %v", actions)
	}
	if !open.History[2].At.Equal(t0.AddDate(0, 0, -7)) {
		t.Errorf("event time %v", open.History[2].At)
	}
	rotated, _ := tr.FindRotate("bbbb0002")
	if strings.Join(rotated.Secret.RotatedLocations, ",") != "scan:~/src/bbbb0002/.env" || !rotated.StatusAt.Equal(t0.AddDate(0, 0, -4)) || !rotated.notedHistoryOnly() {
		t.Errorf("rotated item %+v", rotated)
	}
	snoozed, _ := tr.FindRotate("cccc0003")
	if snoozed.SnoozedUntil != "2027-01-01" {
		t.Errorf("snooze %q", snoozed.SnoozedUntil)
	}
	acc := tr.AcceptedItems()
	if len(acc) != 1 || acc[0].Status != Accepted || acc[0].Accepted.Until != "2027-03-31" || acc[0].Findings[0].ID != "5c7ae3818002130e" ||
		acc[0].Theme != "mac" || acc[0].Key != pinnedKey("5c7ae3818002130e") {
		t.Fatalf("accepted %+v", acc)
	}

	// Once imported, the tracker is the source of truth: a second open does not import again.
	writeJSONFile(t, ledger, map[string]any{"version": 1, "items": []any{}})
	again, err := LoadOrMigrate(paths, t0.Add(time.Hour), nil)
	if err != nil || len(again.Items) != len(tr.Items) {
		t.Fatalf("reopened: %v %d", err, len(again.Items))
	}
	if _, err := os.Stat(ledger); err != nil {
		t.Error("a file left after the import must stay where it is")
	}
}

func TestMigrationRefusesBrokenOrNewerFilesAndLeavesThemAlone(t *testing.T) {
	ledger, accepted := legacyFixture(t)
	path := filepath.Join(t.TempDir(), "tracker.json")
	for _, body := range []string{`{"version": 1, "items": [`, `{"version": 7, "items": []}`, `{"version": 1, "items": [{"id": "x", "fingerprint": "y", "status": "pending"}]}`} {
		_ = os.WriteFile(ledger, []byte(body), 0o600)
		if _, err := LoadOrMigrate(Paths{Tracker: path, LegacyLedger: ledger, LegacyAccepted: accepted}, t0, nil); err == nil {
			t.Errorf("imported %s", body)
		}
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("a failed import wrote the tracker")
		}
		if _, err := os.Stat(ledger); err != nil {
			t.Fatal("a failed import moved the old file")
		}
	}
}
