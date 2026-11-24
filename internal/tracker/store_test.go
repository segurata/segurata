package tracker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadRoundTripModesAndBackup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home")
	path := filepath.Join(dir, "tracker.json")
	tr := New(t0)
	if err := tr.Save(path); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]fs.FileMode{dir: 0o700, path: 0o600} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s: %v %v, want %o", p, err, st, want)
		}
	}
	if _, err := os.Stat(path + ".bak"); !errors.Is(err, fs.ErrNotExist) {
		t.Error("a first save has nothing to back up")
	}
	first, _ := os.ReadFile(path)

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	it, err := got.Find("T-1")
	if err != nil || it.Kind != KindDecide {
		t.Fatalf("T-1: %v %v", it, err)
	}
	if err := it.Note(t0, "first note"); err != nil {
		t.Fatal(err)
	}
	if err := got.Save(path); err != nil {
		t.Fatal(err)
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil || !bytes.Equal(bak, first) {
		t.Fatalf("the backup is not the previous version: %v", err)
	}
	if st, _ := os.Stat(path + ".bak"); st.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %o", st.Mode().Perm())
	}
	again, _ := Load(path)
	if again.Items[0].History[len(again.Items[0].History)-1].Detail != "first note" || len(again.Themes) != len(themes) {
		t.Error("round trip lost data")
	}
}

// Two commands that loaded the same tracker.json: the second save would silently drop the first
// one's change, so it is refused. The refused save leaves the file and its backup alone.
func TestSaveRefusesAFileChangedSinceItWasLoaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	if err := New(t0).Save(path); err != nil {
		t.Fatal(err)
	}
	a, _ := Load(path)
	b, _ := Load(path)
	_ = a.Items[0].Note(t0, "from a")
	if err := a.Save(path); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(path)
	bak, _ := os.ReadFile(path + ".bak")
	_ = b.Items[0].Note(t0, "from b")
	if err := b.Save(path); !errors.Is(err, ErrChanged) || !strings.Contains(err.Error(), "run it again") {
		t.Fatalf("stale save: %v", err)
	}
	if raw, _ := os.ReadFile(path); !bytes.Equal(raw, saved) {
		t.Error("the stale save overwrote the file")
	}
	if raw, _ := os.ReadFile(path + ".bak"); !bytes.Equal(raw, bak) {
		t.Error("the stale save replaced the backup")
	}
	// The command that saved can save again: its own write is what it last saw.
	_ = a.Items[0].Note(t0, "from a, again")
	if err := a.Save(path); err != nil {
		t.Errorf("second save of the same tracker: %v", err)
	}
	// A tracker made new because the file did not exist yet does not replace one created since.
	if err := New(t0).Save(path); !errors.Is(err, ErrChanged) {
		t.Errorf("new tracker over a file created since: %v", err)
	}
}

// Update loads the tracker fresh under the lock, so concurrent changes all land.
func TestUpdateSerializesConcurrentChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	const n = 8
	errs := make(chan error, n)
	for i := range n {
		go func() {
			errs <- Update(path, t0, func(tr *Tracker) error {
				return tr.Items[0].Note(t0, fmt.Sprintf("note %d", i))
			})
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	tr, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	notes := 0
	for _, e := range tr.Items[0].History {
		if e.Action == actNote {
			notes++
		}
	}
	if notes != n {
		t.Errorf("%d of %d notes kept", notes, n)
	}
	// fn's error leaves the file as it was.
	before, _ := os.ReadFile(path)
	if err := Update(path, t0, func(*Tracker) error { return errors.New("no") }); err == nil {
		t.Error("fn's error lost")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("saved after fn failed")
	}
}

func TestSaveRefusesToOverwriteAFileThatDoesNotParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	broken := []byte(`{"schema_version": 1, "items": [` + "\n")
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), ".bak") {
		t.Fatalf("a broken file loaded: %v", err)
	}
	if err := New(t0).Save(path); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("overwrote a broken file: %v", err)
	}
	if raw, _ := os.ReadFile(path); !bytes.Equal(raw, broken) {
		t.Error("the broken file changed")
	}
	if _, err := os.Stat(path + ".bak"); !errors.Is(err, fs.ErrNotExist) {
		t.Error("a broken file must not replace the last good backup")
	}
}

func TestLoadValidates(t *testing.T) {
	good := New(t0)
	good.AddDecision("decide:second", "A second question?", []string{"yes", "no"}, t0) // the cases need two items
	raw, _ := json.Marshal(good)
	cases := map[string]func(m map[string]any){
		"newer schema":  func(m map[string]any) { m["schema_version"] = 99 },
		"no schema":     func(m map[string]any) { delete(m, "schema_version") },
		"unknown field": func(m map[string]any) { m["surprise"] = true },
		"duplicate id":  func(m map[string]any) { it := m["items"].([]any); it[1].(map[string]any)["id"] = "T-0001" },
		"duplicate key": func(m map[string]any) {
			it := m["items"].([]any)
			it[1].(map[string]any)["key"] = it[0].(map[string]any)["key"]
		},
		"id over next_id":   func(m map[string]any) { m["next_id"] = 2 },
		"bad status":        func(m map[string]any) { m["items"].([]any)[0].(map[string]any)["status"] = "maybe" },
		"bad kind":          func(m map[string]any) { m["items"].([]any)[0].(map[string]any)["kind"] = "wish" },
		"decision missing":  func(m map[string]any) { delete(m["items"].([]any)[0].(map[string]any), "decision") },
		"malformed item id": func(m map[string]any) { m["items"].([]any)[0].(map[string]any)["id"] = "X-1" },
	}
	for name, mutate := range cases {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		mutate(m)
		b, _ := json.Marshal(m)
		if _, err := parse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parse(raw); err != nil {
		t.Fatalf("a good tracker: %v", err)
	}
}

func TestPaths(t *testing.T) {
	t.Setenv("SEGURATA_HOME", "/h")
	t.Setenv("SEGURATA_STATE", "/s")
	t.Setenv("SEGURATA_ACCEPTED", "/a.json")
	p, err := Paths{}.Resolve()
	if err != nil || p.Tracker != "/h/tracker.json" || p.LegacyLedger != "/s/rotations.json" || p.LegacyAccepted != "/a.json" {
		t.Errorf("default paths %+v %v", p, err)
	}
	t.Setenv("SEGURATA_STATE", "")
	if p, err := (Paths{}).Resolve(); err != nil || p.LegacyLedger != "/h/rotations.json" {
		t.Errorf("without SEGURATA_STATE the old ledger is read from the tracker directory: %+v %v", p, err)
	}
	if p, _ := (Paths{Tracker: "/x/tracker.json"}).Resolve(); p.LegacyLedger != "" || p.LegacyAccepted != "" {
		t.Errorf("a tracker path alone must never reach the owner's old files: %+v", p)
	}
}

func TestLoadOrMigrateWithNothingIsANewTrackerNotYetWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	tr, err := LoadOrMigrate(Paths{Tracker: path}, t0, nil)
	if err != nil || len(tr.Items) != len(seedDecisions) {
		t.Fatalf("%v %d items", err, len(tr.Items))
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Error("opening wrote the tracker")
	}
}

func TestRetireNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rotations.json")
	for i := 0; i < 2; i++ {
		_ = os.WriteFile(p, []byte("x"), 0o600)
		if _, err := retire(p, t0); err != nil {
			t.Fatal(err)
		}
	}
	names, _ := filepath.Glob(filepath.Join(dir, "rotations.json.migrated-*"))
	if len(names) != 2 || !strings.HasSuffix(names[0], "2026-11-23") && !strings.HasSuffix(names[1], "2026-11-23") {
		t.Errorf("retired files %v", names)
	}
}

// A tracker of an older schema, as a previous binary wrote it, loads with every field intact and
// is saved as the current schema; an older binary then refuses the file instead of misreading new
// fields.
func TestOlderSchemasUpgradeLosslessly(t *testing.T) {
	for v := 1; v < SchemaVersion; v++ {
		t.Run(fmt.Sprintf("schema %d", v), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tracker.json")
			tr := New(t0)
			tr.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "anthropic", "~/.zshrc", "scan", "config", "644", false, false))}, t0, false)
			it, _ := tr.FindRotate("aaaa")
			if err := it.Ignore(t0, "a fixture"); err != nil {
				t.Fatal(err)
			}
			tr.SchemaVersion = v
			old, err := json.MarshalIndent(tr, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, old, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if got.SchemaVersion != SchemaVersion {
				t.Errorf("schema %d after load", got.SchemaVersion)
			}
			got.SchemaVersion = v
			again, _ := json.MarshalIndent(got, "", "  ")
			if !bytes.Equal(again, old) {
				t.Errorf("the upgrade changed data:\n%s\n---\n%s", old, again)
			}
			if err := got.Save(path); err != nil {
				t.Fatal(err)
			}
			var head struct {
				SchemaVersion int `json:"schema_version"`
			}
			raw, _ := os.ReadFile(path)
			if _ = json.Unmarshal(raw, &head); head.SchemaVersion != SchemaVersion {
				t.Errorf("saved as schema %d", head.SchemaVersion)
			}
			if bak, _ := os.ReadFile(path + ".bak"); !bytes.Equal(bak, old) {
				t.Errorf("the schema %d file is not kept as the backup", v)
			}
		})
	}
}
