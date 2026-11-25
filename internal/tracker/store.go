package tracker

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/segurata/segurata/internal/config"

	"github.com/segurata/segurata/internal/statefile"
)

// Paths says where the tracker lives.
type Paths struct {
	Tracker string // tracker.json
}

// Dir is $SEGURATA_HOME, or ~/.segurata: the tracker and its generated views.
func Dir() (string, error) { return config.StateDir() }

// DefaultPaths is the tracker in Dir.
func DefaultPaths() (Paths, error) {
	dir, err := Dir()
	if err != nil {
		return Paths{}, err
	}
	return Paths{Tracker: filepath.Join(dir, "tracker.json")}, nil
}

// Resolve returns p, or DefaultPaths when p names no tracker.
func (p Paths) Resolve() (Paths, error) {
	if p.Tracker != "" {
		return p, nil
	}
	return DefaultPaths()
}

// New is an empty tracker with the seeded themes and decisions.
func New(now time.Time) *Tracker {
	t := &Tracker{SchemaVersion: SchemaVersion, NextID: 1}
	t.seed(now)
	return t
}

// LoadOrNew loads the tracker, or returns a new one when tracker.json does not exist yet (saved by
// the first command that changes it).
func LoadOrNew(p Paths, now time.Time) (*Tracker, error) {
	p, err := p.Resolve()
	if err != nil {
		return nil, err
	}
	t, err := Load(p.Tracker)
	if errors.Is(err, fs.ErrNotExist) {
		return New(now), nil
	}
	return t, err
}

// LoadFor resolves p and loads the tracker (LoadOrNew). With lock it first takes the tracker lock,
// held until unlock, for a command that saves what it loaded. unlock is never nil.
func LoadFor(p Paths, now time.Time, lock bool) (t *Tracker, path string, unlock func(), err error) {
	unlock = func() {}
	if p, err = p.Resolve(); err != nil {
		return nil, "", unlock, err
	}
	if lock {
		if unlock, err = Lock(p.Tracker); err != nil {
			return nil, "", func() {}, err
		}
	}
	t, err = LoadOrNew(p, now)
	return t, p.Tracker, unlock, err
}

// Load reads and validates tracker.json. A missing file is fs.ErrNotExist; a file that does not
// parse or validate is an error, never an empty tracker, so nothing is lost by a later save. The
// tracker remembers the bytes it was read from, so Save can tell when another command saved since.
func Load(path string) (*Tracker, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t, err := parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (fix it or restore %s.bak)", path, err, path)
	}
	t.read = digest(raw)
	return t, nil
}

func digest(raw []byte) *[sha256.Size]byte {
	d := sha256.Sum256(raw)
	return &d
}

// ErrChanged is Save refusing a tracker.json that changed after this tracker was loaded: writing
// it would drop the other command's change.
var ErrChanged = errors.New("changed since this command loaded it")

// Update loads the tracker at path (a new one when there is none yet), applies fn and saves it,
// holding the tracker lock throughout, so commands that change the tracker one after another never
// lose each other's change. fn's error leaves the file alone. Commands that hold the tracker for
// long (a confirmation, file rewrites) do that work first and record its outcome with Update.
func Update(path string, now time.Time, fn func(*Tracker) error) error {
	unlock, err := Lock(path)
	if err != nil {
		return err
	}
	defer unlock()
	t, err := LoadOrNew(Paths{Tracker: path}, now)
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		return err
	}
	return t.Save(path)
}

// upgrades turns a tracker of schema version n into n+1, on the raw JSON. Each future format
// change adds one entry; Load applies them in order before decoding.
var upgrades = map[int]func(map[string]any) error{
	// 2 adds the statuses reclassified and expected, the top-level rules and decision effects. A
	// version 1 file holds none of them, so its data carries over as it is; the bump keeps an older
	// binary from loading a file with values it does not know.
	1: func(map[string]any) error { return nil },
	// 3 adds the top-level owned, a rotate item's secret.attribution and a rule's owners; a version 2
	// file has none, so it carries over as it is.
	2: func(map[string]any) error { return nil },
	// 4 adds the status merged with an item's merged_into, a finding ref's type, resource and match,
	// and the top-level runs; a version 3 file has none, so it carries over as it is.
	3: func(map[string]any) error { return nil },
	// 5 adds a location's gone; a version 4 file has none, so it carries over as it is.
	4: func(map[string]any) error { return nil },
	// 6 adds a secret's liveness, the history action dead, and attribution facts'
	// github_logins; a version 5 file has none, so it carries over as it is.
	5: func(map[string]any) error { return nil },
}

func parse(raw []byte) (*Tracker, error) {
	var head struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}
	switch v := head.SchemaVersion; {
	case v > SchemaVersion:
		return nil, fmt.Errorf("schema_version %d is newer than this binary (%d)", v, SchemaVersion)
	case v < 1:
		return nil, fmt.Errorf("schema_version %d is not a tracker", v)
	case v < SchemaVersion:
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		for ; v < SchemaVersion; v++ {
			if err := upgrades[v](m); err != nil {
				return nil, fmt.Errorf("upgrading from schema_version %d: %w", v, err)
			}
			m["schema_version"] = v + 1
		}
		var err error
		if raw, err = json.Marshal(m); err != nil {
			return nil, err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var t Tracker
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	return &t, t.validate()
}

var idRe = regexp.MustCompile(`^T-(\d{4,})$`)

func idNumber(id string) int {
	m := idRe.FindStringSubmatch(id)
	if m == nil {
		return -1
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func formatID(n int) string { return fmt.Sprintf("T-%04d", n) }

func (t *Tracker) validate() error {
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, it := range t.Items {
		n := idNumber(it.ID)
		switch {
		case n < 1:
			return fmt.Errorf("item id %q is not T-<number>", it.ID)
		case ids[it.ID]:
			return fmt.Errorf("item id %s appears twice", it.ID)
		case n >= t.NextID:
			return fmt.Errorf("item %s is not below next_id %d", it.ID, t.NextID)
		case it.Key == "":
			return fmt.Errorf("item %s has no key", it.ID)
		case keys[it.Key]:
			return fmt.Errorf("item key %q appears twice", it.Key)
		case !slices.Contains(kinds, it.Kind):
			return fmt.Errorf("item %s: unknown kind %q", it.ID, it.Kind)
		case !slices.Contains(statuses, it.Status):
			return fmt.Errorf("item %s: unknown status %q", it.ID, it.Status)
		case it.Kind == KindRotate && (it.Secret == nil || it.Fingerprint == ""):
			return fmt.Errorf("rotate item %s has no secret or fingerprint", it.ID)
		case it.Kind == KindDecide && it.Decision == nil:
			return fmt.Errorf("decide item %s has no decision", it.ID)
		case it.Status == Merged && it.MergedInto == "":
			return fmt.Errorf("merged item %s does not say which item it merged into", it.ID)
		}
		ids[it.ID], keys[it.Key] = true, true
	}
	for i, r := range t.Rules {
		if err := r.validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

// Save writes the tracker atomically with mode 0600 in a 0700 directory, after copying the file it
// replaces to tracker.json.bak. It refuses to replace a file that no longer parses (edited by hand,
// or by another program): that file may hold the only copy of something. It refuses with
// ErrChanged a file other than the one this tracker was loaded from or last saved (another command
// saved since, or the file appeared after a new tracker was made): saving would lose that change.
func (t *Tracker) Save(path string) error {
	if err := t.validate(); err != nil {
		return fmt.Errorf("not saving an invalid tracker: %w", err)
	}
	old, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		if _, perr := parse(old); perr != nil {
			return fmt.Errorf("refusing to overwrite %s: it does not parse (%v); fix it or restore %s.bak", path, perr, path)
		}
		if t.read == nil || *digest(old) != *t.read {
			return fmt.Errorf("%s %w (another segurata command, or an edit, saved it); nothing was written, run it again", path, ErrChanged)
		}
		if err := statefile.Write(path+".bak", old); err != nil {
			return fmt.Errorf("backing up %s: %w", path, err)
		}
	}
	sort.SliceStable(t.Items, func(i, j int) bool { return idNumber(t.Items[i].ID) < idNumber(t.Items[j].ID) })
	t.SchemaVersion = SchemaVersion
	raw, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := statefile.Write(path, raw); err != nil {
		return err
	}
	t.read = digest(raw)
	return nil
}
