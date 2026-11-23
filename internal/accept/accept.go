// Package accept keeps the risks the owner accepts on purpose, such as a browser debugging port
// that local agents need. An accepted finding is still inventoried and written to the JSONL (with
// an "accepted" field) but left out of the summary and of `remediate --list` until its acceptance
// expires. State: ~/.config/securizame/accepted.json, mode 0600 (SECURIZAME_ACCEPTED names another
// file). See docs/architecture.md, "Accepted risks".
package accept

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/statefile"
)

// Entry is one accepted finding. Title is the finding's title when it was accepted, so the list
// still makes sense after the finding is gone.
type Entry struct {
	ID         string    `json:"id"`
	Connector  string    `json:"connector"`
	Title      string    `json:"title"`
	Reason     string    `json:"reason"`
	AcceptedAt time.Time `json:"accepted_at"`
	Until      string    `json:"until,omitempty"` // YYYY-MM-DD, last day the acceptance applies
}

// Expired reports whether now is past the entry's last day, in now's time zone.
func (e *Entry) Expired(now time.Time) bool {
	if e.Until == "" {
		return false
	}
	d, err := time.ParseInLocation(time.DateOnly, e.Until, now.Location())
	return err != nil || !now.Before(d.AddDate(0, 0, 1))
}

// Store is the whole accepted-risks file.
type Store struct {
	Version int      `json:"version"`
	Entries []*Entry `json:"entries"`
}

const version = 1

// DefaultPath is $SECURIZAME_ACCEPTED, or ~/.config/securizame/accepted.json next to the config.
func DefaultPath() (string, error) {
	if p := os.Getenv("SECURIZAME_ACCEPTED"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "securizame", "accepted.json"), nil
}

// Load reads the store; a missing file is an empty store. A broken file is an error rather than
// an empty store, so a typo never brings every accepted finding back silently, nor hides one.
func Load(path string) (*Store, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Store{Version: version}, nil
	}
	if err != nil {
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Version > version {
		return nil, fmt.Errorf("%s: version %d is newer than this binary (%d)", path, s.Version, version)
	}
	s.Version = version
	return &s, nil
}

// Save writes the store atomically with mode 0600.
func (s *Store) Save(path string) error {
	sort.Slice(s.Entries, func(i, j int) bool { return s.Entries[i].ID < s.Entries[j].ID })
	return statefile.WriteJSON(path, s)
}

func (s *Store) byID(id string) *Entry {
	for _, e := range s.Entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// Annotate sets f.Accepted from the store, replacing whatever the finding carried: the store is
// the only source of truth, so a finding loaded from an older run gets today's answer.
func (s *Store) Annotate(f *finding.Finding, now time.Time) {
	e := s.byID(f.ID)
	if e == nil {
		f.Accepted = nil
		return
	}
	f.Accepted = &finding.Acceptance{Reason: e.Reason, AcceptedAt: e.AcceptedAt, Until: e.Until, Expired: e.Expired(now)}
}

// Annotator returns Annotate as of the time now gives, for the inventory and remediate runs.
func (s *Store) Annotator(now func() time.Time) func(*finding.Finding) {
	return func(f *finding.Finding) { s.Annotate(f, now()) }
}

// Accept adds f, or replaces its earlier acceptance.
func (s *Store) Accept(f finding.Finding, reason, until string, now time.Time) (*Entry, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, errors.New("accept needs --reason (why this risk is kept on purpose)")
	}
	if until != "" {
		d, err := time.ParseInLocation(time.DateOnly, until, now.Location())
		if err != nil {
			return nil, fmt.Errorf("--until %q is not a date (YYYY-MM-DD)", until)
		}
		if !now.Before(d.AddDate(0, 0, 1)) {
			return nil, fmt.Errorf("--until %s is in the past", until)
		}
	}
	e := &Entry{ID: f.ID, Connector: f.Connector, Title: f.Title, Reason: reason, AcceptedAt: now.UTC(), Until: until}
	if old := s.byID(f.ID); old != nil {
		*old = *e
		return old, nil
	}
	s.Entries = append(s.Entries, e)
	return e, nil
}

// Unaccept removes the entry with that id, or the only one whose id starts with it.
func (s *Store) Unaccept(ref string) (*Entry, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("no finding id given")
	}
	idx := -1
	for i, e := range s.Entries {
		if e.ID == ref {
			idx = i
			break
		}
		if strings.HasPrefix(e.ID, ref) {
			if idx >= 0 {
				return nil, fmt.Errorf("%q matches several accepted findings: give more of the id", ref)
			}
			idx = i
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("no accepted finding %q (see securizame accept --list)", ref)
	}
	e := s.Entries[idx]
	s.Entries = append(s.Entries[:idx], s.Entries[idx+1:]...)
	return e, nil
}
