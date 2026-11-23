// Package rotation keeps the ledger of secrets to rotate: one item per secret fingerprint, with
// its priority, the plain-words reasons behind it, every place it was found, the files where the
// new value has to go, the provider page where it is rotated, and its history. The ledger lives
// outside the repository, at ~/.local/state/securizame/rotations.json (mode 0600), and holds no
// secret values: only redacted hints and fingerprints. See docs/architecture.md, "Rotation ledger".
package rotation

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

	"github.com/segurata/segurata/internal/secretrisk"
)

type Status string

const (
	Open    Status = "open"
	Rotated Status = "rotated"
	Snoozed Status = "snoozed"
	Ignored Status = "ignored"
)

// History actions.
const (
	actFound      = "found"
	actDone       = "done"
	actSnooze     = "snooze"
	actIgnore     = "ignore"
	actReopen     = "reopen"
	actAutoReopen = "auto-reopen"
	actWake       = "snooze-expired"
)

// stillPresent is the reason given when a rotated secret shows up again with the same value.
const stillPresent = "still present after rotation (old value not removed)"

// Location is one place the secret was found.
type Location struct {
	Path     string    `json:"path"`
	Line     int       `json:"line,omitempty"`
	Bucket   string    `json:"bucket"`
	Tracked  bool      `json:"tracked"`
	Mode     string    `json:"mode,omitempty"`
	Source   string    `json:"source"` // scan | gitleaks | name | ssh
	Kind     string    `json:"kind"`   // config | repo | transcript | history | log
	Remote   bool      `json:"remote,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

func (l Location) key() string { return l.Source + "\x00" + l.Path }

func (l Location) spot() secretrisk.Spot {
	return secretrisk.Where(l.Source, l.Kind, l.Mode, l.Tracked, l.Remote)
}

type Event struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Note   string    `json:"note,omitempty"`
}

// Item is one secret to rotate.
type Item struct {
	ID           string              `json:"id"`
	Fingerprint  string              `json:"fingerprint"`
	Service      string              `json:"service"`
	Type         string              `json:"type"`
	Redacted     string              `json:"redacted"`
	Impact       string              `json:"impact"`
	Priority     secretrisk.Priority `json:"priority"`
	Reasons      []string            `json:"reasons"`
	Status       Status              `json:"status"`
	SnoozedUntil string              `json:"snoozed_until,omitempty"`
	FirstSeen    time.Time           `json:"first_seen"`
	LastSeen     time.Time           `json:"last_seen"`
	Locations    []Location          `json:"locations"`
	UsedIn       []string            `json:"used_in"`
	RotateURL    string              `json:"rotate_url,omitempty"`
	History      []Event             `json:"history"`
}

// Ledger is the whole state file.
type Ledger struct {
	Version int     `json:"version"`
	Items   []*Item `json:"items"`
}

const version = 1

// DefaultPath is $SECURIZAME_STATE/rotations.json, or ~/.local/state/securizame/rotations.json.
func DefaultPath() (string, error) {
	dir := os.Getenv("SECURIZAME_STATE")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "state", "securizame")
	}
	return filepath.Join(dir, "rotations.json"), nil
}

// Load reads the ledger; a missing file is an empty ledger.
func Load(path string) (*Ledger, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Ledger{Version: version}, nil
	}
	if err != nil {
		return nil, err
	}
	var l Ledger
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if l.Version > version {
		return nil, fmt.Errorf("%s: ledger version %d is newer than this binary (%d)", path, l.Version, version)
	}
	l.Version = version
	return &l, nil
}

// Save writes the ledger atomically with mode 0600, in a 0700 directory.
func (l *Ledger) Save(path string) error {
	sort.Slice(l.Items, func(i, j int) bool { return l.Items[i].ID < l.Items[j].ID })
	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".rotations-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Find resolves an id, or a unique prefix of an id or a fingerprint.
func (l *Ledger) Find(ref string) (*Item, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("missing item id")
	}
	var hits []*Item
	for _, it := range l.Items {
		if it.ID == ref {
			return it, nil
		}
		if strings.HasPrefix(it.ID, ref) || strings.HasPrefix(it.Fingerprint, ref) {
			hits = append(hits, it)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("no item %q (see: securizame rotations list --all)", ref)
	case 1:
		return hits[0], nil
	}
	return nil, fmt.Errorf("%q matches %d items, use more characters", ref, len(hits))
}

func (l *Ledger) byFingerprint() map[string]*Item {
	m := make(map[string]*Item, len(l.Items))
	for _, it := range l.Items {
		m[it.Fingerprint] = it
	}
	return m
}

// newID is the shortest prefix of the fingerprint, from 8 characters, no other item uses.
func (l *Ledger) newID(fp string) string {
	used := map[string]bool{}
	for _, it := range l.Items {
		used[it.ID] = true
	}
	for n := 8; n < len(fp); n++ {
		if !used[fp[:n]] {
			return fp[:n]
		}
	}
	return fp
}

func (it *Item) log(at time.Time, action, note string) {
	it.History = append(it.History, Event{At: at.UTC(), Action: action, Note: note})
}

// Done marks the item rotated.
func (it *Item) Done(at time.Time, note string) {
	it.Status, it.SnoozedUntil = Rotated, ""
	it.log(at, actDone, note)
	it.refresh()
}

// Snooze hides the item until a date (YYYY-MM-DD).
func (it *Item) Snooze(at time.Time, until, note string) error {
	d, err := time.Parse(time.DateOnly, until)
	if err != nil {
		return fmt.Errorf("--until %q is not a date (YYYY-MM-DD)", until)
	}
	if !d.After(at) {
		return fmt.Errorf("--until %s is not in the future", until)
	}
	it.Status, it.SnoozedUntil = Snoozed, until
	it.log(at, actSnooze, strings.TrimSpace("until "+until+" "+note))
	return nil
}

// Ignore drops the item from the open list, for false positives.
func (it *Item) Ignore(at time.Time, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("ignore needs --reason (why this is not a secret to rotate)")
	}
	it.Status, it.SnoozedUntil = Ignored, ""
	it.log(at, actIgnore, reason)
	return nil
}

// Reopen puts the item back on the open list.
func (it *Item) Reopen(at time.Time, note string) {
	it.Status, it.SnoozedUntil = Open, ""
	it.log(at, actReopen, note)
	it.refresh()
}

// Active reports whether the item belongs on the default list: open, or snoozed past its date.
func (it *Item) Active(today time.Time) bool {
	switch it.Status {
	case Open:
		return true
	case Snoozed:
		d, err := time.Parse(time.DateOnly, it.SnoozedUntil)
		return err != nil || !today.Before(d)
	}
	return false
}

// worst is the location that exposed the secret the most.
func (it *Item) worst() (secretrisk.Spot, bool) {
	var best secretrisk.Spot
	found := false
	for _, l := range it.Locations {
		s := l.spot()
		if !found || spotRank(s) > spotRank(best) {
			best, found = s, true
		}
	}
	return best, found
}

// spotOrder breaks ties between spots of the same exposure level.
var spotOrder = map[string]int{"git+remote": 7, "transcript": 6, "git": 5, "readable": 4, "history": 3, "log": 2, "local": 1}

func spotRank(s secretrisk.Spot) int { return int(s.Level)*10 + spotOrder[s.Label] }

// WorstLabel is the short label of the worst exposure, for tables.
func (it *Item) WorstLabel() string {
	s, _ := it.worst()
	return s.Label
}

func impactByName(name string) secretrisk.Impact {
	for i := secretrisk.Noise; i <= secretrisk.High; i++ {
		if i.String() == name {
			return i
		}
	}
	return secretrisk.Medium
}

// refresh recomputes everything derived: priority, reasons, used_in, rotate_url.
func (it *Item) refresh() {
	t := secretrisk.Lookup(it.Type)
	it.Service, it.RotateURL = t.Service, t.RotateURL
	worst, ok := it.worst()
	it.Priority = ""
	if ok {
		it.Priority = secretrisk.PriorityOf(impactByName(it.Impact), worst.Level)
	}
	var reasons []string
	if it.reopenedStillPresent() {
		reasons = append(reasons, stillPresent)
	}
	if ok {
		reasons = append(reasons, secretrisk.Reason(t, worst))
		counts := map[string]int{}
		phrase := map[string]string{}
		for _, l := range it.Locations {
			s := l.spot()
			counts[s.Label]++
			phrase[s.Label] = s.Phrase
		}
		labels := make([]string, 0, len(counts))
		for lb := range counts {
			labels = append(labels, lb)
		}
		sort.Slice(labels, func(i, j int) bool { return spotOrder[labels[i]] > spotOrder[labels[j]] })
		for _, lb := range labels {
			n := counts[lb]
			if lb == worst.Label {
				n--
			}
			if n > 0 {
				reasons = append(reasons, fmt.Sprintf("also %s (%d %s)", phrase[lb], n, plural(n, "place", "places")))
			}
		}
	}
	it.Reasons = reasons
	seen := map[string]bool{}
	it.UsedIn = []string{}
	for _, l := range it.Locations {
		if l.Source != "gitleaks" && (l.Kind == "config" || l.Kind == "repo") && !seen[l.Path] {
			seen[l.Path] = true
			it.UsedIn = append(it.UsedIn, l.Path)
		}
	}
	sort.Strings(it.UsedIn)
}

// reopenedStillPresent: the last done/auto-reopen event is an automatic reopen.
func (it *Item) reopenedStillPresent() bool {
	for i := len(it.History) - 1; i >= 0; i-- {
		switch it.History[i].Action {
		case actAutoReopen:
			return it.Status != Rotated
		case actDone, actReopen:
			return false
		}
	}
	return false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Sort orders items by priority, then worst exposure, then service and id.
func Sort(items []*Item) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Priority.Rank() != b.Priority.Rank() {
			return a.Priority.Rank() < b.Priority.Rank()
		}
		wa, _ := a.worst()
		wb, _ := b.worst()
		if spotRank(wa) != spotRank(wb) {
			return spotRank(wa) > spotRank(wb)
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.ID < b.ID
	})
}
