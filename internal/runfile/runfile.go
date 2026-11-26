// Package runfile reads the run files a connector run leaves under out/<date>/: which run of each
// connector instance is the latest, what it holds, and which old ones can go.
package runfile

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// Latest is the run of one connector instance that consumers read.
type Latest struct {
	File string // out/<date>/<name>.jsonl
	// Prev is the run before File by the same rule, or "" when File is the first: nothing reads
	// it, Prune keeps it in case File proves unreadable.
	Prev string
	// Unfinished is a newer file without run_end that was passed over for File, or "".
	Unfinished string
	// Evidence is the newest finished run that inspected something, when File did not (the browser
	// was not reachable, the connector failed), or "". The report shows it in File's place and
	// Prune keeps it, so runs that inspected nothing never hide or delete the last real one.
	Evidence string
}

// FileName keeps run files in a distinct namespace from the old dash-joined names. Encoding
// the instance in lowercase hex preserves its case even on case-insensitive filesystems.
func FileName(label string) string {
	name, instance, _ := strings.Cut(label, ":")
	file := name + "@" + hex.EncodeToString([]byte(instance)) + ".jsonl"
	if len(file) <= 230 { // leave space for CreateTemp's suffix on 255-byte filesystems
		return file
	}
	digest := sha256.Sum256([]byte(label))
	return "@" + hex.EncodeToString(digest[:]) + ".jsonl"
}

// LatestRuns picks, for every connector instance, the newest out/<YYYY-MM-DD> run that finished
// (ends with a run_end record), so a run that was killed or is still running never stands in for
// the last good one. An instance with no finished run at all (only files from before run_end
// records) gets its newest file. Runs are per connector, so the newest day alone is not enough:
// after midnight it may hold only the connectors run since. Days after now's are left out (see
// History).
func LatestRuns(outDir string, now time.Time) ([]Latest, error) {
	history, err := History(outDir, now)
	if err != nil {
		return nil, err
	}
	var out []Latest
	for _, paths := range history {
		l, err := pick(paths)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}

// History lists every run file under out/<YYYY-MM-DD>/, by connector instance label,
// oldest first, leaving out days after now's: one written while the clock was wrong would stand
// in for every real run after it.
func History(outDir string, now time.Time) (map[string][]string, error) {
	entries, err := os.ReadDir(outDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no inventory under %s: run `segurata inventory` first", outDir)
	}
	if err != nil {
		return nil, err
	}
	today := now.Format(time.DateOnly)
	var dates []string
	for _, e := range entries {
		if _, err := time.Parse(time.DateOnly, e.Name()); e.IsDir() && err == nil && e.Name() <= today {
			dates = append(dates, e.Name())
		}
	}
	sort.Strings(dates)
	files := map[string][]string{}
	labels := map[string]string{}
	var orphans []string
	for _, d := range dates {
		day, err := filepath.Glob(filepath.Join(outDir, d, "*.jsonl"))
		if err != nil {
			return nil, err
		}
		files[d] = day
		for _, f := range day {
			if label, known := fileLabel(f); known {
				labels[f] = label
			} else {
				orphans = append(orphans, f)
			}
		}
	}
	adoptOrphans(labels, orphans)
	history := map[string][]string{}
	for _, d := range dates {
		day := map[string][]string{}
		for _, f := range files[d] {
			if label, ok := labels[f]; ok {
				day[label] = append(day[label], f)
			}
		}
		for label, paths := range day {
			// Old and new binaries can write the same instance on the same day. A tie
			// keeps the filename order from Glob, which puts the new name last.
			if len(paths) > 1 {
				times := make(map[string]time.Time, len(paths))
				for _, path := range paths {
					stat, err := os.Stat(path)
					if err != nil {
						return nil, err
					}
					times[path] = stat.ModTime()
					if end, err := endOf(path); err == nil && end != nil && !end.EndedAt.IsZero() {
						times[path] = end.EndedAt
					}
				}
				sort.SliceStable(paths, func(i, j int) bool { return times[paths[i]].Before(times[paths[j]]) })
			}
			history[label] = append(history[label], paths...)
		}
	}
	if len(history) == 0 {
		return nil, fmt.Errorf("no inventory under %s: run `segurata inventory` first", outDir)
	}
	return history, nil
}

// adoptOrphans files each legacy dash-joined file that holds no record (a run killed before its
// first) under the one instance its name can spell, by the stem itself or with the colon as a dash.
// One no instance claims is left out: it names nothing, and Prune deletes it once it is old.
func adoptOrphans(labels map[string]string, orphans []string) {
	known := map[string]bool{}
	for _, l := range labels {
		known[l] = true
	}
	for _, f := range orphans {
		stem := filenameLabel(f)
		if known[stem] {
			labels[f] = stem
			continue
		}
		var claims []string
		for l := range known {
			if strings.ReplaceAll(l, ":", "-") == stem {
				claims = append(claims, l)
			}
		}
		if len(claims) == 1 {
			labels[f] = claims[0]
		}
	}
}

func filenameLabel(file string) string {
	stem := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	if name, encoded, ok := strings.Cut(stem, "@"); ok && name != "" {
		if instance, err := hex.DecodeString(encoded); err == nil {
			return finding.Label(name, string(instance))
		}
	}
	return stem
}

// FileLabel returns the connector instance for a run file. Legacy filenames that merged the
// connector and instance with a dash can recover the identity from their records.
func FileLabel(file string) string {
	label, _ := fileLabel(file)
	return label
}

// fileLabel is FileLabel, and whether it is known: false for a legacy dash-joined or hashed file
// that holds no record, whose label is only its stem.
func fileLabel(file string) (string, bool) {
	stem := filenameLabel(file)
	base := strings.TrimSuffix(filepath.Base(file), ".jsonl")
	hashed := strings.HasPrefix(base, "@")
	if !hashed && (strings.Contains(base, "@") || !strings.Contains(base, "-")) {
		return stem, true
	}
	name, instance, records := firstIdentity(file)
	if name == "" {
		if end, err := endOf(file); err == nil && end != nil {
			name, instance, records = end.Connector, end.Instance, true
		}
	}
	label := finding.Label(name, instance)
	if name != "" && (hashed && FileName(label) == filepath.Base(file) ||
		instance != "" && name+"-"+instance == stem) {
		return label, true
	}
	return stem, records
}

// firstIdentity is the connector and instance the file's first record names, and whether it
// has one.
func firstIdentity(file string) (string, string, bool) {
	f, err := os.Open(file)
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4*1024), 16*1024*1024)
	if sc.Scan() {
		var first struct {
			Connector string `json:"connector"`
			Instance  string `json:"instance"`
		}
		if json.Unmarshal(sc.Bytes(), &first) == nil {
			return first.Connector, first.Instance, true
		}
	}
	return "", "", false
}

// Prune removes the run files of days before cutoff that no LatestRuns entry as of now needs (its
// File, Prev, Unfinished or Evidence), and partial files a killed run left in those days, then the days left
// empty. It touches nothing else under outDir, and nothing at all when the runs cannot be read. It
// returns what it removed.
func Prune(outDir string, now, cutoff time.Time) ([]string, error) {
	runs, err := LatestRuns(outDir, now)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, l := range runs {
		keep[l.File], keep[l.Prev], keep[l.Unfinished], keep[l.Evidence] = true, true, true, true
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return nil, err
	}
	last := cutoff.Format(time.DateOnly)
	var removed []string
	for _, e := range entries {
		if _, err := time.Parse(time.DateOnly, e.Name()); !e.IsDir() || err != nil || e.Name() >= last {
			continue
		}
		dir := filepath.Join(outDir, e.Name())
		files, err := os.ReadDir(dir)
		if err != nil {
			return removed, err
		}
		for _, f := range files {
			path := filepath.Join(dir, f.Name())
			own := strings.HasSuffix(f.Name(), ".jsonl") || strings.Contains(f.Name(), ".jsonl.") && strings.HasSuffix(f.Name(), ".partial")
			if !f.Type().IsRegular() || !own || keep[path] {
				continue
			}
			if err := os.Remove(path); err != nil {
				return removed, err
			}
			removed = append(removed, path)
		}
		_ = os.Remove(dir) // only when empty
	}
	return removed, nil
}

// pick applies the LatestRuns rule to one instance's files, oldest first.
func pick(paths []string) (Latest, error) {
	newest := func(paths []string) (string, error) { // newest finished, else newest
		for i := len(paths) - 1; i >= 0; i-- {
			done, err := Finished(paths[i])
			if err != nil {
				return "", err
			}
			if done {
				return paths[i], nil
			}
		}
		return paths[len(paths)-1], nil
	}
	file, err := newest(paths)
	if err != nil {
		return Latest{}, err
	}
	l := Latest{File: file}
	if last := paths[len(paths)-1]; last != file {
		l.Unfinished = last
	}
	i := slices.Index(paths, file)
	if i > 0 {
		if l.Prev, err = newest(paths[:i]); err != nil {
			return Latest{}, err
		}
	}
	for j := i; j >= 0; j-- {
		end, err := endOf(paths[j])
		if err != nil {
			return Latest{}, err
		}
		if _, none := finding.CoverageOf(end).NoneChecked(); end != nil && !none {
			if j < i {
				l.Evidence = paths[j]
			}
			break
		}
	}
	return l, nil
}

// LatestFiles is the File of every LatestRuns entry.
func LatestFiles(outDir string, now time.Time) ([]string, error) {
	runs, err := LatestRuns(outDir, now)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(runs))
	for i, r := range runs {
		out[i] = r.File
	}
	return out, nil
}

// maxTail bounds what Finished reads from the end of a file: a run_end record is a few KB.
const maxTail = 1 << 20

// Finished reports whether a run's output ends with a run_end record.
func Finished(name string) (bool, error) {
	end, err := endOf(name)
	return end != nil, err
}

// endOf reads the run_end record a run's output ends with, nil when it ends with another record.
func endOf(name string) (*finding.RunEnd, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	n := min(st.Size(), maxTail)
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, st.Size()-n); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	buf = bytes.TrimRight(buf, "\n")
	last := buf[bytes.LastIndexByte(buf, '\n')+1:]
	var end finding.RunEnd
	if json.Unmarshal(last, &end) != nil || end.Type != "run_end" {
		return nil, nil
	}
	return &end, nil
}

// Load reads every finding in the given files, skipping status and log records.
func Load(files []string) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, name := range files {
		got, err := Read(name)
		if err != nil {
			return nil, err
		}
		out = append(out, got.Findings...)
	}
	return out, nil
}

// Output is one connector instance's output, as read back from its run file.
type Output struct {
	Findings []finding.Finding
	Statuses []finding.Status
	End      *finding.RunEnd // nil: no run_end, so the run's completeness is unknown
}

// Coverage is what the run proves about each scope; see finding.Coverage.
func (r Output) Coverage() finding.Coverage { return finding.CoverageOf(r.End) }

// Label names the connector instance from the run's records, which carry the exact connector
// name and instance label; a run with none falls back to the name of its file.
func (r Output) Label(file string) string {
	switch {
	case r.End != nil:
		return finding.Label(r.End.Connector, r.End.Instance)
	case len(r.Findings) > 0:
		return finding.Label(r.Findings[0].Connector, r.Findings[0].Instance)
	case len(r.Statuses) > 0:
		return finding.Label(r.Statuses[0].Connector, r.Statuses[0].Instance)
	}
	return filenameLabel(file)
}

// Read reads one connector instance's output, skipping log records. A file without run_end
// may end in a half-written line (the run was killed mid-record): that line is dropped.
func Read(name string) (Output, error) {
	var r Output
	f, err := os.Open(name)
	if err != nil {
		return r, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var torn error // an unparseable line, fatal unless it turns out to be the last one
	for sc.Scan() {
		if torn != nil {
			return Output{}, torn
		}
		if err := r.decode(sc.Bytes()); err != nil {
			torn = fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := sc.Err(); err != nil {
		return Output{}, err
	}
	if torn != nil && r.End != nil {
		return Output{}, torn
	}
	return r, nil
}

func (r *Output) decode(line []byte) error {
	var head struct{ Type string }
	if err := json.Unmarshal(line, &head); err != nil {
		return err
	}
	switch head.Type {
	case "finding":
		var rec finding.Finding
		if err := json.Unmarshal(line, &rec); err != nil {
			return err
		}
		r.Findings = append(r.Findings, rec)
	case "status":
		var st finding.Status
		if err := json.Unmarshal(line, &st); err != nil {
			return err
		}
		r.Statuses = append(r.Statuses, st)
	case "run_end":
		var end finding.RunEnd
		if err := json.Unmarshal(line, &end); err != nil {
			return err
		}
		r.End = &end
	}
	return nil
}

// Find returns the finding with that id, or the only one whose id starts with it.
func Find(all []finding.Finding, id string) (finding.Finding, error) {
	if id == "" {
		return finding.Finding{}, errors.New("no finding id given")
	}
	var matches []finding.Finding
	for _, f := range all {
		if f.ID == id {
			return f, nil
		}
		if strings.HasPrefix(f.ID, id) {
			matches = append(matches, f)
		}
	}
	switch len(matches) {
	case 0:
		return finding.Finding{}, fmt.Errorf("no finding %q in the latest run of any connector", id)
	case 1:
		return matches[0], nil
	}
	return finding.Finding{}, fmt.Errorf("%q matches %d findings: give more of the id", id, len(matches))
}
