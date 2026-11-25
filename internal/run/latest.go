package run

import (
	"bufio"
	"bytes"
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

// History lists every run file under out/<YYYY-MM-DD>/, by file name (one connector instance),
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
	history := map[string][]string{}
	for _, d := range dates {
		files, err := filepath.Glob(filepath.Join(outDir, d, "*.jsonl"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			history[filepath.Base(f)] = append(history[filepath.Base(f)], f)
		}
	}
	if len(history) == 0 {
		return nil, fmt.Errorf("no inventory under %s: run `segurata inventory` first", outDir)
	}
	return history, nil
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

// ReadRun reads one connector instance's output, skipping log records. A file without run_end
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
