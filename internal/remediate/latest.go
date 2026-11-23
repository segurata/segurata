package remediate

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// LatestDir is the most recent out/<YYYY-MM-DD> directory, where the last inventory wrote.
func LatestDir(outDir string) (string, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return "", err
	}
	var dates []string
	for _, e := range entries {
		if _, err := time.Parse("2006-01-02", e.Name()); e.IsDir() && err == nil {
			dates = append(dates, e.Name())
		}
	}
	if len(dates) == 0 {
		return "", fmt.Errorf("no inventory under %s: run `securizame inventory` first", outDir)
	}
	sort.Strings(dates)
	return filepath.Join(outDir, dates[len(dates)-1]), nil
}

// Load reads every finding in dir/*.jsonl, skipping status and log records.
func Load(dir string) ([]finding.Finding, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []finding.Finding
	for _, name := range files {
		got, err := loadFile(name)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

func loadFile(name string) ([]finding.Finding, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []finding.Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var rec finding.Finding
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if rec.Type == "finding" {
			out = append(out, rec)
		}
	}
	return out, sc.Err()
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
		return finding.Finding{}, fmt.Errorf("no finding %q in the latest run", id)
	case 1:
		return matches[0], nil
	}
	return finding.Finding{}, fmt.Errorf("%q matches %d findings: give more of the id", id, len(matches))
}

// Automatable returns the findings with a remediation action, worst first.
func Automatable(all []finding.Finding) []finding.Finding {
	var out []finding.Finding
	for _, f := range all {
		if f.Remediation.Action != "" {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}
