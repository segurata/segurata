// Package runtest writes synthetic connector outputs for tests: finished runs, whose run_end record
// is derived from their statuses the way run.Inventory derives it, and unfinished ones without it.
package runtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/statefile"
)

// Legacy, among Write's records, writes a run_end without a theme, as segurata wrote them before
// connectors declared themes and grouping.
type Legacy struct{}

// Fingerprints, among Write's records, are the secret fingerprints its run_end names.
type Fingerprints map[string]string

// Write writes one finished run to path. recs are findings and statuses, plus finding.Skipped for a
// declared skip, an error for a failed connector, Fingerprints, and the declared finding.Theme
// (ThemeOther by default, none with Legacy) and []finding.Area. The run counts as having inspected
// something; its times are the newest observed_at among the findings.
func Write(t testing.TB, path string, recs ...any) {
	t.Helper()
	var tally finding.Tally
	tally.Declare("", true, "")
	var err error
	var fps Fingerprints
	theme := finding.ThemeOther
	var covers []finding.Area
	var lines []any
	var at time.Time
	connector, instance := strings.TrimSuffix(filepath.Base(path), ".jsonl"), ""
	named := false
	name := func(c, i string) {
		if !named {
			connector, instance, named = c, i, true
		}
	}
	for _, r := range recs {
		switch r := r.(type) {
		case finding.Finding:
			name(r.Connector, r.Instance)
			if r.ObservedAt.After(at) {
				at = r.ObservedAt
			}
			lines = append(lines, r)
		case finding.Status:
			name(r.Connector, r.Instance)
			tally.Status(r)
			lines = append(lines, r)
		case finding.Skipped:
			tally.Declare(r.Scope, false, r.Reason)
		case error:
			err = errors.Join(err, r)
		case Fingerprints:
			fps = r
		case finding.Theme:
			theme = r
		case []finding.Area:
			covers = r
		case Legacy:
			theme = finding.Theme{}
		default:
			lines = append(lines, r)
		}
	}
	end := tally.End(connector, instance, at, at, err)
	end.SecretFingerprints, end.Theme, end.Covers = fps, theme, covers
	write(t, path, append(lines, end)...)
}

// WriteUnfinished writes recs to path without a run_end record.
func WriteUnfinished(t testing.TB, path string, recs ...any) {
	t.Helper()
	write(t, path, recs...)
}

func write(t testing.TB, path string, recs ...any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := statefile.Write(path, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}
