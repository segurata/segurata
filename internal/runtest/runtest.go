// Package runtest writes synthetic connector outputs for tests: finished runs, whose run_end record
// is derived from their statuses the way run.Inventory derives it, and unfinished ones without it.
package runtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// Legacy, among Write's records, writes a run_end without a theme, as segurata wrote them before
// connectors declared themes and grouping.
type Legacy struct{}

// Fingerprints, among Write's records, are the secret fingerprints its run_end names.
type Fingerprints map[string]string

// Write writes one finished run to path. recs are finding.Finding and finding.Status records, plus
// finding.Skipped for a scope the connector declared skipped, an error for a connector that
// failed, Fingerprints for the secrets the core resolved, and a finding.Theme and []finding.Area
// for the theme and areas the connector declared. The theme is finding.ThemeOther when none is
// given, as the core writes it for a connector that declares none, and none at all with Legacy, a
// run written before connectors declared themes. The run counts as having inspected something, so only statuses, skips and
// errors make it incomplete. Its times are the newest observed_at among the findings.
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

// WriteUnfinished writes recs to path without a run_end record: a run that was killed, is still
// running, or predates run_end records.
func WriteUnfinished(t testing.TB, path string, recs ...any) {
	t.Helper()
	write(t, path, recs...)
}

func write(t testing.TB, path string, recs ...any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
