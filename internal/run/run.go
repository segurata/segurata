// Package run executes connectors and writes their records to out/<date>/<connector>.jsonl.
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secrets"
	"github.com/segurata/segurata/internal/textfmt"
)

// Target is one connector instance to run.
type Target struct {
	Connector connector.Connector
	Instance  config.Instance
}

// Label is "name" or "name:label", the same spelling as the config key.
func (t Target) Label() string {
	name := t.Connector.Describe().Name
	if t.Instance.Label == "" {
		return name
	}
	return name + ":" + t.Instance.Label
}

// Targets expands connectors into their configured instances. A selector "name" picks every
// instance of that connector, "name:label" just one; no selectors means everything.
func Targets(cfg config.Config, conns []connector.Connector, selectors []string) ([]Target, error) {
	var all []Target
	for _, c := range conns {
		for _, in := range cfg.Instances(c.Describe().Name) {
			all = append(all, Target{Connector: c, Instance: in})
		}
	}
	if len(selectors) == 0 {
		return all, nil
	}
	var out []Target
	for _, sel := range selectors {
		n := len(out)
		for _, t := range all {
			if sel == t.Connector.Describe().Name || sel == t.Label() {
				out = append(out, t)
			}
		}
		if len(out) == n {
			return nil, fmt.Errorf("unknown connector or instance %q (see: segurata connectors)", sel)
		}
	}
	return out, nil
}

// Result is what one connector instance produced in one run.
type Result struct {
	Name     string // target label
	File     string
	Findings []finding.Finding
	Statuses []finding.Status
	End      finding.RunEnd // the run_end record written last
	Err      error
}

// sink is the Emitter for one connector: it fills derived fields and appends to the JSONL file.
type sink struct {
	mu       sync.Mutex
	name     string
	label    string
	inst     string
	enc      *json.Encoder
	verbose  io.Writer
	annotate func(*finding.Finding)
	res      *Result
	tally    finding.Tally
}

func (s *sink) Finding(f finding.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f.Connector, f.Instance = s.name, s.inst
	f.Fill(time.Now())
	if s.annotate != nil {
		s.annotate(&f)
	}
	s.res.Findings = append(s.res.Findings, f)
	_ = s.enc.Encode(f)
}

func (s *sink) Status(st finding.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st.Type, st.Connector, st.Instance = "status", s.name, s.inst
	s.res.Statuses = append(s.res.Statuses, st)
	s.tally.Status(st)
	_ = s.enc.Encode(st)
}

// Scope records coverage in the run_end record only; it writes no line of its own.
func (s *sink) Scope(id string, inspected bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tally.Declare(id, inspected, reason)
}

// end writes the run_end record. err is the connector's own error; a cancelled context counts as
// one, since the connector may have stopped early without saying so.
func (s *sink) end(ctx context.Context, started time.Time, err error) {
	if err == nil && ctx.Err() != nil {
		err = fmt.Errorf("interrupted: %w", ctx.Err())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.res.End = s.tally.End(s.name, s.inst, started, time.Now(), err)
	_ = s.enc.Encode(s.res.End)
}

func (s *sink) Log(msg string) {
	if s.verbose != nil {
		fmt.Fprintf(s.verbose, "[%s] %s\n", s.label, msg)
	}
}

// Inventory runs the given targets concurrently and returns their results in input order. annotate,
// when set, stamps each finding before it is written (accepted risks).
func Inventory(ctx context.Context, cfg config.Config, targets []Target, outDir string, verbose io.Writer, annotate func(*finding.Finding)) ([]*Result, error) {
	dir := filepath.Join(outDir, time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	results := make([]*Result, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			results[i] = runOne(ctx, cfg, t, dir, verbose, annotate)
		}(i, t)
	}
	wg.Wait()
	return results, nil
}

func runOne(ctx context.Context, cfg config.Config, t Target, dir string, verbose io.Writer, annotate func(*finding.Finding)) *Result {
	name, label := t.Connector.Describe().Name, t.Label()
	started := time.Now()
	res := &Result{Name: label, File: filepath.Join(dir, strings.ReplaceAll(label, ":", "-")+".jsonl")}
	// The run writes to <file>.partial and renames it over <file> only once run_end is written, so
	// a killed run never truncates an earlier finished run of the same day. The partial file does
	// not match *.jsonl, so readers never pick it up. 0600: the output names accounts, apps and
	// services.
	partial := res.File + ".partial"
	f, err := os.OpenFile(partial, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		res.Err = err
		return res
	}
	s := &sink{name: name, label: label, inst: t.Instance.Label, enc: json.NewEncoder(f), verbose: verbose, annotate: annotate, res: res}

	req, errs := NewRequest(cfg, t.Instance)
	if missing := unresolved(t.Connector, errs, s); !missing {
		res.Err = t.Connector.Inventory(ctx, req, s)
	}
	s.end(ctx, started, res.Err)
	if err := f.Close(); err != nil {
		res.Err = errors.Join(res.Err, err)
		return res
	}
	if err := os.Rename(partial, res.File); err != nil {
		res.Err = errors.Join(res.Err, err)
	}
	return res
}

// unresolved reports each secret reference that could not be resolved as one missing_credentials
// status, with the connector's setup hint when it gives one, and says whether a secret the
// connector needs is among them: then Inventory is not called, so the connector cannot report the
// same problem again in its own words. The core owns unresolvable references; a connector still
// reports a secret that is not configured at all.
func unresolved(c connector.Connector, errs []error, emit connector.Emitter) bool {
	needs := c.Describe().Needs
	hinter, _ := c.(connector.SetupHinter)
	missing := false
	for _, e := range errs {
		detail := e.Error()
		var re *secrets.ResolveError
		if errors.As(e, &re) {
			if hinter != nil {
				if h := hinter.SetupHint(re.Key); h != "" {
					detail += "; " + h
				}
			}
			missing = missing || slices.Contains(needs, "secret:"+re.Key)
		}
		emit.Status(finding.Status{State: finding.StateMissingCredentials, Detail: detail})
	}
	return missing
}

// NewRequest builds the request for one connector instance, resolving its secret references.
// A secret that cannot be resolved is left out of the request and returned as an error.
func NewRequest(cfg config.Config, in config.Instance) (connector.Request, []error) {
	resolved, errs := secrets.ResolveAll(in.Secrets)
	return connector.Request{Protocol: connector.ProtocolVersion, CDPURL: cfg.CDPURL, Config: in.Config, Secrets: resolved}, errs
}

// InstanceRequest is NewRequest for the instance a finding came from (label "" is the unnamed one).
func InstanceRequest(cfg config.Config, name, label string) (connector.Request, []error) {
	for _, in := range cfg.Instances(name) {
		if in.Label == label {
			return NewRequest(cfg, in)
		}
	}
	return connector.Request{}, []error{fmt.Errorf("no configured instance %q of connector %s", label, name)}
}

// Summary prints statuses that need attention, then findings worst first.
func Summary(w io.Writer, results []*Result, minSev finding.Severity) {
	var all []finding.Finding
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(w, "! %s: %v\n", r.Name, r.Err)
		}
		for _, st := range r.Statuses {
			if st.State != finding.StateOK {
				fmt.Fprintf(w, "~ %s %s: %s %s\n", r.Name, st.Account, st.State, st.Detail)
			}
		}
		if sk := r.End.Scopes.Skipped; r.Err == nil && len(sk) > 0 {
			fmt.Fprintf(w, "~ %s: incomplete run, %d %s not inspected (first %s: %s); missing findings there are not resolved\n",
				r.Name, r.End.Scopes.SkippedCount, textfmt.Plural(r.End.Scopes.SkippedCount, "scope", "scopes"), sk[0].Scope, sk[0].Reason)
		}
		all = append(all, r.Findings...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Severity.Rank() > all[j].Severity.Rank() })
	hidden, accepted := 0, 0
	for _, f := range all {
		if f.Hidden() {
			accepted++
			continue
		}
		if f.Severity.Rank() < minSev.Rank() {
			hidden++
			continue
		}
		who := f.Connector
		if f.Instance != "" {
			who += ":" + f.Instance
		}
		fmt.Fprintf(w, "[%-8s] %-20s %s · %s\n", f.Severity, who, f.Account, f.DisplayTitle())
	}
	fmt.Fprintf(w, "\n%d findings (%d below %s hidden).", len(all), hidden, minSev)
	for _, r := range results {
		fmt.Fprintf(w, " %s: %s", r.Name, r.File)
	}
	fmt.Fprintln(w)
	if note := finding.HiddenNote(accepted); note != "" {
		fmt.Fprintln(w, note)
	}
}
