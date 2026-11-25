// Package run executes connectors and writes their records to out/<date>/<connector>.jsonl.
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secrets"
	"github.com/segurata/segurata/internal/textfmt"
)

// Target is one connector instance to run.
type Target struct {
	Connector connector.Connector
	Instance  config.Instance
}

// DefaultTimeout bounds one inventory of an instance whose config and connector name no timeout.
const DefaultTimeout = time.Hour

// Timeout bounds one inventory of the target: the instance's config `timeout`, else the
// connector's declared default, else DefaultTimeout.
func (t Target) Timeout() time.Duration {
	for _, d := range []time.Duration{t.Instance.RunTimeout(), t.Connector.Describe().RunTimeout()} {
		if d > 0 {
			return d
		}
	}
	return DefaultTimeout
}

// Label is "name" or "name:label", the same spelling as the config key.
func (t Target) Label() string { return finding.Label(t.Connector.Describe().Name, t.Instance.Label) }

// FileName is the name of the run file of the connector instance label (see Target.Label) in its
// day's directory: "name.jsonl" or "name-label.jsonl".
func FileName(label string) string { return strings.ReplaceAll(label, ":", "-") + ".jsonl" }

// Targets expands connectors into their configured instances. A selector "name" picks every
// instance of that connector, "name:label" just one; no selectors means everything. Each instance
// appears once, however many selectors name it.
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
	picked := map[string]bool{}
	for _, sel := range selectors {
		matched := false
		for _, t := range all {
			if sel != t.Connector.Describe().Name && sel != t.Label() {
				continue
			}
			matched = true
			if !picked[t.Label()] {
				picked[t.Label()] = true
				out = append(out, t)
			}
		}
		if !matched {
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
	out      io.Writer
	verbose  io.Writer
	annotate func(*finding.Finding)
	expect   func(*finding.Status) // the config's expected rules
	res      *Result
	tally    finding.Tally
	werr     error // the first record that could not be written
}

// write appends one record as a JSON line. The first failure is kept for run_end: a run that lost
// a record must not count as complete, or the lost findings would look resolved. Unlike
// json.Encoder, which fails for good after one error, a later record is still tried, so run_end
// can say what was lost. The caller holds mu.
func (s *sink) write(v any) error {
	b, err := json.Marshal(v)
	if err == nil {
		_, err = s.out.Write(append(b, '\n'))
	}
	if err != nil && s.werr == nil {
		s.werr = fmt.Errorf("writing the run file: %w", err)
	}
	return err
}

func (s *sink) Finding(f finding.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The core owns observed_at: a connector's own value, a future one above all, would make the
	// tracker take every later run as older (see tracker.Sync).
	now := time.Now()
	f.Connector, f.Instance, f.ObservedAt = s.name, s.inst, now.UTC()
	f.Fill(now)
	if s.annotate != nil {
		s.annotate(&f)
	}
	s.res.Findings = append(s.res.Findings, f)
	_ = s.write(f)
}

func (s *sink) Status(st finding.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st.Type, st.Connector, st.Instance = "status", s.name, s.inst
	if s.expect != nil {
		s.expect(&st)
	}
	s.res.Statuses = append(s.res.Statuses, st)
	s.tally.Status(st)
	_ = s.write(st)
}

// Scope records coverage in the run_end record only; it writes no line of its own.
func (s *sink) Scope(id string, inspected bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tally.Declare(id, inspected, reason)
}

// end writes the run_end record and reports whether it was written, with the first write error.
// err is the connector's own error; a context that ended counts as one, with its cause (a
// timeout), since the connector may have stopped early without saying so, and so does a record
// that could not be written.
func (s *sink) end(ctx context.Context, started time.Time, err error, fps map[string]string) (ended bool, werr error) {
	if ctx.Err() != nil {
		err = errors.Join(fmt.Errorf("interrupted: %w", context.Cause(ctx)), err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.res.End = s.tally.End(s.name, s.inst, started, time.Now(), errors.Join(err, s.werr))
	s.res.End.SecretFingerprints = fps
	ended = s.write(s.res.End) == nil
	return ended, s.werr
}

func (s *sink) Log(msg string) {
	if s.verbose != nil {
		fmt.Fprintf(s.verbose, "[%s] %s\n", s.label, msg)
	}
}

// Lent is what the tracker lends an inventory; the zero value lends nothing.
type Lent struct {
	// Annotate stamps each finding before it is written (accepted risks).
	Annotate func(*finding.Finding)
	// Known says whose each secret is, for built-in connectors (connector.Request.Known).
	Known *attribution.Known
}

// Inventory runs the given targets concurrently and returns their results in input order.
func Inventory(ctx context.Context, cfg config.Config, targets []Target, outDir string, verbose io.Writer, lent Lent) ([]*Result, error) {
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
			results[i] = runOne(ctx, cfg, t, dir, verbose, lent)
		}(i, t)
	}
	wg.Wait()
	return results, nil
}

func runOne(ctx context.Context, cfg config.Config, t Target, dir string, verbose io.Writer, lent Lent) *Result {
	name, label := t.Connector.Describe().Name, t.Label()
	timeout := t.Timeout()
	ctx, cancel := context.WithTimeoutCause(ctx, timeout, fmt.Errorf("timed out after %s (raise connectors.%s.timeout)", timeout, label))
	defer cancel()
	started := time.Now()
	res := &Result{Name: label, File: filepath.Join(dir, FileName(label))}
	// The run writes to a partial file of its own and renames it over <file> only once run_end is
	// written, so a killed run never truncates an earlier finished run of the same day, and two runs
	// of the same instance at once never write into one file. The partial file does not match
	// *.jsonl, so readers never pick it up. CreateTemp makes it 0600: the output names accounts,
	// apps and services.
	f, err := os.CreateTemp(dir, filepath.Base(res.File)+".*.partial")
	if err != nil {
		res.Err = err
		return res
	}
	partial := f.Name()
	s := &sink{name: name, label: label, inst: t.Instance.Label, out: f, verbose: verbose, annotate: lent.Annotate, expect: cfg.Expect, res: res}

	req, errs := NewRequest(ctx, cfg, t.Instance)
	req.Known = lent.Known
	if missing := unresolved(t.Connector, errs, s); !missing {
		res.Err = t.Connector.Inventory(ctx, req, s)
	}
	ended, werr := s.end(ctx, started, res.Err, secretFingerprints(req.Secrets))
	res.Err = errors.Join(res.Err, werr)
	// A file without its run_end, or one that did not close, never replaces an earlier run.
	if err := f.Close(); err != nil || !ended {
		res.Err = errors.Join(res.Err, err)
		_ = os.Remove(partial)
		return res
	}
	if err := os.Rename(partial, res.File); err != nil {
		res.Err = errors.Join(res.Err, err)
		_ = os.Remove(partial)
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

// StatusSummary prints, per result, its error and the statuses that need attention: those other
// than ok, expected ones counted by reason, and the scopes an incomplete run left out.
func StatusSummary(w io.Writer, results []*Result) {
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(w, "! %s: %v\n", r.Name, r.Err)
		}
		expected := map[string]int{}
		for _, st := range r.Statuses {
			switch st.State {
			case finding.StateOK:
			case finding.StateExpected:
				expected[st.Expected]++
			default:
				fmt.Fprintf(w, "~ %s %s: %s %s\n", r.Name, st.Account, st.State, st.Detail)
			}
		}
		for _, reason := range slices.Sorted(maps.Keys(expected)) {
			fmt.Fprintf(w, "~ %s: %d expected (by your config: %s)\n", r.Name, expected[reason], reason)
		}
		if sk := r.End.Scopes.Skipped; r.Err == nil && len(sk) > 0 {
			fmt.Fprintf(w, "~ %s: incomplete run, %d %s not inspected (first %s: %s); missing findings there are not resolved\n",
				r.Name, r.End.Scopes.SkippedCount, textfmt.Plural(r.End.Scopes.SkippedCount, "scope", "scopes"), sk[0].Scope, sk[0].Reason)
		}
	}
}

// FingerprintKey is fingerprint.OpenDefault; a variable so tests use their own key.
var FingerprintKey = fingerprint.OpenDefault

// secretFingerprints fingerprints the resolved secrets by name, for run_end: the tracker matches
// them with leaked copies of the same values (see finding.RunEnd). nil without secrets or key.
func secretFingerprints(secrets map[string]string) map[string]string {
	if len(secrets) == 0 {
		return nil
	}
	k, ok := FingerprintKey()
	if !ok {
		return nil
	}
	out := map[string]string{}
	for name, v := range secrets {
		if fp := k.Of(v); fp != "" {
			out[name] = fp
		}
	}
	return out
}

// NewRequest builds the request for one connector instance, resolving its secret references under
// ctx. A secret that cannot be resolved is left out of the request and returned as an error.
func NewRequest(ctx context.Context, cfg config.Config, in config.Instance) (connector.Request, []error) {
	resolved, errs := secrets.ResolveAll(ctx, in.Secrets)
	return connector.Request{Protocol: connector.ProtocolVersion, CDPURL: cfg.CDPURL, Config: in.Config, Secrets: resolved}, errs
}

// InstanceCredentials are what a remediation of the instance a finding came from may use (label
// "" is the unnamed one): NewRequest, and the unresolved references of its remediation_secrets,
// which only Apply resolves.
func InstanceCredentials(ctx context.Context, cfg config.Config, name, label string) (connector.Credentials, []error) {
	for _, in := range cfg.Instances(name) {
		if in.Label == label {
			req, errs := NewRequest(ctx, cfg, in)
			return connector.Credentials{Request: req, WriteRefs: in.RemediationSecrets, Resolve: secrets.Resolve}, errs
		}
	}
	return connector.Credentials{}, []error{fmt.Errorf("no configured instance %q of connector %s", label, name)}
}

// Summary prints statuses that need attention, then findings worst first.
func Summary(w io.Writer, results []*Result, minSev finding.Severity) {
	StatusSummary(w, results)
	var all []finding.Finding
	for _, r := range results {
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
		fmt.Fprintf(w, "[%-8s] %-20s %s · %s\n", f.Severity, f.Selector(), f.Account, f.DisplayTitle())
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
