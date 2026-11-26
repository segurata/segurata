// Package run executes connectors and writes their records under out/<date>/.
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
	"sync"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fanout"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/runfile"
	"github.com/segurata/segurata/internal/secrets"
	"github.com/segurata/segurata/internal/textfmt"
)

// Target is one connector instance to run.
type Target struct {
	Connector connector.Connector
	Instance  config.Instance
}

const defaultTimeout = time.Hour

// Timeout bounds one inventory: the instance's config, else the connector's, else an hour.
func (t Target) Timeout() time.Duration {
	for _, d := range []time.Duration{t.Instance.RunTimeout(), t.Connector.Describe().RunTimeout()} {
		if d > 0 {
			return d
		}
	}
	return defaultTimeout
}

func (t Target) Label() string { return finding.Label(t.Connector.Describe().Name, t.Instance.Label) }

// Targets expands connectors into their configured instances, picked once each by selectors
// "name" (every instance) or "name:label"; no selectors means everything.
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
	End      finding.RunEnd
	Err      error
}

// sink is the Emitter for one connector: it fills derived fields and appends to the run file.
type sink struct {
	mu       sync.Mutex
	name     string
	label    string
	inst     string
	out      io.Writer
	verbose  io.Writer
	annotate func(*finding.Finding)
	tracker  connector.Tracker // nil for none
	theme    finding.Theme
	covers   []finding.Area
	expect   func(*finding.Status)
	res      *Result
	tally    finding.Tally
	werr     error // the first record that could not be written
}

// write appends one record as a JSON line, keeping the first failure for run_end: a run that lost
// a record must not look complete. Later records are still tried. The caller holds mu.
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
	// The core owns observed_at: a future one would make the tracker take later runs as older.
	now := time.Now()
	f.Connector, f.Instance, f.ObservedAt = s.name, s.inst, now.UTC()
	f.Fill(now)
	if s.annotate != nil {
		s.annotate(&f)
	}
	if f.Track == nil && s.tracker != nil {
		f.Track = s.tracker.Track(f)
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

func (s *sink) Scope(id string, inspected bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tally.Declare(id, inspected, reason)
}

// end writes the run_end record and reports whether it was written, with the first write error.
// A context that ended counts as an error: the connector may have stopped early without saying so.
func (s *sink) end(ctx context.Context, started time.Time, err error, fps map[string]string) (ended bool, werr error) {
	if ctx.Err() != nil {
		err = errors.Join(fmt.Errorf("interrupted: %w", context.Cause(ctx)), err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.res.End = s.tally.End(s.name, s.inst, started, time.Now(), errors.Join(err, s.werr))
	s.res.End.SecretFingerprints, s.res.End.Theme, s.res.End.Covers = fps, s.theme, s.covers
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
	Annotate func(*finding.Finding) // stamps accepted risks before a finding is written
	Known    *attribution.Known
}

// braveCheck is a variable so that no test reaches a real browser.
var braveCheck = cdp.Brave

const BrowserProbeTimeout = 15 * time.Second

// Why the browser connectors do not run, the start of their run_end error.
const (
	ReasonUnreachable = "browser not reachable over CDP"
	ReasonNotBrave    = "the browser on the debugging port is not Brave"
)

// BrowserProblem says why the browser connectors cannot run, "" when Brave answers at cdpURL. Only
// Brave is driven, and nothing is ever started in its place.
func BrowserProblem(ctx context.Context, cdpURL string, check func(context.Context, string) (cdp.Version, error)) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, BrowserProbeTimeout)
	defer cancel()
	_, err := check(ctx, cdpURL)
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, cdp.ErrNotBrave):
		return ReasonNotBrave, err
	}
	return ReasonUnreachable, err
}

// Inventory runs the targets concurrently, results in input order. Brave is checked once when a
// target drives it; without it those runs end at once with the reason, skipping every scope, so
// they prove neither a finding nor a status gone.
func Inventory(ctx context.Context, cfg config.Config, targets []Target, outDir string, verbose io.Writer, lent Lent) ([]*Result, error) {
	dir := filepath.Join(outDir, time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var noBrowser error
	if slices.ContainsFunc(targets, func(t Target) bool { return t.Connector.Describe().NeedsCDP() }) {
		if reason, err := BrowserProblem(ctx, cfg.CDPURL, braveCheck); reason != "" {
			noBrowser = fmt.Errorf("%s: %w", reason, err)
		}
	}
	results := make([]*Result, len(targets))
	fanout.Each(len(targets), 0, func(i int) {
		var refused error
		if targets[i].Connector.Describe().NeedsCDP() {
			refused = noBrowser
		}
		results[i] = runOne(ctx, cfg, targets[i], dir, verbose, lent, refused)
	})
	return results, nil
}

// runOne runs one target and writes its run file. A refused target resolves no secret.
func runOne(ctx context.Context, cfg config.Config, t Target, dir string, verbose io.Writer, lent Lent, refused error) *Result {
	name, label := t.Connector.Describe().Name, t.Label()
	timeout := t.Timeout()
	ctx, cancel := context.WithTimeoutCause(ctx, timeout, fmt.Errorf("timed out after %s (raise connectors.%s.timeout)", timeout, label))
	defer cancel()
	started := time.Now()
	res := &Result{Name: label, File: filepath.Join(dir, runfile.FileName(label))}
	// A partial file of its own, renamed over the run file once run_end is written, so a killed or
	// concurrent run never tears a finished one; readers skip it, and CreateTemp makes it 0600: the
	// output names accounts, apps and services.
	f, err := os.CreateTemp(dir, filepath.Base(res.File)+".*.partial")
	if err != nil {
		res.Err = err
		return res
	}
	partial := f.Name()
	d := t.Connector.Describe()
	s := &sink{name: name, label: label, inst: t.Instance.Label, out: f, verbose: verbose, annotate: lent.Annotate, expect: cfg.Expect, res: res,
		theme: finding.ThemeFor(d.Theme), covers: d.Covers}
	s.tracker, _ = t.Connector.(connector.Tracker)

	var req connector.Request
	if res.Err = refused; refused == nil {
		var errs []error
		req, errs = NewRequest(ctx, cfg, t.Instance)
		req.Known = lent.Known
		if missing := unresolved(t.Connector, errs, s); !missing {
			scrub := connector.NewScrubEmitter(s, req.Secrets)
			res.Err = scrub.Err(t.Connector.Inventory(ctx, req, scrub))
		}
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

// unresolved emits one missing_credentials status per unresolvable reference, with the setup
// hint, and reports whether a needed secret is among them: then Inventory is not called, so the
// problem is not reported twice. A secret not configured at all is the connector's to report.
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

// StatusSummary prints each result's error, statuses other than ok (expected ones counted by
// reason) and what an incomplete run left out.
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

// fingerprintKey is a variable so tests use their own key.
var fingerprintKey = fingerprint.OpenDefault

// secretFingerprints are run_end's finding.RunEnd.SecretFingerprints, nil without secrets or key.
func secretFingerprints(secrets map[string]string) map[string]string {
	if len(secrets) == 0 {
		return nil
	}
	k, ok := fingerprintKey()
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

// NewRequest builds an instance's request; a secret that cannot be resolved is left out and
// returned as an error.
func NewRequest(ctx context.Context, cfg config.Config, in config.Instance) (connector.Request, []error) {
	resolved, errs := secrets.ResolveAll(ctx, in.Secrets)
	return connector.Request{Protocol: connector.ProtocolVersion, CDPURL: cfg.CDPURL, Config: in.Config, Secrets: resolved}, errs
}

// InstanceCredentials are the connector.Credentials of one configured instance.
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
