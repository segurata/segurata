// Package run executes connectors and writes their records to out/<date>/<connector>.jsonl.
package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secrets"
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
			return nil, fmt.Errorf("unknown connector or instance %q (see: securizame connectors)", sel)
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
	Err      error
}

// sink is the Emitter for one connector: it fills derived fields and appends to the JSONL file.
type sink struct {
	mu      sync.Mutex
	name    string
	label   string
	inst    string
	enc     *json.Encoder
	verbose io.Writer
	res     *Result
}

func (s *sink) Finding(f finding.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f.Connector, f.Instance = s.name, s.inst
	f.Fill(time.Now())
	s.res.Findings = append(s.res.Findings, f)
	_ = s.enc.Encode(f)
}

func (s *sink) Status(st finding.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st.Type, st.Connector, st.Instance = "status", s.name, s.inst
	s.res.Statuses = append(s.res.Statuses, st)
	_ = s.enc.Encode(st)
}

func (s *sink) Log(msg string) {
	if s.verbose != nil {
		fmt.Fprintf(s.verbose, "[%s] %s\n", s.label, msg)
	}
}

// Inventory runs the given targets concurrently and returns their results in input order.
func Inventory(ctx context.Context, cfg config.Config, targets []Target, outDir string, verbose io.Writer) ([]*Result, error) {
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
			results[i] = runOne(ctx, cfg, t, dir, verbose)
		}(i, t)
	}
	wg.Wait()
	return results, nil
}

func runOne(ctx context.Context, cfg config.Config, t Target, dir string, verbose io.Writer) *Result {
	name, label := t.Connector.Describe().Name, t.Label()
	res := &Result{Name: label, File: filepath.Join(dir, strings.ReplaceAll(label, ":", "-")+".jsonl")}
	// 0600: the output names accounts, apps and services.
	f, err := os.OpenFile(res.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		res.Err = err
		return res
	}
	defer f.Close()
	s := &sink{name: name, label: label, inst: t.Instance.Label, enc: json.NewEncoder(f), verbose: verbose, res: res}

	resolved, errs := secrets.ResolveAll(t.Instance.Secrets)
	for _, e := range errs {
		s.Status(finding.Status{State: finding.StateMissingCredentials, Detail: e.Error()})
	}
	req := connector.Request{Protocol: connector.ProtocolVersion, CDPURL: cfg.CDPURL, Config: t.Instance.Config, Secrets: resolved}
	res.Err = t.Connector.Inventory(ctx, req, s)
	return res
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
		all = append(all, r.Findings...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Severity.Rank() > all[j].Severity.Rank() })
	hidden := 0
	for _, f := range all {
		if f.Severity.Rank() < minSev.Rank() {
			hidden++
			continue
		}
		who := f.Connector
		if f.Instance != "" {
			who += ":" + f.Instance
		}
		fmt.Fprintf(w, "[%-8s] %-20s %s · %s\n", f.Severity, who, f.Account, f.Title)
	}
	fmt.Fprintf(w, "\n%d findings (%d below %s hidden).", len(all), hidden, minSev)
	for _, r := range results {
		fmt.Fprintf(w, " %s: %s", r.Name, r.File)
	}
	fmt.Fprintln(w)
}
