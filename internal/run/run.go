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
	"sync"
	"time"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secrets"
)

// Result is what one connector produced in one run.
type Result struct {
	Name     string
	File     string
	Findings []finding.Finding
	Statuses []finding.Status
	Err      error
}

// sink is the Emitter for one connector: it fills derived fields and appends to the JSONL file.
type sink struct {
	mu      sync.Mutex
	name    string
	enc     *json.Encoder
	verbose io.Writer
	res     *Result
}

func (s *sink) Finding(f finding.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f.Connector = s.name
	f.Fill(time.Now())
	s.res.Findings = append(s.res.Findings, f)
	_ = s.enc.Encode(f)
}

func (s *sink) Status(st finding.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st.Type, st.Connector = "status", s.name
	s.res.Statuses = append(s.res.Statuses, st)
	_ = s.enc.Encode(st)
}

func (s *sink) Log(msg string) {
	if s.verbose != nil {
		fmt.Fprintf(s.verbose, "[%s] %s\n", s.name, msg)
	}
}

// Inventory runs the given connectors concurrently and returns their results in input order.
func Inventory(ctx context.Context, cfg config.Config, conns []connector.Connector, outDir string, verbose io.Writer) ([]*Result, error) {
	dir := filepath.Join(outDir, time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	results := make([]*Result, len(conns))
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c connector.Connector) {
			defer wg.Done()
			results[i] = runOne(ctx, cfg, c, dir, verbose)
		}(i, c)
	}
	wg.Wait()
	return results, nil
}

func runOne(ctx context.Context, cfg config.Config, c connector.Connector, dir string, verbose io.Writer) *Result {
	name := c.Describe().Name
	res := &Result{Name: name, File: filepath.Join(dir, name+".jsonl")}
	// 0600: the output names accounts, apps and services.
	f, err := os.OpenFile(res.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		res.Err = err
		return res
	}
	defer f.Close()
	s := &sink{name: name, enc: json.NewEncoder(f), verbose: verbose, res: res}

	cc := cfg.Connectors[name]
	resolved, errs := secrets.ResolveAll(cc.Secrets)
	for _, e := range errs {
		s.Status(finding.Status{State: finding.StateMissingCredentials, Detail: e.Error()})
	}
	req := connector.Request{Protocol: connector.ProtocolVersion, CDPURL: cfg.CDPURL, Config: cc.Config, Secrets: resolved}
	res.Err = c.Inventory(ctx, req, s)
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
		fmt.Fprintf(w, "[%-8s] %-16s %s · %s\n", f.Severity, f.Connector, f.Account, f.Title)
	}
	fmt.Fprintf(w, "\n%d findings (%d below %s hidden).", len(all), hidden, minSev)
	for _, r := range results {
		fmt.Fprintf(w, " %s: %s", r.Name, r.File)
	}
	fmt.Fprintln(w)
}
