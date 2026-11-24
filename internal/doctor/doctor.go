// Package doctor checks, read-only, everything segurata needs before an inventory: the config
// and its secret references, the browser's debugging port for connectors that drive it, each
// connector's CLIs and sign-ins, and the modes of segurata's own state files. It prints OK, WARN
// or FAIL with the exact fix, and never a secret: references are resolved and the values dropped.
// See docs/architecture.md, "Doctor".
package doctor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/tracker"
)

// Env is everything doctor reads. The command fills it from the defaults; tests point it at a
// temporary home and inject fakes.
type Env struct {
	Out        io.Writer
	ConfigPath string
	KeyPath    string        // fingerprint key
	Tracker    tracker.Paths // tracker.json and the legacy files it imports once
	OutDir     string        // inventory output directory
	GOOS       string
	Connectors []connector.Connector
	// Request builds a connector request, resolving its secret references (run.NewRequest).
	Request func(config.Config, config.Instance) (connector.Request, []error)
	// CDPVersion reads the browser's /json/version (cdp.ReadVersion).
	CDPVersion func(ctx context.Context, url string) (cdp.Version, error)
	LookPath   func(string) (string, error)
}

// Result is one check about one subject: "config", "state", "cdp" or a connector instance.
type Result struct {
	Subject string
	connector.Check
}

const cdpTimeout = 5 * time.Second

// Run checks the connectors the selectors pick (all when none) and prints the results. It returns
// 1 when any check failed, 2 for an unknown selector, 0 otherwise.
func (e Env) Run(ctx context.Context, selectors []string) int {
	var results []Result
	add := func(subject string, checks ...connector.Check) {
		for _, c := range checks {
			results = append(results, Result{subject, c})
		}
	}
	cfg, checks, ok := e.config()
	add("config", checks...)
	if ok {
		targets, err := run.Targets(cfg, e.Connectors, selectors)
		if err != nil {
			fmt.Fprintln(e.Out, err)
			return 2
		}
		add("cdp", e.cdp(ctx, cfg, targets)...)
		for i, checks := range e.connectors(ctx, cfg, targets) {
			add(targets[i].Label(), checks...)
		}
	}
	add("state", e.state()...)
	return Print(e.Out, results)
}

// Print writes the results and a count, and returns 1 when any failed.
func Print(w io.Writer, results []Result) int {
	width := 0
	for _, r := range results {
		width = max(width, len(r.Subject))
	}
	counts := map[connector.Level]int{}
	for _, r := range results {
		counts[r.Level]++
		line := r.What
		if r.Detail != "" {
			line += ": " + r.Detail
		}
		fmt.Fprintf(w, "%-4s  %-*s  %s\n", r.Level, width, r.Subject, indent(line, width+8))
		if r.Fix != "" {
			fmt.Fprintf(w, "%*s  fix: %s\n", width+6, "", indent(r.Fix, width+13))
		}
	}
	fmt.Fprintf(w, "\n%d OK, %d WARN, %d FAIL\n", counts[connector.OK], counts[connector.Warn], counts[connector.Fail])
	if counts[connector.Fail] > 0 {
		return 1
	}
	return 0
}

func indent(s string, n int) string {
	return strings.ReplaceAll(s, "\n", "\n"+strings.Repeat(" ", n))
}

// config loads the config file; ok is false when it cannot be used at all.
func (e Env) config() (config.Config, []connector.Check, bool) {
	what := e.ConfigPath
	_, statErr := os.Stat(e.ConfigPath)
	cfg, err := config.Load(e.ConfigPath)
	if err != nil {
		return cfg, []connector.Check{{Level: connector.Fail, What: what, Detail: "invalid: " + err.Error(),
			Fix: "fix the file; format: docs/architecture.md, \"Secrets used by connectors\""}}, false
	}
	var checks []connector.Check
	if errors.Is(statErr, fs.ErrNotExist) {
		checks = append(checks, connector.Check{Level: connector.Warn, What: what, Detail: "not found: defaults apply and no connector has secrets",
			Fix: "create it (mode 0600); format: docs/architecture.md, \"Secrets used by connectors\""})
	} else {
		checks = append(checks, connector.Check{Level: connector.OK, What: what, Detail: fmt.Sprintf("valid, %d connector instance(s)", len(cfg.Connectors))})
	}
	names := map[string]bool{}
	for _, c := range e.Connectors {
		names[c.Describe().Name] = true
	}
	for _, key := range slices.Sorted(maps.Keys(cfg.Connectors)) {
		if name, _, _ := strings.Cut(key, ":"); !names[name] {
			checks = append(checks, connector.Check{Level: connector.Warn, What: "connectors." + key, Detail: "no connector is called " + name,
				Fix: "rename or remove it (see: segurata connectors)"})
		}
	}
	return cfg, checks, true
}

// cdp checks the browser's debugging port once, when a selected connector needs it.
func (e Env) cdp(ctx context.Context, cfg config.Config, targets []run.Target) []connector.Check {
	var users []string
	for _, t := range targets {
		if d := t.Connector.Describe(); d.NeedsCDP() && !slices.Contains(users, d.Name) {
			users = append(users, d.Name)
		}
	}
	if len(users) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, cdpTimeout)
	defer cancel()
	v, err := e.CDPVersion(ctx, cfg.CDPURL)
	needed := "needed by " + strings.Join(users, ", ")
	if err != nil {
		return []connector.Check{{Level: connector.Fail, What: cfg.CDPURL, Detail: "not reachable (" + needed + "): " + err.Error(),
			Fix: "start the browser with --remote-debugging-port=9222, or set cdp_url (or SEGURATA_CDP) to its address"}}
	}
	return []connector.Check{{Level: connector.OK, What: cfg.CDPURL, Detail: v.Browser + " (" + needed + "). Accepted-risk tradeoff: " +
		"while the port is open, any local process can drive the signed-in browser; keep it on 127.0.0.1 and see segurata accept"}}
}

// connectors checks every target at once and returns each target's checks in order.
func (e Env) connectors(ctx context.Context, cfg config.Config, targets []run.Target) [][]connector.Check {
	out := make([][]connector.Check, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = e.target(ctx, cfg, t)
		}()
	}
	wg.Wait()
	return out
}

func (e Env) target(ctx context.Context, cfg config.Config, t run.Target) []connector.Check {
	d := t.Connector.Describe()
	req, errs := e.Request(cfg, t.Instance)
	checks := secretChecks(t, req, errs)
	doctor, own := t.Connector.(connector.Doctor)
	for _, need := range d.Needs {
		kind, arg, _ := strings.Cut(need, ":")
		switch {
		case kind == "os":
			if !slices.Contains(strings.Split(arg, "|"), e.GOOS) {
				checks = append(checks, connector.Check{Level: connector.Warn, What: "platform", Detail: "runs on " + arg + " only; it reports unsupported on " + e.GOOS})
			}
		case own: // the connector checks its own CLIs and credentials
		case kind == "cli":
			checks = append(checks, e.cliNeed(arg))
		case kind == "secret":
			if _, set := t.Instance.Secrets[arg]; !set {
				checks = append(checks, connector.Check{Level: connector.Warn, What: "secret " + arg, Detail: "not configured: the connector is skipped",
					Fix: fmt.Sprintf(`add "secrets": {"%s": "keychain:%s"} to connectors.%s in the config, and the Keychain item`, arg, keychainService(d.Name, arg), t.Label())})
			}
		}
	}
	if own {
		checks = append(checks, doctor.Doctor(ctx, req)...)
	}
	if len(checks) == 0 {
		checks = append(checks, connector.Check{Level: connector.OK, What: "prerequisites", Detail: "nothing to check"})
	}
	return checks
}

// secretChecks reports each configured reference by key: resolved, or why not. Values never
// leave the request.
func secretChecks(t run.Target, req connector.Request, errs []error) []connector.Check {
	failed := map[string]string{}
	for _, err := range errs {
		key, why, _ := strings.Cut(err.Error(), ": ")
		failed[key] = why
	}
	var checks []connector.Check
	for _, k := range slices.Sorted(maps.Keys(t.Instance.Secrets)) {
		ref := t.Instance.Secrets[k]
		if why, bad := failed[k]; bad {
			checks = append(checks, connector.Check{Level: connector.Fail, What: "secret " + k, Detail: why,
				Fix: "make " + ref + " resolve, or change connectors." + t.Label() + ".secrets." + k})
			continue
		}
		if _, ok := req.Secrets[k]; ok {
			checks = append(checks, connector.Check{Level: connector.OK, What: "secret " + k, Detail: ref + " resolves"})
		}
	}
	return checks
}

// cliNeed checks a "cli:name" or "cli:name (optional)" need of a connector without a Doctor.
func (e Env) cliNeed(arg string) connector.Check {
	name, optional := strings.CutSuffix(arg, " (optional)")
	if path, err := e.LookPath(name); err == nil {
		return connector.Check{Level: connector.OK, What: name, Detail: path}
	}
	level := connector.Fail
	if optional {
		level = connector.Warn
	}
	return connector.Check{Level: level, What: name, Detail: "not found in PATH", Fix: "install " + name + ", respecting the 4-day quarantine"}
}

// state checks segurata's own files: present where needed, readable, closed to other users.
func (e Env) state() []connector.Check {
	var checks []connector.Check
	if _, err := fingerprint.Open(e.KeyPath); errors.Is(err, fs.ErrNotExist) {
		checks = append(checks, connector.Check{Level: connector.Warn, What: "fingerprint key " + e.KeyPath,
			Detail: "not created yet", Fix: "segurata inventory local-secrets creates it; back it up: losing it changes every fingerprint"})
	} else {
		checks = append(checks, fileCheck("fingerprint key", e.KeyPath, err, 0o600))
	}
	_, err := tracker.Load(e.Tracker.Tracker)
	checks = append(checks, optionalFile("tracker", e.Tracker.Tracker, err, 0o600, "segurata track sync creates it"))
	for _, legacy := range []string{e.Tracker.LegacyLedger, e.Tracker.LegacyAccepted} {
		if legacy == "" {
			continue
		}
		if _, err := os.Stat(legacy); err == nil {
			checks = append(checks, connector.Check{Level: connector.Warn, What: "old state file " + legacy,
				Detail: "not imported into the tracker yet", Fix: "segurata status imports it (the old file is kept as " + legacy + ".migrated-<date>)"})
		}
	}
	checks = append(checks, dirCheck("tracker dir", filepath.Dir(e.Tracker.Tracker), "the first command that saves the tracker creates it"))
	checks = append(checks, dirCheck("output dir", e.OutDir, "segurata inventory creates it"))
	return checks
}

func optionalFile(label, path string, loadErr error, want fs.FileMode, creator string) connector.Check {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return connector.Check{Level: connector.OK, What: label + " " + path, Detail: "none yet (" + creator + ")"}
	}
	return fileCheck(label, path, loadErr, want)
}

// fileCheck reports a state file that failed to load, or whose mode lets others read it.
func fileCheck(label, path string, loadErr error, want fs.FileMode) connector.Check {
	what := label + " " + path
	if loadErr != nil {
		return connector.Check{Level: connector.Fail, What: what, Detail: "unreadable: " + loadErr.Error(), Fix: "fix or restore " + path}
	}
	st, err := os.Stat(path)
	if err != nil {
		return connector.Check{Level: connector.Fail, What: what, Detail: err.Error(), Fix: "fix or restore " + path}
	}
	if mode := st.Mode().Perm(); mode != want {
		return connector.Check{Level: connector.Fail, What: what, Detail: fmt.Sprintf("mode %#o, want %#o", mode, want), Fix: fmt.Sprintf("chmod %o %s", want, path)}
	}
	return connector.Check{Level: connector.OK, What: what, Detail: fmt.Sprintf("readable, mode %#o", want)}
}

// dirCheck checks one of segurata's folders. Its files are 0600 already, so a looser folder is a
// warning: it only shows which files exist and when they changed.
func dirCheck(label, dir, creator string) connector.Check {
	what := label + " " + dir
	st, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return connector.Check{Level: connector.OK, What: what, Detail: "not created yet (" + creator + ", mode 0700)"}
	case err != nil:
		return connector.Check{Level: connector.Fail, What: what, Detail: err.Error(), Fix: "fix or remove " + dir}
	case !st.IsDir():
		return connector.Check{Level: connector.Fail, What: what, Detail: "not a directory", Fix: "move it away, or pass another --out"}
	case st.Mode().Perm() != 0o700:
		return connector.Check{Level: connector.Warn, What: what, Detail: fmt.Sprintf("mode %#o, want 0700", st.Mode().Perm()), Fix: "chmod 700 " + dir}
	}
	return connector.Check{Level: connector.OK, What: what, Detail: "mode 0700"}
}

// keychainService is the Keychain service name the connectors' own setup messages suggest:
// segurata-<connector>, with -admin for admin and management keys (OpenAI, Anthropic, OpenRouter).
func keychainService(connector, secret string) string {
	if strings.Contains(secret, "ADMIN") || strings.Contains(secret, "MANAGEMENT") {
		return "segurata-" + connector + "-admin"
	}
	return "segurata-" + connector
}
