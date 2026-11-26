// Package doctor checks, read-only, what an inventory needs: the config and its secret references,
// the browser's debugging port, each connector's CLIs and sign-ins, and the modes of segurata's
// state files. It prints the exact fix, never a secret. See docs/architecture.md, "Doctor".
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
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fanout"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/keychain"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/secrets"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

type Env struct {
	Out        io.Writer
	ConfigPath string
	KeyPath    string // fingerprint key
	Tracker    tracker.Paths
	OutDir     string
	GOOS       string
	Connectors []connector.Connector
	Request    func(context.Context, config.Config, config.Instance) (connector.Request, []error) // run.NewRequest
	CDPVersion func(ctx context.Context, url string) (cdp.Version, error)                         // cdp.ReadVersion
	LookPath   func(string) (string, error)
}

// result is one check about one subject: "config", "state", "cdp" or a connector instance.
type result struct {
	Subject string
	connector.Check
}

const cdpTimeout = 5 * time.Second

// Run checks the connectors the selectors pick (all when none) and prints the results. It returns
// 1 when any check failed, 2 for an unknown selector, 0 otherwise.
func (e Env) Run(ctx context.Context, selectors []string) int {
	var results []result
	add := func(subject string, checks ...connector.Check) {
		for _, c := range checks {
			results = append(results, result{subject, c})
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
	return printResults(e.Out, results)
}

// printResults writes the results and a count, and returns 1 when any failed.
func printResults(w io.Writer, results []result) int {
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
	fanout.Each(len(targets), 0, func(i int) { out[i] = e.target(ctx, cfg, targets[i]) })
	return out
}

func (e Env) target(ctx context.Context, cfg config.Config, t run.Target) []connector.Check {
	d := t.Connector.Describe()
	req, errs := e.Request(ctx, cfg, t.Instance)
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
					Fix: keychainFix(d.Name, arg, t.Label(), keychain.Available)})
			}
		}
	}
	if own {
		checks = append(checks, doctor.Doctor(ctx, req)...)
	}
	if len(checks) == 0 {
		checks = append(checks, connector.Check{Level: connector.OK, What: "prerequisites", Detail: "nothing to check"})
	}
	connector.ScrubChecks(checks, req.Secrets)
	return checks
}

// secretChecks reports each configured reference by key: resolved, or why not.
func secretChecks(t run.Target, req connector.Request, errs []error) []connector.Check {
	failed := map[string]string{}
	for _, err := range errs {
		if re, ok := errors.AsType[*secrets.ResolveError](err); ok {
			failed[re.Key] = re.Err.Error()
		}
	}
	var checks []connector.Check
	for _, k := range slices.Sorted(maps.Keys(t.Instance.Secrets)) {
		ref := t.Instance.Secrets[k]
		if why, bad := failed[k]; bad {
			checks = append(checks, connector.Check{Level: connector.Fail, What: "secret " + k, Detail: why,
				Fix: "check connectors." + t.Label() + ".secrets." + k + " and use a working env:, keychain: or op:// reference"})
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
	return connector.Check{Level: level, What: name, Detail: "not found in PATH", Fix: "install " + name}
}

// state checks segurata's own files: present where needed, readable, closed to other users.
func (e Env) state() []connector.Check {
	var checks []connector.Check
	if _, err := fingerprint.Open(e.KeyPath); errors.Is(err, fs.ErrNotExist) {
		checks = append(checks, connector.Check{Level: connector.Warn, What: "fingerprint key " + e.KeyPath,
			Detail: "not created yet", Fix: "segurata inventory local-secrets creates it; back it up: losing it changes every fingerprint"})
	} else {
		checks = append(checks, fileCheck("fingerprint key", e.KeyPath, err))
	}
	_, err := tracker.Load(e.Tracker.Tracker)
	checks = append(checks, optionalFile("tracker", e.Tracker.Tracker, err, "segurata track sync creates it"))
	checks = append(checks, dirCheck("tracker dir", filepath.Dir(e.Tracker.Tracker), "the first command that saves the tracker creates it"))
	checks = append(checks, dirCheck("output dir", e.OutDir, "segurata inventory creates it"))
	return checks
}

func optionalFile(label, path string, loadErr error, creator string) connector.Check {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return connector.Check{Level: connector.OK, What: label + " " + path, Detail: "none yet (" + creator + ")"}
	}
	return fileCheck(label, path, loadErr)
}

// privacy is whether one of segurata's files or folders is closed to other accounts: the owner
// and mode on Unix, the DACL on Windows.
type privacy struct {
	ok          bool
	detail, fix string
}

// fileCheck reports a state file that failed to load, or that other accounts can reach.
func fileCheck(label, path string, loadErr error) connector.Check {
	what := label + " " + path
	if loadErr != nil {
		return connector.Check{Level: connector.Fail, What: what, Detail: "unreadable: " + loadErr.Error(), Fix: "fix or restore " + path}
	}
	st, err := os.Stat(path)
	if err != nil {
		return connector.Check{Level: connector.Fail, What: what, Detail: err.Error(), Fix: "fix or restore " + path}
	}
	p := filePrivacy(path, st)
	if !p.ok {
		return connector.Check{Level: connector.Fail, What: what, Detail: p.detail, Fix: p.fix}
	}
	return connector.Check{Level: connector.OK, What: what, Detail: "readable, " + p.detail}
}

// dirCheck checks one of segurata's folders. Its files are private already, so a looser folder is
// a warning: it only shows which files exist and when they changed.
func dirCheck(label, dir, creator string) connector.Check {
	what := label + " " + dir
	st, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return connector.Check{Level: connector.OK, What: what, Detail: "not created yet (" + creator + ", " + newDirAccess + ")"}
	case err != nil:
		return connector.Check{Level: connector.Fail, What: what, Detail: err.Error(), Fix: "fix or remove " + dir}
	case !st.IsDir():
		return connector.Check{Level: connector.Fail, What: what, Detail: "not a directory", Fix: "move it away, or pass another --out"}
	}
	p := dirPrivacy(dir, st)
	if !p.ok {
		return connector.Check{Level: connector.Warn, What: what, Detail: p.detail, Fix: p.fix}
	}
	return connector.Check{Level: connector.OK, What: what, Detail: p.detail}
}

// keychainFix configures secret as a keychain: reference and says how to add its item. Where
// keychain: references do not resolve, it suggests an env: reference instead.
func keychainFix(connector, secret, label string, available bool) string {
	svc := keychainService(connector, secret)
	if !available {
		name := strings.ToUpper(strings.ReplaceAll(svc, "-", "_"))
		return fmt.Sprintf(`add "secrets": {"%s": "env:%s"} to connectors.%s in the config and export %s from your secret manager, or use an op:// reference (keychain: references need the macOS Keychain or Windows Credential Manager)`, secret, name, label, name)
	}
	return fmt.Sprintf(`add "secrets": {"%s": "keychain:%s"} to connectors.%s in the config, and the item (%s)`, secret, svc, label, keychain.Default("").Hint(svc))
}

// keychainService is the Keychain service the connectors' setup messages suggest.
func keychainService(connector, secret string) string {
	if textfmt.ContainsAny(secret, "ADMIN", "MANAGEMENT") {
		return "segurata-" + connector + "-admin"
	}
	return "segurata-" + connector
}
