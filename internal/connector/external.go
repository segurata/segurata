package connector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/searchpath"
	"github.com/segurata/segurata/internal/textfmt"
)

const externalPrefix = "segurata-"

// validName is what a connector name may look like: it selects the secrets the core hands over
// and names the run file, so it must be a plain word that cannot climb out of a directory.
var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// RemediationProtocol is the first protocol version with `plan` and `apply`.
const RemediationProtocol = 2

// External wraps a segurata-<name> executable so it behaves like a built-in connector.
type External struct {
	Path string
	desc Description
}

// Discover finds segurata-<name> executables on PATH. A built-in name wins over an external one, an
// earlier PATH directory over a later one, and a file whose suffix is not a valid name never runs.
// Only absolute PATH entries count, so the plugin set never depends on the working directory and
// matches what a scheduled run sees.
func Discover() []*External {
	seen := map[string]bool{}
	for _, c := range Builtins() {
		seen[c.Describe().Name] = true
	}
	var out []*External
	for _, dir := range filepath.SplitList(searchpath.Clean(os.Getenv("PATH"))) {
		matches, _ := filepath.Glob(filepath.Join(dir, externalPrefix+"*"))
		for _, p := range matches {
			name := fileName(p)
			if seen[name] || !isExecutable(p) {
				continue
			}
			if !validName.MatchString(name) {
				fmt.Fprintf(os.Stderr, "segurata: ignoring %s: %q is not a connector name\n", p, name)
				continue
			}
			e, err := LoadExternal(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "segurata: ignoring %s: %v\n", p, err)
				continue
			}
			seen[name] = true
			out = append(out, e)
		}
	}
	return out
}

// fileName is the connector name a segurata-<name> path stands for.
func fileName(path string) string { return strings.TrimPrefix(filepath.Base(path), externalPrefix) }

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// Bounds on a plugin's subprocesses, so one that hangs or floods its output cannot hang or exhaust
// the core. describe runs on every command that lists connectors and prints a few hundred bytes.
var describeTimeout = 10 * time.Second

const (
	maxDescribeBytes = 1 << 20
	maxStderrBytes   = 1 << 20
)

// command prepares `<path> <sub>`, killed when ctx is done; proc.Command bounds the wait for pipes
// a child it left behind may still hold open.
func command(ctx context.Context, path, sub string) *exec.Cmd {
	return proc.Command(ctx, path, sub)
}

// LoadExternal runs `<path> describe` and checks what it prints, including that the name it
// declares is the one in its file name.
func LoadExternal(path string) (*External, error) {
	ctx, cancel := context.WithTimeout(context.Background(), describeTimeout)
	defer cancel()
	cmd := command(ctx, path, "describe")
	var raw bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &raw, n: maxDescribeBytes}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("no answer within %v", describeTimeout)
		}
		return nil, fmt.Errorf("describe: %w", err)
	}
	e := &External{Path: path}
	if err := json.Unmarshal(raw.Bytes(), &e.desc); err != nil {
		return nil, fmt.Errorf("describe output is not JSON: %w", err)
	}
	if err := e.desc.validate(); err != nil {
		return nil, err
	}
	if want := fileName(path); e.desc.Name != want {
		return nil, fmt.Errorf("describe names %q, but the file is %s%s", e.desc.Name, externalPrefix, want)
	}
	return e, nil
}

// validate checks a description an external connector printed.
func (d Description) validate() error {
	if d.Name == "" {
		return errors.New("describe has no name")
	}
	if !validName.MatchString(d.Name) {
		return fmt.Errorf("name %q is not lowercase letters, digits and dashes", d.Name)
	}
	if d.Protocol < MinProtocolVersion || d.Protocol > ProtocolVersion {
		return fmt.Errorf("speaks protocol %d, core speaks %d to %d", d.Protocol, MinProtocolVersion, ProtocolVersion)
	}
	if len(d.Remediates) > 0 && d.Protocol < RemediationProtocol {
		return fmt.Errorf("declares remediations but speaks protocol %d; remediation needs protocol %d", d.Protocol, RemediationProtocol)
	}
	if d.Theme.ID != "" && !validName.MatchString(d.Theme.ID) {
		return fmt.Errorf("theme id %q is not lowercase letters, digits and dashes", d.Theme.ID)
	}
	for _, a := range d.Covers {
		if !validName.MatchString(a.ID) {
			return fmt.Errorf("covered area %q is not lowercase letters, digits and dashes", a.ID)
		}
	}
	for _, a := range d.Remediates {
		if strings.TrimSpace(a) == "" {
			return errors.New("declares an empty remediation action")
		}
	}
	return nil
}

func (e *External) Describe() Description { return e.desc }

// Inventory runs `segurata-<name> inventory`. The request carries the protocol version the
// connector declared, so a version 1 connector never sees a version it does not know. A record the
// core cannot use fails the run once the rest has been read: dropping it silently would make what
// it reported look resolved.
func (e *External) Inventory(ctx context.Context, req Request, emit Emitter) error {
	req.Protocol = e.desc.Protocol
	var stderr bytes.Buffer
	var malformed int
	var first error
	err := e.stream(ctx, "inventory", req, &limitedWriter{w: &stderr, n: maxStderrBytes}, func(line []byte) {
		if err := decodeRecord(line, e.desc.Name, emit); err != nil {
			if malformed++; first == nil {
				first = err
			}
		}
	})
	diag := strings.TrimSpace(stderr.String())
	if err != nil {
		return fmt.Errorf("%s: %w: %s", e.desc.Name, err, diag)
	}
	if diag != "" {
		emit.Log(diag)
	}
	if malformed > 0 {
		return fmt.Errorf("%s: %s, first: %w", e.desc.Name, textfmt.Count(malformed, "malformed record", "malformed records"), first)
	}
	return nil
}

// RemediationRequest is what the core writes to `plan` and `apply` (protocol 2). Plan is set only
// for `apply`: the plan the owner saw and confirmed.
type RemediationRequest struct {
	Request
	Finding finding.Finding `json:"finding"`
	Plan    *Plan           `json:"plan,omitempty"`
}

// PlanReply is what `segurata-<name> plan` prints: the fields of a Plan, plus needs_sudo, which a
// connector may set and the core refuses.
type PlanReply struct {
	Plan
	SudoRequested bool `json:"needs_sudo,omitempty"`
}

// maxPlanBytes bounds what the core reads from `plan`; a plan is a few hundred bytes.
const maxPlanBytes = 1 << 20

// RequestPlan runs `segurata-<name> plan` and decodes its reply strictly: an unknown field or
// trailing data is an error, never ignored, and so is a plan that carries one of the request's
// secret values. It vets nothing else; the core does.
func (e *External) RequestPlan(ctx context.Context, req RemediationRequest) (PlanReply, error) {
	if e.desc.Protocol < RemediationProtocol {
		return PlanReply{}, fmt.Errorf("%s speaks protocol %d, which has no remediation", e.desc.Name, e.desc.Protocol)
	}
	req.Protocol, req.Plan = e.desc.Protocol, nil
	in, err := json.Marshal(req)
	if err != nil {
		return PlanReply{}, err
	}
	cmd := command(ctx, e.Path, "plan")
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limitedWriter{w: &stdout, n: maxPlanBytes}, &limitedWriter{w: &stderr, n: maxStderrBytes}
	scrub := newScrubber(req.Secrets)
	if err := cmd.Run(); err != nil {
		return PlanReply{}, fmt.Errorf("%s plan: %w: %s", e.desc.Name, err, scrub.String(strings.TrimSpace(stderr.String())))
	}
	dec := json.NewDecoder(&stdout)
	dec.DisallowUnknownFields()
	var reply PlanReply
	if err := dec.Decode(&reply); err != nil {
		return PlanReply{}, fmt.Errorf("%s plan: output is not a plan: %w", e.desc.Name, err)
	}
	if dec.More() {
		return PlanReply{}, fmt.Errorf("%s plan: unexpected data after the plan", e.desc.Name)
	}
	if scrub.Carries(reply) {
		return PlanReply{}, fmt.Errorf("%s plan: the plan carries a secret the core handed the connector", e.desc.Name)
	}
	return reply, nil
}

// RequestApply runs `segurata-<name> apply` with the confirmed plan. Its `log` records go to
// out, its stderr to errw, both with the request's secret values redacted; a non-zero exit is a
// failed apply.
func (e *External) RequestApply(ctx context.Context, req RemediationRequest, out, errw io.Writer) error {
	if e.desc.Protocol < RemediationProtocol {
		return fmt.Errorf("%s speaks protocol %d, which has no remediation", e.desc.Name, e.desc.Protocol)
	}
	if req.Plan == nil {
		return errors.New("apply needs the confirmed plan")
	}
	req.Protocol = e.desc.Protocol
	scrub := newScrubber(req.Secrets)
	stderr := &lineScrubber{w: errw, s: scrub}
	err := e.stream(ctx, "apply", req, stderr, func(line []byte) {
		var rec struct {
			Type string `json:"type"`
			Msg  string `json:"msg"`
		}
		if json.Unmarshal(line, &rec) != nil || rec.Type != "log" {
			fmt.Fprintf(out, "  %s: non-log line ignored\n", e.desc.Name)
			return
		}
		fmt.Fprintf(out, "  %s: %s\n", e.desc.Name, scrub.String(rec.Msg))
	})
	stderr.Flush()
	if err != nil {
		return fmt.Errorf("%s apply: %w", e.desc.Name, scrub.Error(err))
	}
	return nil
}

// stream runs one subcommand with in as its JSON stdin and hands each stdout line to line.
func (e *External) stream(ctx context.Context, sub string, in any, stderr io.Writer, line func([]byte)) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	cmd := command(ctx, e.Path, sub)
	cmd.Stdin = bytes.NewReader(raw)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// A child the plugin left behind can hold its pipes open after the plugin is killed, and the
	// reads below would wait for that child however short ctx was: WaitDelay bounds only Wait.
	// Closing both pipes when ctx ends releases them at once.
	stop := context.AfterFunc(ctx, func() { _ = stdout.Close(); _ = errPipe.Close() })
	defer stop()
	copied := make(chan error, 1)
	go func() {
		_, err := io.Copy(stderr, errPipe)
		_ = errPipe.Close() // a writer that failed (too much output) ends the plugin's writes too
		copied <- err
	}()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line(sc.Bytes())
	}
	scanErr := sc.Err()
	if scanErr != nil {
		_, _ = io.Copy(io.Discard, stdout) // let the process finish writing before Wait
	}
	copyErr := <-copied
	if err := cmd.Wait(); err != nil {
		return err
	}
	if ctx.Err() == nil && copyErr != nil {
		return copyErr
	}
	return scanErr
}

// limitedWriter keeps at most n bytes and fails after that, so a runaway plugin cannot fill memory.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("output too large")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

// decodeRecord routes one JSON line to the emitter by its "type" field. It returns an error, and
// emits nothing, for a line that is not a record of a known type with the fields that type needs.
func decodeRecord(line []byte, name string, emit Emitter) error {
	var head struct {
		Type string `json:"type"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		return fmt.Errorf("unparseable line: %w", err)
	}
	switch head.Type {
	case "finding":
		var f finding.Finding
		if err := json.Unmarshal(line, &f); err != nil {
			return fmt.Errorf("finding: %w", err)
		}
		if !f.Severity.Valid() || f.Remediation.Severity != "" && !f.Remediation.Severity.Valid() {
			return fmt.Errorf("finding %s/%s: severity %q (remediation %q) is not info, low, medium, high or critical",
				f.Resource.Type, f.Resource.ID, f.Severity, f.Remediation.Severity)
		}
		f.Connector = name
		emit.Finding(f)
	case "status":
		var s finding.Status
		if err := json.Unmarshal(line, &s); err != nil {
			return fmt.Errorf("status: %w", err)
		}
		s.Connector = name
		emit.Status(s)
	case "scope":
		var sc struct {
			Scope     string `json:"scope"`
			Inspected bool   `json:"inspected"`
			Reason    string `json:"reason"`
		}
		if err := json.Unmarshal(line, &sc); err != nil {
			return fmt.Errorf("scope: %w", err)
		}
		emit.Scope(sc.Scope, sc.Inspected, sc.Reason)
	case "log":
		emit.Log(head.Msg)
	default:
		return fmt.Errorf("unknown record type %q", head.Type)
	}
	return nil
}
