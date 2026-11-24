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
	"strings"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/proc"
)

const externalPrefix = "segurata-"

// RemediationProtocol is the first protocol version with `plan` and `apply`.
const RemediationProtocol = 2

// External wraps a segurata-<name> executable so it behaves like a built-in connector.
type External struct {
	Path string
	desc Description
}

// Discover finds segurata-<name> executables on PATH. Built-in names win over external ones.
func Discover() []*External {
	seen := map[string]bool{}
	for _, c := range Builtins() {
		seen[c.Describe().Name] = true
	}
	var out []*External
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		matches, _ := filepath.Glob(filepath.Join(dir, externalPrefix+"*"))
		for _, p := range matches {
			name := strings.TrimPrefix(filepath.Base(p), externalPrefix)
			if seen[name] || !isExecutable(p) {
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

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// LoadExternal runs `<path> describe` and checks what it prints.
func LoadExternal(path string) (*External, error) {
	raw, err := exec.Command(path, "describe").Output()
	if err != nil {
		return nil, fmt.Errorf("describe: %w", err)
	}
	e := &External{Path: path}
	if err := json.Unmarshal(raw, &e.desc); err != nil {
		return nil, fmt.Errorf("describe output is not JSON: %w", err)
	}
	if err := e.desc.validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// validate checks a description an external connector printed.
func (d Description) validate() error {
	if d.Name == "" {
		return errors.New("describe has no name")
	}
	if d.Protocol < MinProtocolVersion || d.Protocol > ProtocolVersion {
		return fmt.Errorf("speaks protocol %d, core speaks %d to %d", d.Protocol, MinProtocolVersion, ProtocolVersion)
	}
	if len(d.Remediates) > 0 && d.Protocol < RemediationProtocol {
		return fmt.Errorf("declares remediations but speaks protocol %d; remediation needs protocol %d", d.Protocol, RemediationProtocol)
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
// connector declared, so a version 1 connector never sees a version it does not know.
func (e *External) Inventory(ctx context.Context, req Request, emit Emitter) error {
	req.Protocol = e.desc.Protocol
	var stderr bytes.Buffer
	err := e.stream(ctx, "inventory", req, &stderr, func(line []byte) { decodeRecord(line, e.desc.Name, emit) })
	if err != nil {
		return fmt.Errorf("%s: %w: %s", e.desc.Name, err, strings.TrimSpace(stderr.String()))
	}
	if s := strings.TrimSpace(stderr.String()); s != "" {
		emit.Log(s)
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
// trailing data is an error, never ignored. It vets nothing else; the core does.
func (e *External) RequestPlan(ctx context.Context, req RemediationRequest) (PlanReply, error) {
	if e.desc.Protocol < RemediationProtocol {
		return PlanReply{}, fmt.Errorf("%s speaks protocol %d, which has no remediation", e.desc.Name, e.desc.Protocol)
	}
	req.Protocol, req.Plan = e.desc.Protocol, nil
	in, err := json.Marshal(req)
	if err != nil {
		return PlanReply{}, err
	}
	cmd := proc.Command(ctx, e.Path, "plan")
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limitedWriter{w: &stdout, n: maxPlanBytes}, &stderr
	if err := cmd.Run(); err != nil {
		return PlanReply{}, fmt.Errorf("%s plan: %w: %s", e.desc.Name, err, strings.TrimSpace(stderr.String()))
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
	return reply, nil
}

// RequestApply runs `segurata-<name> apply` with the confirmed plan. Its `log` records go to
// out, its stderr to errw; a non-zero exit is a failed apply.
func (e *External) RequestApply(ctx context.Context, req RemediationRequest, out, errw io.Writer) error {
	if e.desc.Protocol < RemediationProtocol {
		return fmt.Errorf("%s speaks protocol %d, which has no remediation", e.desc.Name, e.desc.Protocol)
	}
	if req.Plan == nil {
		return errors.New("apply needs the confirmed plan")
	}
	req.Protocol = e.desc.Protocol
	err := e.stream(ctx, "apply", req, errw, func(line []byte) {
		var rec struct {
			Type string `json:"type"`
			Msg  string `json:"msg"`
		}
		if json.Unmarshal(line, &rec) != nil || rec.Type != "log" {
			fmt.Fprintf(out, "  %s: non-log line ignored\n", e.desc.Name)
			return
		}
		fmt.Fprintf(out, "  %s: %s\n", e.desc.Name, rec.Msg)
	})
	if err != nil {
		return fmt.Errorf("%s apply: %w", e.desc.Name, err)
	}
	return nil
}

// stream runs one subcommand with in as its JSON stdin and hands each stdout line to line.
func (e *External) stream(ctx context.Context, sub string, in any, stderr io.Writer, line func([]byte)) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	cmd := proc.Command(ctx, e.Path, sub)
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line(sc.Bytes())
	}
	scanErr := sc.Err()
	if scanErr != nil {
		_, _ = io.Copy(io.Discard, stdout) // let the process finish writing before Wait
	}
	if err := cmd.Wait(); err != nil {
		return err
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

// decodeRecord routes one JSON line to the emitter by its "type" field.
func decodeRecord(line []byte, name string, emit Emitter) {
	var head struct {
		Type string `json:"type"`
		Msg  string `json:"msg"`
	}
	if json.Unmarshal(line, &head) != nil {
		emit.Log(fmt.Sprintf("%s: unparseable line ignored", name))
		return
	}
	switch head.Type {
	case "finding":
		var f finding.Finding
		if json.Unmarshal(line, &f) == nil {
			f.Connector = name
			emit.Finding(f)
		}
	case "status":
		var s finding.Status
		if json.Unmarshal(line, &s) == nil {
			s.Connector = name
			emit.Status(s)
		}
	case "scope":
		var sc struct {
			Scope     string `json:"scope"`
			Inspected bool   `json:"inspected"`
			Reason    string `json:"reason"`
		}
		if json.Unmarshal(line, &sc) == nil {
			emit.Scope(sc.Scope, sc.Inspected, sc.Reason)
		}
	case "log":
		emit.Log(head.Msg)
	}
}
