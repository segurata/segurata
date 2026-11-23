package connector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

const externalPrefix = "securizame-"

// External wraps a securizame-<name> executable so it behaves like a built-in connector.
type External struct {
	Path string
	desc Description
}

// Discover finds securizame-<name> executables on PATH. Built-in names win over external ones.
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
			e := &External{Path: p}
			if err := e.load(); err != nil {
				fmt.Fprintf(os.Stderr, "securizame: ignoring %s: %v\n", p, err)
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

func (e *External) load() error {
	raw, err := exec.Command(e.Path, "describe").Output()
	if err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	if err := json.Unmarshal(raw, &e.desc); err != nil {
		return fmt.Errorf("describe output is not JSON: %w", err)
	}
	if e.desc.Protocol != ProtocolVersion {
		return fmt.Errorf("speaks protocol %d, core speaks %d", e.desc.Protocol, ProtocolVersion)
	}
	return nil
}

func (e *External) Describe() Description { return e.desc }

func (e *External) Inventory(ctx context.Context, req Request, emit Emitter) error {
	in, err := json.Marshal(req)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, e.Path, "inventory")
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
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
		decodeRecord(sc.Bytes(), e.desc.Name, emit)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %w: %s", e.desc.Name, err, strings.TrimSpace(stderr.String()))
	}
	if s := strings.TrimSpace(stderr.String()); s != "" {
		emit.Log(s)
	}
	return sc.Err()
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
	case "log":
		emit.Log(head.Msg)
	}
}
