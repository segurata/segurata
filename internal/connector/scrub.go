package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// minScrubbed is the shortest value scrubbed: a shorter one would match ordinary text.
const minScrubbed = 6

// scrubber redacts the secret values the core handed a connector in what the connector prints.
type scrubber struct {
	values   []string // longest first, so a value inside another is never replaced first
	replacer *strings.Replacer
}

func newScrubber(secrets map[string]string) scrubber {
	var s scrubber
	for _, v := range secrets {
		if len(v) >= minScrubbed {
			s.values = append(s.values, v)
		}
	}
	sort.Slice(s.values, func(i, j int) bool { return len(s.values[i]) > len(s.values[j]) })
	pairs := make([]string, 0, 2*len(s.values))
	for _, v := range s.values {
		pairs = append(pairs, v, secretrisk.Redact("", "", v))
	}
	s.replacer = strings.NewReplacer(pairs...)
	return s
}

func (s scrubber) String(text string) string {
	if len(s.values) == 0 {
		return text
	}
	return s.replacer.Replace(text)
}

// ScrubChecks removes known credential values from doctor diagnostics in place.
func ScrubChecks(checks []Check, secrets map[string]string) {
	s := newScrubber(secrets)
	for i := range checks {
		c := &checks[i]
		c.What, c.Detail, c.Fix = s.String(c.What), s.String(c.Detail), s.String(c.Fix)
	}
}

func (s scrubber) Error(err error) error {
	if err == nil {
		return nil
	}
	if msg := err.Error(); s.String(msg) != msg {
		return errors.New(s.String(msg))
	}
	return err
}

// Carries reports whether v, as JSON, holds a secret value anywhere.
func (s scrubber) Carries(v any) bool {
	if len(s.values) == 0 {
		return false
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return true // cannot tell: treat as carrying, never as clean
	}
	text := string(raw)
	for _, val := range s.values {
		quoted, _ := json.Marshal(val)
		if strings.Contains(text, string(quoted[1:len(quoted)-1])) {
			return true
		}
	}
	return false
}

// ScrubEmitter drops a finding or status that carries a secret value and fails the run through Err,
// since a silent drop would look resolved; scopes and logs pass redacted.
type ScrubEmitter struct {
	emit    Emitter
	s       scrubber
	mu      sync.Mutex
	dropped int
}

func NewScrubEmitter(emit Emitter, secrets map[string]string) *ScrubEmitter {
	return &ScrubEmitter{emit: emit, s: newScrubber(secrets)}
}

func (e *ScrubEmitter) Finding(f finding.Finding) {
	if e.drop(f) {
		return
	}
	e.emit.Finding(f)
}

func (e *ScrubEmitter) Status(st finding.Status) {
	if e.drop(st) {
		return
	}
	e.emit.Status(st)
}

func (e *ScrubEmitter) Scope(id string, inspected bool, reason string) {
	e.emit.Scope(e.s.String(id), inspected, e.s.String(reason))
}

func (e *ScrubEmitter) Log(msg string) { e.emit.Log(e.s.String(msg)) }

func (e *ScrubEmitter) drop(v any) bool {
	if !e.s.Carries(v) {
		return false
	}
	e.mu.Lock()
	e.dropped++
	e.mu.Unlock()
	return true
}

// Err scrubs the connector's own error and adds one for dropped records.
func (e *ScrubEmitter) Err(err error) error {
	e.mu.Lock()
	n := e.dropped
	e.mu.Unlock()
	err = e.s.Error(err)
	if n > 0 {
		err = errors.Join(err, fmt.Errorf("%s carried a secret the core handed the connector, and were dropped",
			textfmt.Count(n, "record", "records")))
	}
	return err
}

// lineScrubber scrubs whole lines, so a value split across two writes is still found.
type lineScrubber struct {
	w   io.Writer
	s   scrubber
	buf []byte
}

func (l *lineScrubber) Write(p []byte) (int, error) {
	l.buf = append(l.buf, p...)
	if i := bytes.LastIndexByte(l.buf, '\n'); i >= 0 {
		if _, err := io.WriteString(l.w, l.s.String(string(l.buf[:i+1]))); err != nil {
			return 0, err
		}
		l.buf = l.buf[i+1:]
	}
	if len(l.buf) > maxStderrBytes {
		return 0, errors.New("output too large")
	}
	return len(p), nil
}

func (l *lineScrubber) Flush() {
	if len(l.buf) > 0 {
		_, _ = io.WriteString(l.w, l.s.String(string(l.buf)))
		l.buf = nil
	}
}
