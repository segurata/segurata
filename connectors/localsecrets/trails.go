package localsecrets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Trails finds in trail files (histories, logs, transcripts) exactly the secrets an inventory
// reports there, with their byte spans, for `segurata redact`.
type Trails struct {
	s      *scan
	failed *trailFailure
}

// Hit is one secret in the searched text, delimited by Start and End; it never holds the value.
type Hit struct {
	Start, End  int
	Type        string
	Fingerprint string
	Impact      secretrisk.Impact
	Priority    secretrisk.Priority // of this copy; "" for noise
}

// Trails needs the fingerprint key an inventory created: a new one would match no ledger item.
func (c *Connector) Trails(ctx context.Context, cfg map[string]any) (*Trails, error) {
	home, err := c.Home()
	if err != nil {
		return nil, err
	}
	set, err := parseSettings(cfg, home)
	if err != nil {
		return nil, err
	}
	fp, err := fingerprint.Open(c.KeyPath(home))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("no fingerprint key yet: run `segurata inventory local-secrets` first")
	}
	if err != nil {
		return nil, fmt.Errorf("fingerprint key: %w", err)
	}
	if _, err := c.LookPath("rg"); err != nil {
		return nil, errors.New("rg (ripgrep) is required: install it (https://github.com/BurntSushi/ripgrep#installation)")
	}
	failed := &trailFailure{}
	return &Trails{s: newScan(ctx, c, home, set, fp, failed), failed: failed}, nil
}

func (t *Trails) Home() string { return t.s.home }

func (t *Trails) Tilde(p string) string { return t.s.tilde(p) }

func isTrail(kind string) bool { return kind == "transcript" || kind == "history" || kind == "log" }

// Lines is the candidate lines, ascending, of every trail file ripgrep matches: all trails an
// inventory scans, or just files (to check them again after a rewrite).
func (t *Trails) Lines(files []string) (map[string][]int, error) {
	var passes []pass
	if files == nil {
		passes = t.s.trailPasses()
	} else {
		byKind := map[string][]string{}
		for _, f := range files {
			k := t.s.kindOf(f)
			byKind[k] = append(byKind[k], f)
		}
		for k, paths := range byKind {
			passes = append(passes, pass{patternsFor(k), paths, nil})
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	seen := map[string]map[int]bool{}
	for _, p := range passes {
		args := rgArgsFor(p)
		if args == nil {
			continue
		}
		wg.Go(func() {
			out := t.s.rgOutput(args)
			mu.Lock()
			defer mu.Unlock()
			eachRGMatch(out, func(path string, line int, _ string) {
				if !isTrail(t.s.kindOf(path)) {
					return
				}
				if seen[path] == nil {
					seen[path] = map[int]bool{}
				}
				seen[path][line] = true
			})
		})
	}
	wg.Wait()
	if msg := t.failed.get(); msg != "" {
		return nil, errors.New(msg)
	}
	out := make(map[string][]int, len(seen))
	for p, ls := range seen {
		out[p] = slices.Sorted(maps.Keys(ls))
	}
	return out, nil
}

// combined is the alternation ripgrep runs for several -e: leftmost match, then first pattern.
func combined(ps []pattern) *regexp.Regexp {
	parts := make([]string, len(ps))
	for i, p := range ps {
		src := p.src
		if strings.HasPrefix(src, "(?i)") {
			parts[i] = "(?i:" + src[4:] + ")"
		} else {
			parts[i] = "(?:" + src + ")"
		}
	}
	return regexp.MustCompile(strings.Join(parts, "|"))
}

var (
	matchersOnce                sync.Once
	matcherSpecific, matcherAll *matcher
)

func matcherFor(kind string) *matcher {
	matchersOnce.Do(func() {
		matcherSpecific, matcherAll = newMatcher(specific), newMatcher(withAssignment)
	})
	if specificOnly(kind) {
		return matcherSpecific
	}
	return matcherAll
}

// Find is the secrets an inventory would report in text for a file at path with effective mode.
func (t *Trails) Find(path, mode, text string) []Hit {
	return t.find(path, mode, text, matcherFor(t.s.kindOf(path)).findAll)
}

func (t *Trails) find(path, mode, text string, matches func(string) [][]int) []Hit {
	kind := t.s.kindOf(path)
	patterns := patternsFor(kind)
	spot := secretrisk.Where(kind, mode, false, false)
	var hits []Hit
	off := 0
	for line := range strings.SplitAfterSeq(text, "\n") {
		for _, loc := range matches(strings.TrimSuffix(line, "\n")) {
			ev, value, c, ok := lineEvidence(path, line[loc[0]:loc[1]], strings.TrimSuffix(line, "\n"), patterns, t.s.now)
			if !ok {
				continue
			}
			start, end := loc[0], loc[1]
			if c.p.typ != privateKeyType {
				g := c.p.group
				start, end = loc[0]+c.idx[2*g], loc[0]+c.idx[2*g+1]
			}
			ev.Kind = kind
			impact := secretrisk.ImpactOf(ev)
			hits = append(hits, Hit{Start: off + start, End: off + end, Type: ev.Type,
				Fingerprint: t.s.fp.Of(value), Impact: impact, Priority: secretrisk.PriorityOf(impact, spot.Level)})
		}
		off += len(line)
	}
	return hits
}

// lineEvidence judges the match mt of line from the text alone: the evidence without its place,
// the raw value and how mt was classified. A service-account key is judged from its whole file,
// so it is left out.
func lineEvidence(path, mt, line string, patterns []pattern, now time.Time) (secretrisk.Evidence, string, classified, bool) {
	c, ok := classify(path, mt, patterns)
	if !ok {
		return secretrisk.Evidence{}, "", c, false
	}
	switch c.p.typ {
	case privateKeyType:
		ev, value, ok := privateKeyEvidence(mt)
		return ev, value, c, ok
	case "gcp-service-account":
		return secretrisk.Evidence{}, "", c, false
	}
	ev, value, ok := valueEvidence(c.p, c.subs(mt), c.varName, line, now)
	return ev, value, c, ok
}

func (t *Trails) Mode(p string) string {
	eff, _ := modeOf(p, t.s.home)
	return eff
}

// trailFailure is the emitter of a trail scan: it keeps the first ripgrep failure, which leaves
// the files scope uninspected, so the caller gets an error instead of a partial list.
type trailFailure struct {
	mu  sync.Mutex
	msg string
}

func (l *trailFailure) Finding(finding.Finding) {}
func (l *trailFailure) Status(finding.Status)   {}
func (l *trailFailure) Log(string)              {}
func (l *trailFailure) Scope(id string, inspected bool, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id == secretrisk.FilesScope && !inspected && l.msg == "" {
		l.msg = reason
	}
}

func (l *trailFailure) get() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.msg
}
