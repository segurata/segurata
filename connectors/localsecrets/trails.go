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

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Trails is the part of a scan that covers trail files (shell histories, logs, agent
// transcripts), for `segurata redact`: it finds in them exactly the secrets an inventory would
// report, with the bytes each one occupies on its line, so they can be replaced in place.
type Trails struct {
	s   *scan
	log *firstLog
}

// Hit is one secret found in a piece of text, as an inventory would classify it. It never holds
// the value: Start and End delimit it inside the text that was searched.
type Hit struct {
	Start, End  int
	Type        string
	Fingerprint string
	Impact      secretrisk.Impact
	// Priority is the rotation priority of this one copy (impact × the file's exposure); "" for
	// noise.
	Priority secretrisk.Priority
}

// Trails prepares a trail scan with the connector's config. It needs the fingerprint key an
// inventory created: a new key would match nothing in the rotation ledger.
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
		return nil, errors.New("rg (ripgrep) is required: install it, respecting the 4-day quarantine")
	}
	l := &firstLog{}
	return &Trails{s: newScan(ctx, c, home, set, fp, l), log: l}, nil
}

// Home is the home folder the trails live under.
func (t *Trails) Home() string { return t.s.home }

// Tilde writes a path under the home folder as ~/…, as findings do.
func (t *Trails) Tilde(p string) string { return t.s.tilde(p) }

// Kind classifies a path as an inventory does: transcript, history, log, repo or config.
func (t *Trails) Kind(p string) string { return t.s.kindOf(p) }

// IsTrail reports whether a path is a trail: a transcript, a shell history or a log.
func IsTrail(kind string) bool { return kind == "transcript" || kind == "history" || kind == "log" }

// Lines runs ripgrep with the inventory's patterns and returns every trail file holding a
// candidate match, with the candidate line numbers in ascending order. Without files it covers
// every trail an inventory scans; with files, just those (to check them again after a rewrite).
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
	// The passes run at once, as an inventory's do.
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
				if !IsTrail(t.s.kindOf(path)) {
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
	if msg := t.log.get(); msg != "" {
		return nil, errors.New(msg)
	}
	out := make(map[string][]int, len(seen))
	for p, ls := range seen {
		out[p] = slices.Sorted(maps.Keys(ls))
	}
	return out, nil
}

// combined joins patterns into one alternation, as ripgrep does with several -e: the leftmost
// match wins, and among matches at the same place the first pattern.
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

// matcherFor finds the matches of patternsFor(kind) joined into one alternation.
func matcherFor(kind string) *matcher {
	matchersOnce.Do(func() {
		matcherSpecific, matcherAll = newMatcher(specific), newMatcher(withAssignment)
	})
	if specificOnly(kind) {
		return matcherSpecific
	}
	return matcherAll
}

// Find returns the secrets in text, line by line, that an inventory would report for a file at
// path. Matches an inventory drops for trails (a private-key header without its body, a
// service-account marker) are not hits. mode is the file's effective mode, used for exposure.
func (t *Trails) Find(path, mode, text string) []Hit {
	return t.find(path, mode, text, matcherFor(t.s.kindOf(path)).findAll)
}

// find is Find with the function that places the alternation's matches on a line.
func (t *Trails) find(path, mode, text string, matches func(string) [][]int) []Hit {
	kind := t.s.kindOf(path)
	patterns := patternsFor(kind)
	spot := secretrisk.Where("scan", kind, mode, false, false)
	var hits []Hit
	off := 0
	for line := range strings.SplitAfterSeq(text, "\n") {
		for _, loc := range matches(strings.TrimSuffix(line, "\n")) {
			mt := line[loc[0]:loc[1]]
			c, ok := classify(path, mt, patterns)
			if !ok {
				continue
			}
			var ev secretrisk.Evidence
			var value string
			start, end := loc[0], loc[1]
			switch c.p.typ {
			case privateKeyType:
				ev, value, ok = privateKeyEvidence(mt)
			case "gcp-service-account":
				ok = false
			default:
				ev, value, ok = valueEvidence(c.p, c.subs(mt), c.varName, strings.TrimSuffix(line, "\n"), t.s.now)
				g := c.p.group
				start, end = loc[0]+c.idx[2*g], loc[0]+c.idx[2*g+1]
			}
			if !ok {
				continue
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

// Mode is a file's effective mode for other accounts, as findings report it.
func (t *Trails) Mode(p string) string {
	eff, _ := modeOf(p, t.s.home)
	return eff
}

// firstLog is the emitter of a trail scan: it keeps the first log line (a ripgrep failure), so
// the caller gets it as an error instead of a partial list.
type firstLog struct {
	mu  sync.Mutex
	msg string
}

func (l *firstLog) Finding(finding.Finding) {}
func (l *firstLog) Status(finding.Status)   {}
func (l *firstLog) Log(m string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.msg == "" {
		l.msg = m
	}
}
func (l *firstLog) get() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.msg
}
