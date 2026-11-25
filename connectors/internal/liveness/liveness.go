// Package liveness asks a provider, once per leaked secret, whether the secret still works: one
// call with it to the provider's cheapest read-only identity endpoint (providers.go). The answer
// is live (accepted), dead (rejected as invalid, revoked or expired) or unknown (no answer that
// tells). local-secrets runs it at scan time, the only moment segurata holds the value, and only
// when the owner turned it on for secrets attributed to owners they chose: see
// docs/architecture.md, "Liveness".
//
// Safety: every endpoint is a GET that reads who the caller is, or lists something; none changes
// state, costs money or sends anything. Calls go one at a time per provider, with a pause between
// any two, through httpx (credentials are dropped on a redirect to another host). Results hold
// no value and no provider message (which may echo part of the key), and are cached by
// fingerprint so a secret is not tried again for a while.
package liveness

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Config is local-secrets' `liveness` block. Off unless enabled; owners default to mine only, and
// not-mine can never be named: someone else's key is never tried.
type Config struct {
	Enabled   bool
	Owners    []attribution.Owner
	Providers []string // nil: every provider the package knows
}

// ParseConfig reads `{"enabled": true, "owners": ["mine", "unknown"], "providers": ["github"]}`.
func ParseConfig(raw any) (Config, error) {
	c := Config{Owners: []attribution.Owner{attribution.Mine}}
	if raw == nil {
		return c, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return c, fmt.Errorf(`liveness must be an object such as {"enabled": true, "owners": ["mine"]}`)
	}
	if v, ok := m["enabled"]; ok {
		if c.Enabled, ok = v.(bool); !ok {
			return c, fmt.Errorf("liveness.enabled must be true or false")
		}
	}
	if v, ok := m["owners"]; ok {
		list, err := stringList(v, "liveness.owners")
		if err != nil {
			return c, err
		}
		owners, err := attribution.ParseOwners(strings.Join(list, ","))
		if err != nil {
			return c, fmt.Errorf("liveness.owners: %w", err)
		}
		if slices.Contains(owners, attribution.NotMine) {
			return c, fmt.Errorf("liveness.owners: not-mine is never allowed: segurata does not try someone else's key")
		}
		c.Owners = owners
	}
	if v, ok := m["providers"]; ok {
		list, err := stringList(v, "liveness.providers")
		if err != nil {
			return c, err
		}
		for _, p := range list {
			if byName(p) == nil {
				return c, fmt.Errorf("liveness.providers: unknown provider %q (known: %s)", p, strings.Join(Providers(), ", "))
			}
		}
		c.Providers = list
	}
	return c, nil
}

func stringList(v any, key string) ([]string, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list of strings", key)
	}
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, ok := x.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("%s must be a list of strings", key)
		}
		out = append(out, s)
	}
	return out, nil
}

// Allows reports whether the owner lets the check try a secret attributed to owner.
func (c Config) Allows(owner attribution.Owner) bool {
	return owner != attribution.NotMine && slices.Contains(c.Owners, owner)
}

// allowsProvider reports whether the config's provider allowlist names the provider.
func (c Config) allowsProvider(name string) bool {
	return c.Providers == nil || slices.Contains(c.Providers, name)
}

// Probe is one secret to try. Value never leaves this package except in the request to its
// provider.
type Probe struct {
	// Fingerprints get the result: the secret's own, and for an AWS key pair the key id's too.
	Fingerprints []string
	Type         string // a secretrisk catalog type
	Value        string
	KeyID        string // aws-secret-key: the access key id found with it
}

// Stats count what one run of the check did, for the connector's status line.
type Stats struct {
	Asked, Cached, Live, Dead, Unknown int
	Unsupported                        int // no provider endpoint for the type, or a key without its pair
	NotAllowed                         int // attributed to an owner the config leaves out, or a provider it leaves out
	Interrupted                        int // not asked: the run's time ran out
}

func (s Stats) String() string {
	return fmt.Sprintf("liveness: %d asked, %d from cache; %d live, %d dead, %d unknown; %d unsupported, %d not allowed, %d interrupted",
		s.Asked, s.Cached, s.Live, s.Dead, s.Unknown, s.Unsupported, s.NotAllowed, s.Interrupted)
}

// Checker runs the check. Zero values are the defaults: real endpoints, no cache, the real clock,
// DefaultInterval.
type Checker struct {
	Config Config
	// Bases replaces a provider's base URLs (tests point them at a fake server).
	Bases map[string][]string
	Cache *Cache
	Now   func() time.Time
	// Interval is the least time between two calls, across providers.
	Interval time.Duration
}

// DefaultInterval keeps the whole check under four calls a second.
const DefaultInterval = 250 * time.Millisecond

// Check tries each probe the config allows, one call per probe, and returns the result by
// fingerprint. A probe whose fingerprints all have a fresh cached result is not asked again.
// Results of probes asked are cached; ctx ending stops the calls that have not started.
func (c *Checker) Check(ctx context.Context, probes []Probe) (map[string]secretrisk.Liveness, Stats) {
	now := c.now()
	out := map[string]secretrisk.Liveness{}
	var st Stats
	queues := map[*provider][]Probe{}
	for _, p := range probes {
		if r, ok := c.Cache.fresh(p.Fingerprints, now); ok {
			for _, fp := range p.Fingerprints {
				out[fp] = r
			}
			st.Cached++
			continue
		}
		pv := forType(p)
		switch {
		case pv == nil:
			st.Unsupported++
		case !c.Config.allowsProvider(pv.name):
			st.NotAllowed++
		default:
			queues[pv] = append(queues[pv], p)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	lim := &limiter{every: c.interval()}
	for pv, queue := range queues {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, p := range queue {
				if lim.wait(ctx) != nil {
					mu.Lock()
					st.Interrupted++
					mu.Unlock()
					continue
				}
				r := c.ask(ctx, pv, p)
				r.CheckedAt = c.now().UTC()
				mu.Lock()
				st.Asked++
				switch r.State {
				case secretrisk.Live:
					st.Live++
				case secretrisk.Dead:
					st.Dead++
				default:
					st.Unknown++
				}
				for _, fp := range p.Fingerprints {
					out[fp] = r
				}
				c.Cache.put(p.Fingerprints, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out, st
}

func (c *Checker) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func (c *Checker) interval() time.Duration {
	if c.Interval == 0 {
		return DefaultInterval
	}
	return c.Interval
}

// ask tries the probe on each of the provider's hosts while they say dead: dead only when every
// host rejects it.
func (c *Checker) ask(ctx context.Context, pv *provider, p Probe) secretrisk.Liveness {
	bases := pv.bases
	if b, ok := c.Bases[pv.name]; ok {
		bases = b
	}
	var r secretrisk.Liveness
	for _, base := range bases {
		if r = pv.ask(ctx, base, p); r.State != secretrisk.Dead {
			return r
		}
	}
	return r
}

// limiter spaces calls at least every apart, across goroutines.
type limiter struct {
	mu    sync.Mutex
	every time.Duration
	next  time.Time
}

func (l *limiter) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	now := time.Now()
	at := l.next
	if at.Before(now) {
		at = now
	}
	l.next = at.Add(l.every)
	l.mu.Unlock()
	t := time.NewTimer(time.Until(at))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Providers names every provider the check knows, sorted.
func Providers() []string {
	out := make([]string, len(providers))
	for i, p := range providers {
		out[i] = p.name
	}
	sort.Strings(out)
	return out
}
