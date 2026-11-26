// Package liveness asks a provider, once per leaked secret, whether it still works: one call with
// it to a read-only identity endpoint, or a lookup with the owner's own credentials for a secret
// that cannot be tried alone. local-secrets runs it at scan time, the only moment segurata holds
// the value. See docs/architecture.md, "Liveness".
//
// Safety: no endpoint changes state, costs money or sends anything; every call is a GET but
// Slack's bodiless auth.test and Linear's one fixed GraphQL query. Calls are spaced, follow no
// redirect, and keep no value nor provider message, which may echo part of the key.
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
	"github.com/segurata/segurata/internal/cfgkey"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Config is local-secrets' `liveness` block. Owners default to mine; not-mine is never allowed.
type Config struct {
	Enabled     bool
	Owners      []attribution.Owner
	Providers   []string // nil: every provider
	AWSProfiles []string // nil: every profile `aws configure list-profiles` names
	SSHHosts    []string // whose ~/.ssh/authorized_keys private keys are looked up in
}

// ParseConfig reads `{"enabled": true, "owners": ["mine", "unknown"], "providers": ["github"],
// "aws_profiles": ["prod"], "ssh_hosts": ["deploy@build1"]}`.
func ParseConfig(raw any) (Config, error) {
	c := Config{Owners: []attribution.Owner{attribution.Mine}}
	var err error
	if raw == nil {
		return c, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return c, fmt.Errorf(`liveness must be an object such as {"enabled": true, "owners": ["mine"]}`)
	}
	if c.Enabled, err = cfgkey.Bool(m, "liveness", "enabled", false); err != nil {
		return c, err
	}
	list, err := cfgkey.Strings(m, "liveness", "owners")
	if err != nil {
		return c, err
	}
	if list != nil {
		owners, err := attribution.ParseOwners(strings.Join(list, ","))
		if err != nil {
			return c, fmt.Errorf("liveness.owners: %w", err)
		}
		if slices.Contains(owners, attribution.NotMine) {
			return c, fmt.Errorf("liveness.owners: not-mine is never allowed: segurata does not try someone else's key")
		}
		c.Owners = owners
	}
	if c.Providers, err = cfgkey.Strings(m, "liveness", "providers"); err != nil {
		return c, err
	}
	for _, p := range c.Providers {
		if byName(p) == nil {
			return c, fmt.Errorf("liveness.providers: unknown provider %q (known: %s)", p, strings.Join(Providers(), ", "))
		}
	}
	if c.AWSProfiles, err = cfgkey.Strings(m, "liveness", "aws_profiles"); err != nil {
		return c, err
	}
	if c.SSHHosts, err = cfgkey.Strings(m, "liveness", "ssh_hosts"); err != nil {
		return c, err
	}
	if len(c.SSHHosts) > maxSSHHosts {
		return c, fmt.Errorf("liveness.ssh_hosts: at most %d hosts", maxSSHHosts)
	}
	for _, h := range c.SSHHosts {
		if !sshHost.MatchString(h) {
			return c, fmt.Errorf("liveness.ssh_hosts: %q is not a host name or user@host", h)
		}
	}
	return c, nil
}

// Allows reports whether the check may try a secret of the type attributed to owner. A lookup
// never sends the secret, so it runs for mine and unknown whatever Owners says.
func (c Config) Allows(owner attribution.Owner, typ string) bool {
	if owner == attribution.NotMine {
		return false
	}
	if pv := forType(typ); pv != nil && pv.lookup != nil {
		return true
	}
	return slices.Contains(c.Owners, owner)
}

func (c Config) allowsProvider(name string) bool {
	return c.Providers == nil || slices.Contains(c.Providers, name)
}

// Probe is one secret to try. Value leaves this package only in the request to its provider.
type Probe struct {
	Fingerprints []string // the secret's own, and for an AWS key pair the key id's too
	Type         string   // a secretrisk catalog type
	Value        string
	KeyID        string // aws-secret-key: the access key id found with it
	// Recover reads Value and KeyID again for git history replayed from the cache, whose values the
	// scan never read; only when the cache has no fresh answer. It runs on its provider's goroutine.
	Recover func(ctx context.Context) (value, keyID string, ok bool)
}

// Stats count what one run of the check did, for the connector's status line.
type Stats struct {
	Asked, Cached, Live, Dead, Unknown int
	Unsupported                        int // no provider endpoint for the type, or a key without its pair
	NotAllowed                         int // an owner or provider the config leaves out
	Interrupted                        int // the run's time ran out
	NoValue                            int // no value read or recovered
	Recovered                          int // values read again from git history
	Unregistered                       int
	Hints                              []string // what the owner can set up for lookups to classify more
}

func (s Stats) String() string {
	line := fmt.Sprintf("liveness: %d asked, %d from cache, %d values recovered from git history; %d live, %d dead, %d unregistered, %d unknown; %d unsupported, %d not allowed, %d without a value at hand, %d interrupted",
		s.Asked, s.Cached, s.Recovered, s.Live, s.Dead, s.Unregistered, s.Unknown, s.Unsupported, s.NotAllowed, s.NoValue, s.Interrupted)
	for _, h := range s.Hints {
		line += "; " + h
	}
	return line
}

func (s *Stats) asked(state secretrisk.LiveState) {
	s.Asked++
	switch state {
	case secretrisk.Live:
		s.Live++
	case secretrisk.Dead:
		s.Dead++
	case secretrisk.Unregistered:
		s.Unregistered++
	default:
		s.Unknown++
	}
}

// Checker runs the check. Zero values are the defaults: real endpoints, no cache, the real clock,
// defaultInterval, lookups without sources.
type Checker struct {
	Config   Config
	Bases    map[string][]string // replaces a provider's base URLs
	Cache    *Cache
	Now      func() time.Time
	Interval time.Duration // the least time between two calls, across providers
	Owner    Owner
	// Attribution is the owner of a fingerprint; nil allows nothing.
	Attribution func(fingerprint string) (attribution.Owner, bool)
}

// allows requires every fingerprint attributed to an allowed owner, so someone else's key never
// rides along with the owner's.
func (c *Checker) allows(p Probe, pv *provider) bool {
	if c.Attribution == nil || len(p.Fingerprints) == 0 || pv != nil && !c.Config.allowsProvider(pv.name) {
		return false
	}
	for _, fp := range p.Fingerprints {
		if o, ok := c.Attribution(fp); !ok || !c.Config.Allows(o, p.Type) {
			return false
		}
	}
	return true
}

const defaultInterval = 250 * time.Millisecond

// Check tries each probe the gates allow, unless the cache answers, and returns the results by
// fingerprint. A refused probe is neither answered from the cache nor recovered.
func (c *Checker) Check(ctx context.Context, probes []Probe) (map[string]secretrisk.Liveness, Stats) {
	now := c.now()
	out := map[string]secretrisk.Liveness{}
	var st Stats
	queues := map[*provider][]Probe{}
	for _, p := range probes {
		pv := forType(p.Type)
		if !c.allows(p, pv) {
			st.NotAllowed++
			continue
		}
		if r, ok := c.Cache.fresh(p.Fingerprints, now); ok {
			for _, fp := range p.Fingerprints {
				out[fp] = r
			}
			st.Cached++
			continue
		}
		switch {
		case p.Value == "" && p.Recover == nil:
			st.NoValue++
		case pv == nil, p.Recover == nil && forProbe(p) == nil: // an AWS secret key without its key id
			st.Unsupported++
		default:
			queues[pv] = append(queues[pv], p)
		}
	}
	lk := &lookups{owner: c.Owner, cfg: c.Config}
	var mu sync.Mutex
	var wg sync.WaitGroup
	lim := &limiter{every: c.interval()}
	count := func(n *int) {
		mu.Lock()
		*n++
		mu.Unlock()
	}
	for pv, queue := range queues {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, p := range queue {
				if ctx.Err() != nil {
					count(&st.Interrupted)
					continue
				}
				if p.Value == "" {
					v, id, ok := p.Recover(ctx)
					if !ok {
						count(&st.NoValue)
						continue
					}
					p.Value, p.KeyID = v, id
					count(&st.Recovered)
				}
				if forProbe(p) == nil {
					count(&st.Unsupported)
					continue
				}
				if pv.lookup == nil && lim.wait(ctx) != nil {
					count(&st.Interrupted)
					continue
				}
				r := withoutValue(c.ask(ctx, lk, pv, p), p)
				r.CheckedAt, r.Rules = c.now().UTC(), secretrisk.LivenessRules
				mu.Lock()
				st.asked(r.State)
				for _, fp := range p.Fingerprints {
					out[fp] = r
				}
				c.Cache.put(p.Fingerprints, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	st.Hints = lk.hints()
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
		return defaultInterval
	}
	return c.Interval
}

// ask tries each of the provider's hosts until one accepts the probe: dead only when every host
// says dead, else the first other answer.
func (c *Checker) ask(ctx context.Context, lk *lookups, pv *provider, p Probe) secretrisk.Liveness {
	if pv.lookup != nil {
		r := pv.lookup(ctx, lk, p)
		r.Provider, r.ByOwner = pv.name, true
		return r
	}
	bases := pv.bases
	if b, ok := c.Bases[pv.name]; ok {
		bases = b
	}
	var r secretrisk.Liveness
	for i, base := range bases {
		got := pv.ask(ctx, base, p)
		if got.State == secretrisk.Live {
			r = got
			break
		}
		if i == 0 || r.State == secretrisk.Dead {
			r = got
		}
	}
	r.Provider = pv.name
	return r
}

// valueWindow is the shortest run of a value that counts as holding it.
const valueWindow = 8

// withoutValue drops every field holding a part of the probe's value or key id: the last guard,
// whatever a provider echoes.
func withoutValue(r secretrisk.Liveness, p Probe) secretrisk.Liveness {
	holds := func(s string) bool {
		for _, v := range []string{p.Value, p.KeyID} {
			for i := 0; i+valueWindow <= len(v); i++ {
				if strings.Contains(s, v[i:i+valueWindow]) {
					return true
				}
			}
		}
		return false
	}
	if holds(r.Reason) {
		r.Reason = "error"
	}
	if holds(r.Account) {
		r.Account = ""
	}
	if holds(r.Endpoint) {
		method, rest, _ := strings.Cut(r.Endpoint, " ")
		host, _, _ := strings.Cut(rest, "/")
		r.Endpoint = method + " " + host
	}
	return r
}

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

func Providers() []string {
	out := make([]string, len(providers))
	for i, p := range providers {
		out[i] = p.name
	}
	sort.Strings(out)
	return out
}
