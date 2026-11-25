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
	// AWSProfiles are the owner's aws CLI profiles lone key ids are looked up with; nil: every
	// profile `aws configure list-profiles` names.
	AWSProfiles []string
	// SSHHosts are hosts whose ~/.ssh/authorized_keys private keys are looked up in (opt-in).
	SSHHosts []string
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
	if v, ok := m["aws_profiles"]; ok {
		if c.AWSProfiles, err = stringList(v, "liveness.aws_profiles"); err != nil {
			return c, err
		}
	}
	if v, ok := m["ssh_hosts"]; ok {
		if c.SSHHosts, err = stringList(v, "liveness.ssh_hosts"); err != nil {
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

// Allows reports whether the owner lets the check try a secret of the type attributed to owner. A
// lookup with the owner's credentials (a lone AWS key id, a private key) never sends the secret,
// so it runs for mine and unknown whatever owners says; someone else's secret is never looked at.
func (c Config) Allows(owner attribution.Owner, typ string) bool {
	if owner == attribution.NotMine {
		return false
	}
	if pv := forType(typ); pv != nil && pv.lookup != nil {
		return true
	}
	return slices.Contains(c.Owners, owner)
}

// allowsProvider reports whether the config's provider allowlist names the provider.
func (c Config) allowsProvider(name string) bool {
	return c.Providers == nil || slices.Contains(c.Providers, name)
}

// Probe is one secret to try. Value never leaves this package except in the request to its
// provider. A probe without a value (a secret replayed from the git history cache, whose value the
// run never read) only looks in the cache.
type Probe struct {
	// Fingerprints get the result: the secret's own, and for an AWS key pair the key id's too.
	Fingerprints []string
	Type         string // a secretrisk catalog type
	Value        string
	KeyID        string // aws-secret-key: the access key id found with it
	// Recover reads Value (and KeyID) again when the probe has none, and is called only when the
	// cache has no fresh answer and the run still has time: for git history replayed from the
	// cache, whose values the scan never read. ok is false when it could not. It runs on its
	// provider's goroutine, concurrently with other providers' probes.
	Recover func(ctx context.Context) (value, keyID string, ok bool)
}

// Stats count what one run of the check did, for the connector's status line.
type Stats struct {
	Asked, Cached, Live, Dead, Unknown int
	Unsupported                        int // no provider endpoint for the type, or a key without its pair
	NotAllowed                         int // attributed to an owner the config leaves out, or a provider it leaves out
	Interrupted                        int // not asked: the run's time ran out
	NoValue                            int // not asked: no value, read or recovered (cached git history)
	Recovered                          int // values read again from git history at check time
	Unregistered                       int // SSH keys registered nowhere the lookup can see
	// Hints say what the owner can set up for the lookups to classify more: a permission, a scope.
	Hints []string
}

func (s Stats) String() string {
	line := fmt.Sprintf("liveness: %d asked, %d from cache, %d values recovered from git history; %d live, %d dead, %d unregistered, %d unknown; %d unsupported, %d not allowed, %d without a value at hand, %d interrupted",
		s.Asked, s.Cached, s.Recovered, s.Live, s.Dead, s.Unregistered, s.Unknown, s.Unsupported, s.NotAllowed, s.NoValue, s.Interrupted)
	for _, h := range s.Hints {
		line += "; " + h
	}
	return line
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
	// Owner runs the lookups (lookup.go); its zero value leaves them without sources.
	Owner Owner
	// Attribution is the owner of a fingerprint, false when the run has none for it. Check tries a
	// probe only when Config.Allows every one of its fingerprints; nil allows nothing.
	Attribution func(fingerprint string) (attribution.Owner, bool)
}

// allows reports whether the owner and provider gates let the probe through: every fingerprint
// attributed to an owner the config allows (someone else's key never rides along with the owner's),
// and the provider in the allowlist.
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

// DefaultInterval keeps the whole check under four calls a second.
const DefaultInterval = 250 * time.Millisecond

// Check tries each probe the config allows, one call per probe, and returns the result by
// fingerprint. The gates come first: a probe they refuse is neither answered from the cache nor
// recovered. A probe whose fingerprints all have a fresh cached result is not asked again.
// Results of probes asked are cached; ctx ending stops the calls that have not started.
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
				st.Asked++
				switch r.State {
				case secretrisk.Live:
					st.Live++
				case secretrisk.Dead:
					st.Dead++
				case secretrisk.Unregistered:
					st.Unregistered++
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
		return DefaultInterval
	}
	return c.Interval
}

// ask tries the probe on each of the provider's hosts until one accepts it: dead only when every
// host says dead, else the first other answer. A lookup runs once, with the owner's credentials.
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

// withoutValue is r with every field that holds a part of the probe's value or key id (any
// valueWindow characters of it) dropped: the reason becomes "error", the account and the endpoint's
// path go. The judges keep no provider message, and providerText keeps only short codes; this is
// the last guard, whatever a provider echoes.
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
