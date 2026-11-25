package liveness

import (
	"sync"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
)

// How long a result holds before the secret is tried again. A dead key rarely comes back; a live
// one can be revoked any day, and the owner wants to see that soon; an unregistered SSH key can be
// added to an account any day too. Unknown is never cached: the
// next run asks again.
const (
	LiveTTL = 24 * time.Hour
	DeadTTL = 7 * 24 * time.Hour
)

// cacheVersion 2 came with secretrisk.LivenessRules 2: a version-1 file's dead results may be a
// bare 401, so it is discarded and every secret asked again.
const cacheVersion = 2

// Cache keeps results by fingerprint in a 0600 file: fingerprint, state, when, provider and the
// account, never a value.
type Cache struct {
	path    string
	mu      sync.Mutex
	Results map[string]secretrisk.Liveness `json:"results"`
	Version int                            `json:"version"`
}

// LoadCache reads the cache at path; a missing, unreadable or older-format file is an empty cache.
func LoadCache(path string) *Cache {
	c := &Cache{path: path}
	if found, err := statefile.ReadJSON(path, c); found && err == nil && c.Version == cacheVersion && c.Results != nil {
		return c
	}
	return &Cache{path: path, Results: map[string]secretrisk.Liveness{}}
}

// Save writes the cache, leaving out results past their TTL at now. A nil cache saves nothing.
func (c *Cache) Save(now time.Time) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for fp, r := range c.Results {
		if !withinTTL(r, now) {
			delete(c.Results, fp)
		}
	}
	c.Version = cacheVersion
	return statefile.WriteJSON(c.path, c)
}

// fresh returns the cached result when every fingerprint has one, all the same state and within
// its TTL.
func (c *Cache) fresh(fps []string, now time.Time) (secretrisk.Liveness, bool) {
	if c == nil || len(fps) == 0 {
		return secretrisk.Liveness{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	first, ok := c.Results[fps[0]]
	if !ok || !withinTTL(first, now) {
		return first, false
	}
	for _, fp := range fps[1:] {
		if r, ok := c.Results[fp]; !ok || r.State != first.State || !withinTTL(r, now) {
			return first, false
		}
	}
	return first, true
}

func (c *Cache) put(fps []string, r secretrisk.Liveness) {
	if c == nil || r.State == secretrisk.Unknown {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, fp := range fps {
		c.Results[fp] = r
	}
}

// withinTTL reports whether a live or dead result is still young enough to stand for a new check.
// One dated after now (a clock that jumped forward) never is.
func withinTTL(r secretrisk.Liveness, now time.Time) bool {
	if r.CheckedAt.After(now) {
		return false
	}
	switch r.State {
	case secretrisk.Live, secretrisk.Unregistered:
		return now.Sub(r.CheckedAt) < LiveTTL
	case secretrisk.Dead:
		return now.Sub(r.CheckedAt) < DeadTTL
	}
	return false
}
