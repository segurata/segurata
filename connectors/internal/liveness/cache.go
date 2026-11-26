package liveness

import (
	"sync"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
)

// A dead key rarely comes back; a live one can be revoked, and an unregistered SSH key registered,
// any day. Unknown is never cached.
const (
	liveTTL = 24 * time.Hour
	deadTTL = 7 * 24 * time.Hour
)

// cacheVersion 2 came with secretrisk.LivenessRules 2: a version-1 dead result may be a bare 401.
const cacheVersion = 2

// Cache keeps results by fingerprint in a 0600 file, never a value.
type Cache struct {
	path    string
	mu      sync.Mutex
	Results map[string]secretrisk.Liveness `json:"results"`
	Version int                            `json:"version"`
}

// LoadCache treats a missing, unreadable or older-format file as an empty cache.
func LoadCache(path string) *Cache {
	c := &Cache{path: path}
	if found, err := statefile.ReadJSON(path, c); found && err == nil && c.Version == cacheVersion && c.Results != nil {
		return c
	}
	return &Cache{path: path, Results: map[string]secretrisk.Liveness{}}
}

// Save leaves out results past their TTL. A nil cache saves nothing.
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

// fresh needs every fingerprint cached, in one state and within its TTL.
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

// withinTTL is false for a result dated after now: a clock that jumped forward.
func withinTTL(r secretrisk.Liveness, now time.Time) bool {
	if r.CheckedAt.After(now) {
		return false
	}
	switch r.State {
	case secretrisk.Live, secretrisk.Unregistered:
		return now.Sub(r.CheckedAt) < liveTTL
	case secretrisk.Dead:
		return now.Sub(r.CheckedAt) < deadTTL
	}
	return false
}
