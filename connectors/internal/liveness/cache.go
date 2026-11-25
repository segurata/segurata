package liveness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
)

// How long a result holds before the secret is tried again. A dead key rarely comes back; a live
// one can be revoked any day, and the owner wants to see that soon. Unknown is never cached: the
// next run asks again.
const (
	LiveTTL = 24 * time.Hour
	DeadTTL = 7 * 24 * time.Hour
)

const cacheVersion = 1

// DefaultCachePath is ~/.cache/segurata/liveness.json.
func DefaultCachePath(home string) string {
	return filepath.Join(home, ".cache", "segurata", "liveness.json")
}

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
	raw, err := os.ReadFile(path)
	if err == nil && json.Unmarshal(raw, c) == nil && c.Version == cacheVersion {
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
func withinTTL(r secretrisk.Liveness, now time.Time) bool {
	switch r.State {
	case secretrisk.Live:
		return now.Sub(r.CheckedAt) < LiveTTL
	case secretrisk.Dead:
		return now.Sub(r.CheckedAt) < DeadTTL
	}
	return false
}
