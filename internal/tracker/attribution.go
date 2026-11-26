package tracker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/finding"
)

// ownerEmail is a variable so tests stay hermetic. See docs/architecture.md, "Attribution".
var ownerEmail = attribution.GitEmail

// ConfiguredSync fills the expected rules and owned accounts from the config at path, plus git's
// commit email; "" takes nothing, from the config or from git.
func ConfiguredSync(path string, opt SyncOptions) (SyncOptions, error) {
	if path == "" {
		return opt, nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		return opt, fmt.Errorf("config: %w", err)
	}
	opt.Expect, opt.Owned = cfg.Expect, cfg.Owned
	if e := ownerEmail(); e != "" {
		opt.Owned = opt.Owned.Merge(attribution.Owned{Emails: []string{e}})
	}
	return opt, nil
}

func (t *Tracker) ownedAll(extra attribution.Owned) attribution.Owned {
	var o attribution.Owned
	if t.Owned != nil {
		o = *t.Owned
	}
	return o.Merge(extra)
}

// Known is what attribution knows now, for a scan to ask before it acts on a secret.
func (t *Tracker) Known(extra attribution.Owned) *attribution.Known {
	k := &attribution.Known{Owned: t.ownedAll(extra), Facts: map[string]attribution.Facts{}}
	for _, it := range t.Items {
		if it.Kind == KindRotate && it.Secret != nil && it.Secret.Attribution != nil {
			k.Facts[it.Fingerprint] = it.Secret.Attribution.Facts
		}
	}
	return k
}

func (t *Tracker) discover(runs []*run) {
	var fs []finding.Finding
	var sts []finding.Status
	for _, r := range runs {
		fs = append(fs, r.findings...)
		sts = append(sts, r.statuses...)
	}
	found := attribution.Discover(fs, sts)
	merged := t.ownedAll(found)
	t.Owned = &merged
}

// collectClaims folds the claims of the folded sightings into their items' facts, never dropping
// one.
func (t *Tracker) collectClaims(folded map[string]*run) {
	by := t.byFingerprint()
	for _, r := range folded {
		if !r.isSecrets() {
			continue
		}
		for _, s := range sightingsOf(r.findings) {
			if it := by[s.Evidence.Fingerprint]; it != nil && !s.Evidence.Claims.Empty() {
				it.attributionResult().Facts.Add(s.Evidence.Claims)
			}
		}
	}
	for _, it := range by {
		if c := it.livenessClaims(); !c.Empty() {
			it.attributionResult().Facts.Add(c)
		}
	}
}

func (it *Item) attributionResult() *attribution.Result {
	if it.Secret.Attribution == nil {
		it.Secret.Attribution = &attribution.Result{}
	}
	return it.Secret.Attribution
}

// attribute recomputes every rotate item's attribution, adding the GitHub owners of its
// repositories, before the rules run so a rule narrowed to owners sees today's.
func (t *Tracker) attribute(owned attribution.Owned) {
	owners := repoOwners{}
	for _, it := range t.Items {
		if it.Kind != KindRotate || it.Secret == nil {
			continue
		}
		res := it.attributionResult()
		for _, l := range it.Secret.Locations {
			if l.Kind == "repo" {
				res.Facts.AddRepoOwner(owners.of(l.Path))
			}
		}
		*res = attribution.Attribute(res.Facts, owned)
		it.derive()
	}
}

type repoOwners map[string]string

func (r repoOwners) of(p string) string {
	dir := filepath.Dir(expandHome(p))
	if o, ok := r[dir]; ok {
		return o
	}
	o, _ := attribution.RepoOwner(dir)
	r[dir] = o
	return o
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}

func (t *Tracker) ownerCounts(keep func(*Item) bool) map[attribution.Owner]int {
	m := map[attribution.Owner]int{}
	for _, it := range t.Items {
		if it.Kind == KindRotate && keep(it) {
			m[it.Owner()]++
		}
	}
	return m
}
