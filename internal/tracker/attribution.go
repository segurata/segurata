package tracker

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/homepath"
	"github.com/segurata/segurata/internal/secretrisk"
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
	opt.Expect, opt.Owned = cfg.Expect, ConfigOwned(cfg)
	return opt, nil
}

// ConfigOwned is what the config says the owner holds (config.OwnedAccounts) plus git's commit
// email: the accounts a sync and a scan's Known add to the tracker's own.
func ConfigOwned(cfg config.Config) attribution.Owned {
	o := cfg.OwnedAccounts()
	if e := ownerEmail(); e != "" {
		o = o.Merge(attribution.Owned{Emails: []string{e}})
	}
	return o
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

// attribute recomputes every rotate item's attribution, from its facts and what its locations say
// today, before the rules run so a rule narrowed to owners sees today's.
func (t *Tracker) attribute(owned attribution.Owned) {
	home, _ := os.UserHomeDir()
	owners := repoOwners{}
	for _, it := range t.Items {
		if it.Kind == KindRotate && it.Secret != nil {
			it.reattribute(owned, home, owners)
		}
	}
}

// reattribute rebuilds the facts its locations give: the GitHub owner of each repository it is
// committed in (kept on the location, so a clone deleted since still counts), the repositories
// without one, and the owner's own config files holding it.
func (it *Item) reattribute(owned attribution.Owned, home string, owners repoOwners) {
	res := it.attributionResult()
	f := &res.Facts
	f.RepoOwners, f.UnownedRepos, f.OwnConfig = nil, nil, nil
	for i := range it.Secret.Locations {
		l := &it.Secret.Locations[i]
		switch {
		case l.committed():
			l.RepoOwner = cmp.Or(owners.of(l.repoDir(home)), l.RepoOwner)
			if l.RepoOwner != "" {
				f.AddRepoOwner(l.RepoOwner)
			} else {
				f.AddUnownedRepo(cmp.Or(l.Repo, l.Path))
			}
		case l.ownConfig(home):
			f.AddOwnConfig(l.Path)
		}
	}
	*res = attribution.Attribute(res.Facts, owned)
	it.derive()
}

// committed reports whether the location is a commit that says whose the secret is: not history a
// fork inherited from its upstream (the upstream's secret), and not a third-party copy of a value
// the owner also holds elsewhere (reused: that other copy says whose it is).
func (l Location) committed() bool {
	return l.Tracked && l.Origin != secretrisk.OriginForkUpstream && !l.Reused
}

func (l Location) repoDir(home string) string {
	if l.Repo != "" {
		return homepath.Expand(l.Repo, home)
	}
	return filepath.Dir(homepath.Expand(l.Path, home))
}

// packageStores hold other people's code and copies of other files below the home's dot folders:
// a sample key there is not the owner's config.
var packageStores = []string{".cache/", ".npm/", ".nvm/", ".cargo/registry/", ".cargo/git/", ".rustup/", ".m2/repository/",
	".gradle/caches/", ".gradle/wrapper/", ".pyenv/", ".rbenv/", ".rvm/", ".gem/ruby/", ".gem/specs/", ".cocoapods/", ".pub-cache/",
	".vscode/", ".vscode-server/", ".vscode-insiders/", ".cursor/extensions/", ".ivy2/", ".sbt/", ".conda/", ".julia/",
	".nuget/packages/", ".deno/", ".bun/", ".pnpm-store/", ".yarn/", ".asdf/", ".volta/", ".fnm/", ".trash/", ".local/lib/",
	".local/pipx/", ".local/share/virtualenvs/", ".local/share/pnpm/", ".terraform.d/plugins/", ".claude/file-history/",
	".claude/paste-cache/", ".claude/plugins/"}

// ownConfig reports whether the location is a working file of the owner's own configuration: a dot
// file or folder of the home (or a PowerShell profile, or the Windows user environment), outside
// every git repository, package store, test, example and vendored folder. A cloned repository's
// .env, a transcript, a shell history or a log is not.
func (l Location) ownConfig(home string) bool {
	if l.Kind != "config" || !l.working() || l.Tracked || l.Origin != "" {
		return false
	}
	if strings.HasPrefix(l.Path, secretrisk.UserEnvKey+`\`) {
		return true
	}
	rel, ok := strings.CutPrefix(strings.ReplaceAll(l.Path, `\`, "/"), "~/")
	if !ok || home == "" {
		return false
	}
	lower := strings.ToLower(rel)
	dot := strings.HasPrefix(rel, ".") && !strings.HasPrefix(rel, "./") && !strings.HasPrefix(rel, "../")
	switch {
	case !dot && !secretrisk.IsPowerShellProfile(rel):
		return false
	case slices.ContainsFunc(packageStores, func(p string) bool { return strings.HasPrefix(lower, p) }),
		slices.ContainsFunc(strings.Split(lower, "/"), func(d string) bool { return d == "site-packages" || d == "dist-packages" }),
		secretrisk.RoleOf(lower) != secretrisk.RoleNone:
		return false
	}
	return !attribution.InRepository(homepath.Expand(l.Path, home))
}

type repoOwners map[string]string

func (r repoOwners) of(dir string) string {
	if o, ok := r[dir]; ok {
		return o
	}
	o, _ := attribution.RepoOwner(dir)
	r[dir] = o
	return o
}

// setOwner records the owner's own verdict, which wins over attribution everywhere; Unknown goes
// back to the automatic one.
func (t *Tracker) setOwner(it *Item, at time.Time, o attribution.Owner, reason string, extra attribution.Owned) error {
	if it.Secret == nil {
		return fmt.Errorf("%s is not a secret", it.ID)
	}
	if !slices.Contains(attribution.Owners, o) {
		return fmt.Errorf("owner %q: use mine, not-mine or unknown", o)
	}
	reason = strings.TrimSpace(reason)
	if o != attribution.Unknown && reason == "" {
		return errors.New("owner needs --reason")
	}
	res := it.attributionResult()
	res.Facts.Override = nil
	if o != attribution.Unknown {
		res.Facts.Override = &attribution.Override{Owner: o, Reason: reason, At: at.UTC()}
	}
	home, _ := os.UserHomeDir()
	it.reattribute(t.ownedAll(extra), home, repoOwners{})
	if o == attribution.Unknown {
		it.Log(at, EvOwner, actOwner, fmt.Sprintf("back to the automatic attribution: %s (%s confidence)", it.Owner(), res.Confidence))
	} else {
		it.Log(at, EvOwner, actOwner, string(o)+": "+reason)
	}
	return nil
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
