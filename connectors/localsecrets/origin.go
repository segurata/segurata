package localsecrets

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
)

// A secret committed to someone else's repository (a clone of instructure/canvas-lms, fastai,
// testssl.sh) is that project's to rotate, and so is one a fork inherited from its upstream. This
// file decides whose each repository is, from its GitHub remotes and the owner's GitHub account
// and organizations: those come from config (owned_owners) and from `gh api user` and every page
// of `gh api user/orgs`, asked once a week and cached in ~/.cache/segurata/github-owners.json
// when both answered.
//
// Limits: a repository without a GitHub remote has no known origin and counts as the owner's; so
// does every repository when neither gh nor owned_owners names an owner. A fork's inherited
// history is recognised only when the upstream is a configured remote whose branches were fetched.

// selfModule is segurata's own module path: its repositories (and worktrees) hold the synthetic
// secrets of the test corpus, so they are left out of the secret scan.
const selfModule = "github.com/segurata/segurata"

// ownersTTL is how long the owner's GitHub account and organizations are trusted from the cache.
const ownersTTL = 7 * 24 * time.Hour

// ownersCache is ~/.cache/segurata/github-owners.json.
type ownersCache struct {
	Login string    `json:"login"`
	Orgs  []string  `json:"orgs"`
	At    time.Time `json:"at"`
}

// repoOrigin is whose a repository is: secretrisk.OriginOwned, OriginThirdParty or "" (unknown),
// and for an owned fork the name of the remote that tracks its third-party upstream.
type repoOrigin struct {
	origin   string
	upstream string
}

// ownership holds the owner's names and the origins of the repositories seen in one run.
type ownership struct {
	once    sync.Once
	names   map[string]bool // lowercased GitHub logins and organizations
	mu      sync.Mutex
	origins map[string]repoOrigin
	self    map[string]bool
}

// ownerNames is the set of GitHub owners that are the user, from config and gh; empty when none
// is known.
func (s *scan) ownerNames() map[string]bool {
	s.own.once.Do(func() {
		names := map[string]bool{}
		for _, o := range s.cfg.ownedOwners {
			names[strings.ToLower(o)] = true
		}
		if c, ok := s.githubOwners(); ok {
			names[strings.ToLower(c.Login)] = true
			for _, o := range c.Orgs {
				names[strings.ToLower(o)] = true
			}
		}
		delete(names, "")
		s.own.names = names
	})
	return s.own.names
}

func (s *scan) ownersCachePath() string {
	return filepath.Join(filepath.Dir(s.c.CacheDir(s.home)), "github-owners.json")
}

// githubOwners is the gh user's login and organizations, from the cache while fresh, else from gh.
func (s *scan) githubOwners() (ownersCache, bool) {
	path := s.ownersCachePath()
	var c ownersCache
	if raw, err := os.ReadFile(path); err == nil && json.Unmarshal(raw, &c) == nil && c.Login != "" && s.now.Sub(c.At) < ownersTTL {
		return c, true
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.emit.Log("github owners cache: " + err.Error())
	}
	if s.c.GH == nil {
		return c, false
	}
	if _, err := s.c.LookPath("gh"); err != nil {
		return c, false
	}
	gh := guardGH(s.c.GH)
	out, err := gh.Run(s.ctx, "api", "user")
	var user struct{ Login string }
	if err != nil || json.Unmarshal(out, &user) != nil || user.Login == "" {
		s.emit.Log("gh api user: repository ownership unknown (set owned_owners): " + errString(err))
		return c, false
	}
	// Without every organization, their repositories would pass for third-party ones: an answer
	// short of a page is no answer, and it is not cached.
	out, err = gh.Run(s.ctx, ghOrgsArgs...)
	if err != nil {
		s.emit.Log("gh api user/orgs: repository ownership unknown (set owned_owners): " + err.Error())
		return c, false
	}
	c = ownersCache{Login: user.Login, Orgs: strings.Fields(string(out)), At: s.now}
	if err := statefile.WriteJSON(path, c); err != nil {
		s.emit.Log("github owners cache: " + err.Error())
	}
	return c, true
}

// ghOrgsArgs read the user's organizations, every page, one login per line.
var ghOrgsArgs = []string{"api", "--paginate", "--jq", ".[].login", "user/orgs?per_page=100"}

func errString(err error) string {
	if err == nil {
		return "unreadable answer"
	}
	return err.Error()
}

// originOf is whose the repository at root is.
func (s *scan) originOf(root string) repoOrigin {
	s.own.mu.Lock()
	if o, ok := s.own.origins[root]; ok {
		s.own.mu.Unlock()
		return o
	}
	s.own.mu.Unlock()
	o := classifyOrigin(githubRemotes(gitConfigPath(root)), s.ownerNames())
	s.own.mu.Lock()
	if s.own.origins == nil {
		s.own.origins = map[string]repoOrigin{}
	}
	s.own.origins[root] = o
	s.own.mu.Unlock()
	return o
}

// classifyOrigin judges a repository by its GitHub remotes, origin first: owned when the owner of
// origin is one of names, third-party otherwise. An owned repository with another remote whose
// owner is not the user is a fork, and that remote its upstream. Unknown without names or GitHub
// remotes.
func classifyOrigin(remotes []githubRemote, names map[string]bool) repoOrigin {
	if len(remotes) == 0 || len(names) == 0 {
		return repoOrigin{}
	}
	if !names[strings.ToLower(remotes[0].owner())] {
		return repoOrigin{origin: secretrisk.OriginThirdParty}
	}
	o := repoOrigin{origin: secretrisk.OriginOwned}
	for _, r := range remotes[1:] {
		if !names[strings.ToLower(r.owner())] {
			o.upstream = r.name
			break
		}
	}
	return o
}

// inheritedCommits returns which of commits (abbreviated ids, as evidence keeps them) a fork has
// from its upstream: those reachable from the upstream's remote-tracking branches. nil when the
// upstream has no fetched branches or git cannot tell (an id it does not know): no copy is then
// counted as inherited.
func (s *scan) inheritedCommits(repo, upstream string, commits []string) map[string]bool {
	commits = sortedUnique(commits)
	if len(commits) == 0 || !remoteNameRe.MatchString(upstream) {
		return nil
	}
	git := guardGit(s.c.Git)
	refs := "--remotes=" + upstream
	tips, err := git.Run(s.ctx, gitDirArg(repo), "rev-list", "--no-walk", refs)
	if err != nil || strings.TrimSpace(string(tips)) == "" {
		return nil
	}
	// The commits reachable from the leaks but not from the upstream: the fork's own history.
	out, err := git.Run(s.ctx, append(append([]string{gitDirArg(repo), "rev-list"}, commits...), "--not", refs)...)
	if err != nil {
		s.emit.Log("fork history " + s.tilde(repo) + ": " + err.Error())
		return nil
	}
	own := strings.Fields(string(out))
	inherited := map[string]bool{}
	for _, c := range commits {
		mine := false
		for _, o := range own {
			if strings.HasPrefix(o, c) {
				mine = true
				break
			}
		}
		if !mine {
			inherited[c] = true
		}
	}
	return inherited
}

var remoteNameRe = regexp.MustCompile(`\A[A-Za-z0-9._-]+\z`)

// isSelf reports whether the repository at root is segurata's own (its go.mod names selfModule).
func (s *scan) isSelf(root string) bool {
	s.own.mu.Lock()
	defer s.own.mu.Unlock()
	if v, ok := s.own.self[root]; ok {
		return v
	}
	if s.own.self == nil {
		s.own.self = map[string]bool{}
	}
	v := goModule(filepath.Join(root, "go.mod")) == selfModule
	s.own.self[root] = v
	return v
}

// goModule is the module path a go.mod file declares, "" when there is none.
func goModule(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}

// githubRemote is one remote of a repository on GitHub.
type githubRemote struct{ name, slug string }

func (r githubRemote) owner() string { o, _, _ := strings.Cut(r.slug, "/"); return o }

var githubURL = regexp.MustCompile(`github\.com[:/]([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$`)

// githubRemotes reads a git config file for its GitHub remotes, origin first, then in file order.
func githubRemotes(configPath string) []githubRemote {
	f, err := os.Open(configPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var section string
	var out []githubRemote
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		name, isRemote := strings.CutPrefix(section, `[remote "`)
		if !ok || strings.TrimSpace(k) != "url" || !isRemote {
			continue
		}
		m := githubURL.FindStringSubmatch(strings.TrimSpace(v))
		if m == nil {
			continue
		}
		r := githubRemote{name: strings.TrimSuffix(name, `"]`), slug: m[1] + "/" + m[2]}
		if r.name == "origin" {
			out = append([]githubRemote{r}, out...)
		} else {
			out = append(out, r)
		}
	}
	return out
}

// githubSlug is the owner/name of a repository's first GitHub remote, origin first.
func githubSlug(configPath string) string {
	if rs := githubRemotes(configPath); len(rs) > 0 {
		return rs[0].slug
	}
	return ""
}
