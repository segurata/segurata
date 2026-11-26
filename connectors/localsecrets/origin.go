package localsecrets

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
)

// A secret in someone else's repository, or inherited by a fork from its upstream, is that
// project's to rotate. Whose a repository is comes from its GitHub remotes and the owner's names
// (owned_owners and gh, cached weekly). Without a GitHub remote or any known owner its origin is
// unknown and it counts as the owner's.

const ownersTTL = 7 * 24 * time.Hour

type ownersCache struct {
	Login string    `json:"login"`
	Orgs  []string  `json:"orgs"`
	At    time.Time `json:"at"`
}

// repoOrigin is whose a repository is ("" unknown) and, for an owned fork, its upstream remote.
type repoOrigin struct {
	origin   string
	upstream string
}

type ownership struct {
	once    sync.Once
	names   map[string]bool // lowercased GitHub logins and organizations
	mu      sync.Mutex
	origins map[string]repoOrigin
}

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

func (s *scan) githubOwners() (ownersCache, bool) {
	path := s.ownersCachePath()
	var c ownersCache
	found, err := statefile.ReadJSON(path, &c)
	if err != nil {
		s.emit.Log("github owners cache: " + err.Error())
	}
	if found && err == nil && c.Login != "" && s.now.Sub(c.At) < ownersTTL {
		return c, true
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
	// A missing organization would pass its repositories for third-party ones: all pages or none.
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

var ghOrgsArgs = []string{"api", "--paginate", "--jq", ".[].login", "user/orgs?per_page=100"}

func errString(err error) string {
	if err == nil {
		return "unreadable answer"
	}
	return err.Error()
}

func (s *scan) originOf(root string) repoOrigin {
	names := s.ownerNames()
	s.own.mu.Lock()
	defer s.own.mu.Unlock()
	if o, ok := s.own.origins[root]; ok {
		return o
	}
	if s.own.origins == nil {
		s.own.origins = map[string]repoOrigin{}
	}
	o := classifyOrigin(githubRemotes(gitConfigPath(root)), names)
	s.own.origins[root] = o
	return o
}

// classifyOrigin judges by origin's owner; an owned repository with a third-party remote is a fork
// of it.
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

// inheritedCommits are the commits (abbreviated) reachable from the upstream's fetched branches;
// nil when git cannot tell.
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
	out, err := git.Run(s.ctx, append(append([]string{gitDirArg(repo), "rev-list"}, commits...), "--not", refs)...)
	if err != nil {
		s.emit.Log("fork history " + s.tilde(repo) + ": " + err.Error())
		return nil
	}
	own := strings.Fields(string(out)) // the fork's own history
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

type githubRemote struct{ name, slug string }

func (r githubRemote) owner() string { o, _, _ := strings.Cut(r.slug, "/"); return o }

var githubURL = regexp.MustCompile(`github\.com[:/]([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$`)

// githubRemotes are origin first, then in file order.
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

func githubSlug(configPath string) string {
	if rs := githubRemotes(configPath); len(rs) > 0 {
		return rs[0].slug
	}
	return ""
}
