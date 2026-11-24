package attribution

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RepoOwner is the GitHub owner (user or organization) of the repository that holds path, read
// offline from its origin remote in .git/config; ok is false outside a repository, without an
// origin, or with a remote that is not on GitHub. Worktrees are followed to their main
// repository's config.
func RepoOwner(path string) (string, bool) {
	cfg := gitConfig(path)
	if cfg == "" {
		return "", false
	}
	return githubOwner(originURL(cfg))
}

// gitConfig finds the config file of the repository holding path: the nearest .git above it, a
// directory or a worktree's "gitdir:" file.
func gitConfig(path string) string {
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		dot := filepath.Join(dir, ".git")
		if st, err := os.Stat(dot); err == nil {
			if st.IsDir() {
				return filepath.Join(dot, "config")
			}
			raw, err := os.ReadFile(dot)
			if err != nil {
				return ""
			}
			gitdir, ok := strings.CutPrefix(strings.TrimSpace(string(raw)), "gitdir:")
			if !ok {
				return ""
			}
			gitdir = strings.TrimSpace(gitdir)
			if !filepath.IsAbs(gitdir) {
				gitdir = filepath.Join(dir, gitdir)
			}
			if common, err := os.ReadFile(filepath.Join(gitdir, "commondir")); err == nil {
				c := strings.TrimSpace(string(common))
				if !filepath.IsAbs(c) {
					c = filepath.Join(gitdir, c)
				}
				gitdir = c
			}
			return filepath.Join(gitdir, "config")
		}
		if parent := filepath.Dir(dir); parent == dir {
			return ""
		}
	}
}

// originURL is the url of [remote "origin"] in a git config file.
func originURL(cfg string) string {
	f, err := os.Open(cfg)
	if err != nil {
		return ""
	}
	defer f.Close()
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			in = line == `[remote "origin"]`
			continue
		}
		if k, v, ok := strings.Cut(line, "="); in && ok && strings.TrimSpace(k) == "url" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// githubRemote reads the owner from git@github.com:o/r.git, ssh://git@github.com/o/r and
// https://github.com/o/r(.git), with or without credentials or a port.
var githubRemote = regexp.MustCompile(`(?i)^(?:[a-z+]+://)?(?:[^@/]+@)?github\.com(?::\d+)?[:/]([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/`)

func githubOwner(url string) (string, bool) {
	if m := githubRemote.FindStringSubmatch(url); m != nil {
		return m[1], true
	}
	return "", false
}
