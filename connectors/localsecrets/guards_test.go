package localsecrets

import (
	"errors"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/internal/cli"
)

func TestGuards(t *testing.T) {
	blob := strings.Repeat("a", 40)
	safeLog := gitLogSafety + " --all"
	for _, tc := range []struct {
		name    string
		check   cli.Checker
		allowed [][]string
		refused [][]string
	}{
		{"rg", rgCheck,
			[][]string{{"-o", "-e", "x", "--", "--pre"}},
			[][]string{{"--pre", "sh", "-e", "x"}, {"--pre=sh"}, {"-z", "-e", "x"}, {"--search-zip"}}},
		{"gitleaks", gitleaksCheck,
			[][]string{{"version"}, {"git", "--log-opts", safeLog, "repo"}, {"git", "--report-path", "-", "--log-opts", safeLog, "repo"}},
			[][]string{
				{"git", "--report-path", "/tmp/r.json", "--log-opts", safeLog, "repo"}, {"git", "--report-path=r.json", "repo"},
				{"git", "--report-path", "-", "repo"}, {"git", "--log-opts", "--all", "repo"}, {"git", "--log-opts=" + safeLog, "repo"},
				{"dir", "repo"}, {"version", "--config=x"},
			}},
		{"git", gitCheck,
			[][]string{
				{"--git-dir=/r/.git", "--work-tree=/r", "ls-files", "-z"},
				{"--git-dir=/r/.git", "--work-tree=/r", "ls-files", "-s", "-z"},
				{"--git-dir=/r/.git", "rev-list", "--no-walk", "--all"},
				{"--git-dir=/r/.git", "rev-list", "0123456789", "--not", "--remotes=upstream"},
				{"--git-dir=/r/.git", "log", "--all", "--no-renames", "--diff-filter=A", "--name-only", "--format=", "-z"},
				{"--git-dir=/r/.git", "log", "--all", "--raw", "--no-abbrev", "--format=%x01%H", "-z", "--", ":(literal)-p", "--output=x"},
				{"--git-dir=/r/.git", "cat-file", "-s", blob},
				{"--git-dir=/r/.git", "cat-file", "-s", "0123456789:a/b.env"},
				{"--git-dir=/r/.git", "cat-file", "blob", "0123456789:a/b.env"},
				{"--git-dir=/r/.git", "cat-file", "blob", "0123456789:nb/a b.ipynb"},
			},
			[][]string{
				{"--git-dir=/r/.git", "config", "x"}, {"--git-dir=/r/.git"}, {"-c", "core.pager=sh", "log"},
				{"--git-dir=/r/.git", "log", "-p"}, {"--git-dir=/r/.git", "log", "--output=/tmp/x", "--all"},
				{"--git-dir=/r/.git", "log", "--ext-diff", "--all"}, {"--git-dir=/r/.git", "log", "--textconv"},
				{"--git-dir=/r/.git", "cat-file", "-p", blob}, {"--git-dir=/r/.git", "cat-file", "-p", "0123456789:a/b.env"},
				{"--git-dir=/r/.git", "cat-file", "blob", blob}, {"--git-dir=/r/.git", "cat-file", "-s", "HEAD"},
				{"--git-dir=/r/.git", "cat-file", "-s", "HEAD:x"}, {"--git-dir=/r/.git", "cat-file", "blob", "HEAD:x"},
				{"--git-dir=/r/.git", "cat-file", "--textconv", "0123456789:x"},
			}},
		{"git head", gitHeadCheck,
			[][]string{{"--git-dir=/r/.git", "cat-file", "blob", blob}},
			[][]string{{"--git-dir=/r/.git", "cat-file", "blob", "HEAD:x"}, {"--git-dir=/r/.git", "cat-file", "-p", blob}}},
		{"gh", ghCheck,
			[][]string{{"repo", "view", "o/r", "--json", "visibility"}, {"api", "user"}, strings.Fields(ghOrgsCall)},
			[][]string{
				{"repo", "delete", "o/r"}, {"repo", "view", "o/r", "--web"}, {"api", "-X", "DELETE", "repos/o/r"},
				{"api", "-X", "DELETE", "user"}, {"api", "user/repos"}, {"api", "graphql"},
				{"api", "--paginate", "--jq", ".[].login", "user/repos"},
			}},
		{"ssh-keygen", sshKeygenCheck,
			[][]string{{"-y", "-P", "", "-f", "k"}, {"-l", "-f", "k.pub"}},
			[][]string{{"-p", "-f", "k"}, {"-y", "-P", "guess", "-f", "k"}}},
	} {
		for _, args := range tc.allowed {
			if err := tc.check.Check(args); err != nil {
				t.Errorf("%s refused %q: %v", tc.name, args, err)
			}
		}
		for _, args := range tc.refused {
			if err := tc.check.Check(args); !errors.Is(err, cli.ErrRefused) {
				t.Errorf("%s allowed %q", tc.name, args)
			}
		}
	}
}
