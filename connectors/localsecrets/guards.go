package localsecrets

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/segurata/segurata/connectors/internal/cli"
)

// Every external command goes through one of these guards, so a bug cannot make the connector run
// anything that writes, executes other programs or prints raw values to a file.

func refuse(args []string) error {
	return fmt.Errorf("%w: %s", cli.ErrRefused, strings.Join(args, " "))
}

// rgCheck refuses ripgrep flags that run other programs (--pre, --search-zip).
var rgCheck = cli.CheckFunc(func(args []string) error {
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "--pre") || a == "-z" || strings.HasPrefix(a, "--search-zip") {
			return refuse(args)
		}
	}
	return nil
})

// gitleaksCheck allows only `gitleaks version`, and `gitleaks git` with the report on stdout and
// its `git log` told not to run textconv drivers or external diffs (gitLogSafety).
var gitleaksCheck = cli.CheckFunc(func(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		return nil
	}
	if err := (cli.Allowlist{"git"}).Check(args); err != nil {
		return err
	}
	safe := false
	for i, a := range args {
		if strings.HasPrefix(a, "--report-path=") || strings.HasPrefix(a, "--log-opts=") ||
			(a == "--report-path" && (i+1 >= len(args) || args[i+1] != "-")) {
			return refuse(args)
		}
		if a == "--log-opts" && i+1 < len(args) {
			safe = strings.HasPrefix(args[i+1], gitLogSafety+" ")
		}
	}
	if !safe {
		return refuse(args)
	}
	return nil
})

// A repository's own config (.git/config, and the files it includes) can name programs that git
// runs during a read. The scan reads every repository under the home folder, cloned or extracted
// from anywhere, so every git it starts, directly or through gitleaks, overrides each of them.
// Command-line settings (GIT_CONFIG_COUNT) outrank every config file, includes and
// config.worktree among them.
var gitOverrides = [][2]string{
	{"core.fsmonitor", "false"},     // ls-files runs the fsmonitor hook program on the work tree
	{"core.hooksPath", "/dev/null"}, // no hook, whichever command would run one
	{"log.showSignature", "false"},  // git log would run gpg.program (or gpg.ssh/x509.program) on signed commits
	{"protocol.allow", "never"},     // no transport: core.sshCommand, remote helpers, credential helpers, core.gitProxy
	{"core.pager", "cat"},           // the pager runs only on a terminal; pinned anyway
}

// gitEnv is the environment added to every git and gitleaks process: gitOverrides, plus
//   - GIT_CONFIG_NOSYSTEM: the system config is skipped (the user's global config is theirs);
//   - GIT_NO_LAZY_FETCH: a partial clone does not fetch a missing object from its promisor
//     remote, which would run core.sshCommand or a remote helper (protocol.allow blocks it too);
//   - GIT_TERMINAL_PROMPT=0 and GIT_PAGER=cat: nothing waits on the terminal;
//   - GIT_OPTIONAL_LOCKS=0: reads do not refresh and rewrite the index.
//
// textconv drivers and external diffs (diff.<driver>.textconv, diff.<driver>.command and
// diff.external) have no single setting to override: only a patch runs them, and only gitleaks
// asks for one, with gitLogSafety. safe.directory keeps git's default: a repository owned by
// another account is refused, and its scan reported as failed.
var gitEnv = func() []string {
	env := []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_OPTIONAL_LOCKS=0",
		fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(gitOverrides))}
	for i, kv := range gitOverrides {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	return env
}()

// gitLogSafety opens every --log-opts gitleaks passes to its `git log -p`: no textconv driver
// and no external diff program from the repository's config or attributes.
const gitLogSafety = "--no-textconv --no-ext-diff"

// gitList allows only `git ls-files` and `git rev-list`, both read-only.
var gitList = cli.Allowlist{"ls-files", "rev-list"}

// gitLogFlags are the only flags `git log` may take: file lists and raw blob ids, never a patch
// (which could run an external diff or textconv program) and never --output.
var gitLogFlags = []string{"--all", "--remotes", "--full-history", "--no-renames", "--name-only", "--raw", "--no-abbrev", "-z", "--diff-filter=", "--format="}

// gitCheck is gitList plus the data-dump check's reads (dumpscan.go), `git log` with gitLogFlags
// and `git cat-file -s <object>` (a size), and the notebook check's (notebook.go), `git cat-file
// blob <commit>:<path>` (a file as committed; cat-file runs no textconv without --textconv).
// Options before the subcommand must be --git-dir= or --work-tree=.
var gitCheck = cli.CheckFunc(func(args []string) error {
	i := 0
	for i < len(args) && (strings.HasPrefix(args[i], "--git-dir=") || strings.HasPrefix(args[i], "--work-tree=")) {
		i++
	}
	rest := args[i:]
	switch {
	case len(rest) == 0:
		return refuse(args)
	case rest[0] == "log":
		for _, a := range rest[1:] {
			if a == "--" {
				return nil
			}
			if !logFlagAllowed(a) {
				return refuse(args)
			}
		}
		return nil
	case rest[0] == "cat-file":
		if len(rest) == 3 && rest[1] == "-s" && hexID.MatchString(rest[2]) {
			return nil
		}
		if len(rest) == 3 && rest[1] == "blob" && commitPath.MatchString(rest[2]) {
			return nil
		}
		return refuse(args)
	}
	return gitList.Check(args)
})

func logFlagAllowed(a string) bool {
	for _, f := range gitLogFlags {
		if a == f || (strings.HasSuffix(f, "=") && strings.HasPrefix(a, f)) {
			return true
		}
	}
	return false
}

// gitHeadCheck allows only `git cat-file blob <object>`, run through headExec so at most the
// first bytes of the blob are read.
var gitHeadCheck = cli.CheckFunc(func(args []string) error {
	if len(args) == 4 && strings.HasPrefix(args[0], "--git-dir=") && args[1] == "cat-file" && args[2] == "blob" && hexID.MatchString(args[3]) {
		return nil
	}
	return refuse(args)
})

// commitPath is `<abbreviated commit>:<path>`, the only object name cat-file blob may read.
var commitPath = regexp.MustCompile(`\A[0-9a-f]{7,40}:[^\x00]+\z`)

// ghCheck allows only `gh repo view <owner/name> --json visibility` and the two reads of who the
// user is (origin.go): `gh api user` and every page of `gh api user/orgs` (ghOrgsArgs), both GET.
var ghCheck = cli.CheckFunc(func(args []string) error {
	switch {
	case len(args) == 5 && args[0] == "repo" && args[1] == "view" && githubSlugRe.MatchString(args[2]) && args[3] == "--json" && args[4] == "visibility":
	case len(args) == 2 && args[0] == "api" && args[1] == "user":
	case slices.Equal(args, ghOrgsArgs):
	default:
		return refuse(args)
	}
	return nil
})

// sshKeygenCheck allows exactly two shapes: print the public key of a key opened with an empty
// passphrase (-y -P "" -f key), and print a key's fingerprint (-l -f key).
var sshKeygenCheck = cli.CheckFunc(func(args []string) error {
	switch {
	case len(args) == 5 && args[0] == "-y" && args[1] == "-P" && args[2] == "" && args[3] == "-f":
	case len(args) == 3 && args[0] == "-l" && args[1] == "-f":
	default:
		return refuse(args)
	}
	return nil
})

func guardRG(r cli.Runner) cli.Runner        { return cli.Guard(rgCheck, r) }
func guardGitleaks(r cli.Runner) cli.Runner  { return cli.Guard(gitleaksCheck, r) }
func guardGit(r cli.Runner) cli.Runner       { return cli.Guard(gitCheck, r) }
func guardGitHead(r cli.Runner) cli.Runner   { return cli.Guard(gitHeadCheck, r) }
func guardGH(r cli.Runner) cli.Runner        { return cli.Guard(ghCheck, r) }
func guardSSHKeygen(r cli.Runner) cli.Runner { return cli.Guard(sshKeygenCheck, r) }
