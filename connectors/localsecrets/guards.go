package localsecrets

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/gitlocal"
)

// Every external command goes through a guard, so a bug cannot make the connector write, run
// other programs or put raw values in a file.

func refuse(args []string) error {
	return fmt.Errorf("%w: %s", cli.ErrRefused, strings.Join(args, " "))
}

// rgCheck refuses the flags that run other programs.
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

// gitleaksCheck allows `gitleaks version`, and `gitleaks git` reporting to stdout with
// gitLogSafety.
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

// unsafeRepos names safe.directory when git refuses a repository another account owns.
func unsafeRepos(r cli.Runner) cli.Runner {
	return cli.RunnerFunc(func(ctx context.Context, args ...string) ([]byte, error) {
		out, err := r.Run(ctx, args...)
		if err != nil {
			err = gitlocal.Classify(err, cli.Stderr(err))
		}
		return out, err
	})
}

// gitEnv keeps git to local data, even in an untrusted repository.
var gitEnv = gitlocal.ReadEnv()

// gitLogSafety opens every --log-opts: no textconv or external diff from the repository.
const gitLogSafety = "--no-textconv --no-ext-diff"

var gitList = cli.Allowlist{"ls-files", "rev-list"}

// gitLogFlags never ask for a patch (external diff, textconv) or --output.
var gitLogFlags = []string{"--all", "--remotes", "--full-history", "--no-renames", "--name-only", "--raw", "--no-abbrev", "-z", "--diff-filter=", "--format="}

// gitCheck is gitList, `git log` with gitLogFlags, `cat-file -s` of an object or a committed file
// and `cat-file blob` of a committed file (no textconv without --textconv). Only --git-dir= and
// --work-tree= may precede the subcommand.
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
		if len(rest) == 3 && rest[1] == "-s" && (hexID.MatchString(rest[2]) || commitPath.MatchString(rest[2])) {
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

// gitHeadCheck allows only `git cat-file blob <object>`, which headExec cuts short.
var gitHeadCheck = cli.CheckFunc(func(args []string) error {
	if len(args) == 4 && strings.HasPrefix(args[0], "--git-dir=") && args[1] == "cat-file" && args[2] == "blob" && hexID.MatchString(args[3]) {
		return nil
	}
	return refuse(args)
})

var commitPath = regexp.MustCompile(`\A[0-9a-f]{7,40}:[^\x00]+\z`)

// ghCheck allows a repository's visibility and the GETs of the user and their organizations.
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

// sshKeygenCheck allows opening a key with an empty passphrase and printing a fingerprint.
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
func guardGit(r cli.Runner) cli.Runner       { return cli.Guard(gitCheck, unsafeRepos(r)) }
func guardGitHead(r cli.Runner) cli.Runner   { return cli.Guard(gitHeadCheck, unsafeRepos(r)) }
func guardGH(r cli.Runner) cli.Runner        { return cli.Guard(ghCheck, r) }
func guardSSHKeygen(r cli.Runner) cli.Runner { return cli.Guard(sshKeygenCheck, r) }
