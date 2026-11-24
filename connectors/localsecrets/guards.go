package localsecrets

import (
	"fmt"
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

// gitleaksCheck allows only `gitleaks git` with the report on stdout, and `gitleaks version`.
var gitleaksCheck = cli.CheckFunc(func(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		return nil
	}
	if err := (cli.Allowlist{"git"}).Check(args); err != nil {
		return err
	}
	for i, a := range args {
		if strings.HasPrefix(a, "--report-path=") || (a == "--report-path" && (i+1 >= len(args) || args[i+1] != "-")) {
			return refuse(args)
		}
	}
	return nil
})

// gitList allows only `git ls-files` and `git rev-list`, both read-only.
var gitList = cli.Allowlist{"ls-files", "rev-list"}

// gitLogFlags are the only flags `git log` may take: file lists and raw blob ids, never a patch
// (which could run an external diff or textconv program) and never --output.
var gitLogFlags = []string{"--all", "--remotes", "--full-history", "--no-renames", "--name-only", "--raw", "--no-abbrev", "-z", "--diff-filter=", "--format="}

// gitCheck is gitList plus the data-dump check's reads (dumpscan.go): `git log` with gitLogFlags
// and `git cat-file -s <object>` (a size). Options before the subcommand must be --git-dir= or
// --work-tree=.
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

// ghCheck allows only `gh repo view <owner/name> --json visibility`.
var ghCheck = cli.CheckFunc(func(args []string) error {
	if len(args) == 5 && args[0] == "repo" && args[1] == "view" && githubSlugRe.MatchString(args[2]) && args[3] == "--json" && args[4] == "visibility" {
		return nil
	}
	return refuse(args)
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
