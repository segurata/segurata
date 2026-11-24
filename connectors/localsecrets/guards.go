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
func guardGit(r cli.Runner) cli.Runner       { return cli.Guard(gitList, r) }
func guardSSHKeygen(r cli.Runner) cli.Runner { return cli.Guard(sshKeygenCheck, r) }
