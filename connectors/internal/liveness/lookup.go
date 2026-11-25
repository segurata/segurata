package liveness

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"slices"
	"sync"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Lookups classify the secrets no provider endpoint can try by themselves: a lone AWS access key
// id (awskeys.go) and a private key (sshkeys.go). They use the owner's own credentials (the aws
// CLI's profiles, gh's login, ~/.ssh, ssh to hosts the owner lists) and never send the secret: the
// key id is compared with the owner's IAM inventory, the private key's public half with the keys
// the owner registered. Every command goes through a read-only guard. Errors are reduced to
// segurata's own words and a setup hint; no command output or error text is kept, since an
// error may echo its arguments. See docs/architecture.md, "Liveness".

// Owner is what the lookups run with. A nil runner leaves its lookup without that source.
type Owner struct {
	AWS  cli.Runner // the aws CLI
	GH   cli.Runner // the gh CLI, logged in as the owner
	SSH  cli.Runner // ssh, for config ssh_hosts
	Home string     // ~/.ssh is read here
}

// lookups is one Check's state: what each lookup read once for every probe, and the setup hints
// for the status line.
type lookups struct {
	owner Owner
	cfg   Config

	awsOnce sync.Once
	aws     *awsInventory
	sshOnce sync.Once
	ssh     *sshRegistry

	mu    sync.Mutex
	notes []string
}

// hint records a setup hint once.
func (l *lookups) hint(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !slices.Contains(l.notes, s) {
		l.notes = append(l.notes, s)
	}
}

func (l *lookups) hints() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.notes)
}

// cliError is segurata's word for a failed command: the AWS error code ("AccessDenied"), "not
// installed", "timed out" or "failed". The error itself is never kept: its text may hold arguments
// and the CLI's stderr.
func cliError(err error) string {
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return "not installed"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, cli.ErrRefused):
		return "refused by segurata's read-only guard"
	}
	if m := awsCLIErrorCode.FindStringSubmatch(err.Error()); m != nil {
		return m[1]
	}
	return "failed"
}

// awsCLIErrorCode is the code in the aws CLI's "An error occurred (AccessDenied) when calling …".
var awsCLIErrorCode = regexp.MustCompile(`An error occurred \(([A-Za-z]+)\)`)

func unknown(endpoint, reason string) secretrisk.Liveness {
	return secretrisk.Liveness{State: secretrisk.Unknown, Endpoint: endpoint, Reason: reason}
}
