package liveness

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"slices"
	"sync"

	"github.com/segurata/segurata/connectors/internal/awsfiles"
	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Lookups classify a lone AWS key id (awskeys.go) and a private key (sshkeys.go) with the owner's
// own credentials, never sending the secret, through read-only guards. No command output or error
// text is kept: an error may echo its arguments.

// Owner is what the lookups run with; a nil runner leaves its lookup without that source.
type Owner struct {
	AWS        cli.Runner
	AWSIssuers func() map[string]awsfiles.Provider // a profile named not AWS is never signed in with; nil: all are
	GH         cli.Runner                          // logged in as the owner
	SSH        cli.Runner                          // for config ssh_hosts
	Home       string                              // ~/.ssh is read here
}

// lookups is one Check's state: what each lookup read once, and the setup hints.
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

// cliError is segurata's word for a failed command; the error itself may hold arguments.
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

var awsCLIErrorCode = regexp.MustCompile(`An error occurred \(([A-Za-z]+)\)`)

func unknown(endpoint, reason string) secretrisk.Liveness {
	return secretrisk.Liveness{State: secretrisk.Unknown, Endpoint: endpoint, Reason: reason}
}
