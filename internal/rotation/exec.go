package rotation

import (
	"context"
	"fmt"

	"github.com/segurata/segurata/internal/keychain"
)

// Runner runs one external program with stdin and returns its stdout. Rotation runs only pbpaste,
// pbcopy and security, by absolute path; a secret value may travel on stdin, never in args. Tests
// inject a recorder.
type Runner = keychain.Runner

const (
	pbpaste  = "/usr/bin/pbpaste"
	pbcopy   = "/usr/bin/pbcopy"
	security = keychain.Security
)

// clipboard reads and clears the macOS pasteboard.
type clipboard struct{ run Runner }

func (c clipboard) paste(ctx context.Context) ([]byte, error) {
	return c.run(ctx, nil, pbpaste)
}

// clear empties the pasteboard: pbcopy with nothing on stdin.
func (c clipboard) clear(ctx context.Context) error {
	_, err := c.run(ctx, nil, pbcopy)
	return err
}

// lookupLine is the shell line that reads the value back, as docs/secrets.md recommends.
func lookupLine(service string) string {
	return fmt.Sprintf(`"$(security find-generic-password -a "$USER" -s %s -w)"`, service)
}
