package rotation

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner runs one external program with stdin and returns its stdout. Rotation runs only the
// commands below, by absolute path. A secret value may travel on stdin, never in args: args show
// up in process listings, stdin does not. Tests inject a recorder.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

const (
	pbpaste  = "/usr/bin/pbpaste"
	pbcopy   = "/usr/bin/pbcopy"
	security = "/usr/bin/security"
)

// Exec is the real Runner. Its error carries stderr, never stdout: stdout of `security -i`
// echoes nothing today, but it is the channel a value would come back on.
func Exec(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// scrub removes every copy of value from a message before it is printed.
func scrub(msg, value string) string {
	if value == "" {
		return msg
	}
	return strings.ReplaceAll(msg, value, "[new value]")
}

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

// keychain stores and reads generic passwords in the login Keychain.
type keychain struct {
	run     Runner
	account string
}

// store adds or updates (-U) the item through `security -i`, which reads its commands from stdin,
// so the value never appears in an argument list.
func (k keychain) store(ctx context.Context, service, value string) error {
	cmd := fmt.Sprintf("add-generic-password -U -a %s -s %s -w %s\n", k.account, service, value)
	if _, err := k.run(ctx, []byte(cmd), security, "-i"); err != nil {
		return fmt.Errorf("storing %s in the Keychain: %s", service, scrub(err.Error(), value))
	}
	return nil
}

// read returns the stored value, to check it in memory; it is never printed.
func (k keychain) read(ctx context.Context, service string) (string, error) {
	out, err := k.run(ctx, nil, security, "find-generic-password", "-a", k.account, "-s", service, "-w")
	if err != nil {
		return "", fmt.Errorf("reading %s back from the Keychain: %w", service, err)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

// lookupLine is the shell line that reads the value back, as docs/secrets.md recommends.
func lookupLine(service string) string {
	return fmt.Sprintf(`"$(security find-generic-password -a "$USER" -s %s -w)"`, service)
}
