// Package prompt asks the owner at the terminal before a command changes something.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrNotTTY is returned when confirmation would be needed but nobody can answer it.
var ErrNotTTY = errors.New("stdin is not a terminal, so nobody can confirm: refusing to apply (pass --yes to apply without asking)")

// Confirm asks "Apply? [y/N]" on out and reads the answer from in. yes skips the question; when in
// is not a terminal nobody can answer, so it refuses with ErrNotTTY. Every command that changes
// something on --apply confirms through here.
func Confirm(in io.Reader, out io.Writer, yes, tty bool) (bool, error) {
	if yes {
		return true, nil
	}
	if !tty {
		return false, ErrNotTTY
	}
	fmt.Fprint(out, "\nApply? [y/N] ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}
