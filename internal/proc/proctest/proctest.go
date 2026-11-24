// Package proctest writes fake executables for tests of code that runs child processes.
package proctest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Hung writes an executable shell script that waits on a child holding its stdout, the way a
// wrapper that does not exec its program behaves, and returns its path. extra lines run first
// (a `describe` answer, say). The test is skipped where there is no sh.
func Hung(t testing.TB, name, extra string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+extra+"\nsleep 60\necho done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
