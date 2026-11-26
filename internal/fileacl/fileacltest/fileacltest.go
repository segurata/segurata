// Package fileacltest asserts in tests that a file is private, on every platform: mode 0600 (0700
// for a directory) on Unix, and on Windows the protected owner-and-SYSTEM DACL segurata writes.
package fileacltest

import (
	"os"
	"testing"
)

// AssertPrivate fails the test unless path is a private file.
func AssertPrivate(t testing.TB, path string) {
	t.Helper()
	assert(t, path, false)
}

// AssertPrivateDir fails the test unless path is a private directory.
func AssertPrivateDir(t testing.TB, path string) {
	t.Helper()
	assert(t, path, true)
}

// Expose lets BUILTIN\Users, on Unix the group and others, read path, the way a shared folder
// passes its access down.
func Expose(t testing.TB, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := expose(path, st.IsDir()); err != nil {
		t.Fatal(err)
	}
}

// Access is who may reach path, to compare before and after a rewrite: its mode on Unix, its DACL
// on Windows. The owner is left out: Windows gives a replaced file the writer's.
func Access(t testing.TB, path string) string {
	t.Helper()
	a, err := access(path)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func assert(t testing.TB, path string, dir bool) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.IsDir() != dir {
		t.Fatalf("%s: directory %v, want %v", path, st.IsDir(), dir)
	}
	if why := notPrivate(path, st); why != "" {
		t.Fatalf("%s is not private: %s", path, why)
	}
}
