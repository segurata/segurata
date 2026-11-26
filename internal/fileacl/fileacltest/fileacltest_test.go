package fileacltest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/segurata/segurata/internal/fileacl"
)

type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Helper()               {}
func (r *recorder) Fatalf(string, ...any) { r.failed = true; panic(r) }
func (r *recorder) Fatal(...any)          { r.failed = true; panic(r) }

func fails(t *testing.T, f func(testing.TB)) (failed bool) {
	t.Helper()
	r := &recorder{TB: t}
	defer func() {
		if p := recover(); p != nil && p != r {
			panic(p)
		}
		failed = r.failed
	}()
	f(r)
	return
}

func TestAssertPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	if err := fileacl.MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	f, err := fileacl.CreatePrivate(dir, "f")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	AssertPrivateDir(t, dir)
	AssertPrivate(t, f.Name())
	if !fails(t, func(tb testing.TB) { AssertPrivate(tb, dir) }) || !fails(t, func(tb testing.TB) { AssertPrivateDir(tb, f.Name()) }) {
		t.Error("a file passed for a directory, or the reverse")
	}
	open := filepath.Join(t.TempDir(), "open")
	if err := os.WriteFile(open, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}
	if !fails(t, func(tb testing.TB) { AssertPrivate(tb, open) }) {
		t.Error("a file left as created passed as private")
	}
}
