package config

import "testing"

func TestDefaultOutDirIgnoresTheWorkingDirectory(t *testing.T) {
	t.Setenv("SEGURATA_OUT", "")
	t.Setenv("SEGURATA_HOME", "/tmp/seg-home")
	if got := DefaultOutDir(); got != "/tmp/seg-home/out" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("SEGURATA_OUT", "/tmp/elsewhere")
	if got := DefaultOutDir(); got != "/tmp/elsewhere" {
		t.Fatalf("SEGURATA_OUT: got %q", got)
	}
}
