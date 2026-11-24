package searchpath

import "testing"

func TestCleanDropsDuplicatesAndUnexpandable(t *testing.T) {
	got := Clean("/a/bin:~/src/bin::/b/:/a/bin:rel/bin:/b")
	if got != "/a/bin:/b" {
		t.Fatalf("got %q", got)
	}
}
