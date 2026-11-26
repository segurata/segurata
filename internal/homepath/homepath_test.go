package homepath

import (
	"path/filepath"
	"testing"
)

func TestExpand(t *testing.T) {
	for p, want := range map[string]string{
		"~": "/h", "~/a/b": filepath.Join("/h", "a", "b"), "~/": filepath.Clean("/h"), "/abs": "/abs", "rel": "rel", "~user/x": "~user/x", "": "",
	} {
		if got := Expand(p, "/h"); got != want {
			t.Errorf("Expand(%q) = %q, want %q", p, got, want)
		}
	}
	if got := Expand("~/a", ""); got != "~/a" {
		t.Errorf("unknown home: %q", got)
	}
}

func TestShorten(t *testing.T) {
	for p, want := range map[string]string{
		"/h": "~", "/h/a/b": "~/a/b", "/hx/a": "/hx/a", "/other": "/other", "": "",
	} {
		if got := Shorten(p, "/h"); got != want {
			t.Errorf("Shorten(%q) = %q, want %q", p, got, want)
		}
	}
	if got := Shorten("/h/a", ""); got != "/h/a" {
		t.Errorf("unknown home: %q", got)
	}
}
