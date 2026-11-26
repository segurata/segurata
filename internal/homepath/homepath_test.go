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

func TestExpandOnWindows(t *testing.T) {
	home := `C:\Users\ana`
	for p, want := range map[string]string{
		`~\a\b`: filepath.Join(home, "a", "b"), "~/a/b": filepath.Join(home, "a", "b"), `~user\x`: `~user\x`,
	} {
		if got := expand(p, home, true); got != want {
			t.Errorf("expand(%q) = %q, want %q", p, got, want)
		}
	}
	if got := expand(`~\a`, "/h", false); got != `~\a` {
		t.Errorf(`"~\a" is a file name on Unix, expanded to %q`, got)
	}
}

// The Unix rules: the home prefix is compared byte for byte.
func TestShorten(t *testing.T) {
	for p, want := range map[string]string{
		"/h": "~", "/h/a/b": "~/a/b", "/hx/a": "/hx/a", "/other": "/other", "": "", "/H/a": "/H/a",
	} {
		if got := shorten(p, "/h", false); got != want {
			t.Errorf("shorten(%q) = %q, want %q", p, got, want)
		}
	}
	if got := Shorten("/h/a", ""); got != "/h/a" {
		t.Errorf("unknown home: %q", got)
	}
	if got := Shorten("/x", "/"); got != "~/x" {
		t.Errorf("root home: %q", got)
	}
	if got := Shorten("/", "/"); got != "~" {
		t.Errorf("root home itself: %q", got)
	}
}

// On Windows the same file gets the same ~ form whatever the case of the drive or folders and
// whichever separator the tool that printed it used.
func TestShortenOnWindows(t *testing.T) {
	home := `C:\Users\Ana`
	for p, want := range map[string]string{
		`C:\Users\Ana`:              "~",
		`c:\users\ana\src`:          "~/src",
		`C:\Users\Ana\src\App\.env`: "~/src/App/.env",
		`c:\USERS\ana\src\App\.env`: "~/src/App/.env",
		`C:/Users/Ana/src/.env`:     "~/src/.env",
		`C:\Users\Anabel\.env`:      `C:\Users\Anabel\.env`,
		`D:\Users\Ana\.env`:         `D:\Users\Ana\.env`,
	} {
		if got := shorten(p, home, true); got != want {
			t.Errorf("shorten(%q) = %q, want %q", p, got, want)
		}
	}
	if got := shorten(`/h\a`, "/h", false); got != `/h\a` {
		t.Errorf("a backslash is a file name character on Unix: %q", got)
	}
}
