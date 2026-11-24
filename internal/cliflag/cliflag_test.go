package cliflag

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestParseTakesFlagsAnywhere(t *testing.T) {
	var errw bytes.Buffer
	fs := New("done", &errw)
	note := fs.String("note", "", "")
	pos, err := Parse(fs, []string{"T-1", "--note", "x", "T-2"})
	if err != nil || *note != "x" || !slices.Equal(pos, []string{"T-1", "T-2"}) {
		t.Errorf("pos %v note %q err %v", pos, *note, err)
	}
}

func TestNewReportsABadFlagWithoutExiting(t *testing.T) {
	var errw bytes.Buffer
	fs := New("inventory", &errw)
	fs.Bool("verbose", false, "")
	if _, err := Parse(fs, []string{"github", "--bogus"}); err == nil || !strings.Contains(errw.String(), "bogus") {
		t.Errorf("err %v, stderr %q", err, errw.String())
	}
}
