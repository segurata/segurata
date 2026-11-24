package prompt

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestIsTerminalRejectsDevNullAndPipes(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(null) || IsTerminal(r) {
		t.Fatal("/dev/null and pipes are not terminals")
	}
}

func TestConfirmTakesOnlyYesAndNeedsATerminal(t *testing.T) {
	for answer, want := range map[string]bool{"y\n": true, " YES \n": true, "yes": true, "\n": false, "n\n": false, "": false, "sure\n": false} {
		var out bytes.Buffer
		ok, err := Confirm(strings.NewReader(answer), &out, false, true)
		if err != nil || ok != want {
			t.Errorf("answer %q: ok=%v err=%v, want %v", answer, ok, err, want)
		}
		if !strings.Contains(out.String(), "Apply? [y/N]") {
			t.Errorf("answer %q: asked %q", answer, out.String())
		}
	}
	if ok, err := Confirm(strings.NewReader(""), io.Discard, false, false); ok || !errors.Is(err, ErrNotTTY) {
		t.Fatalf("without a terminal: ok=%v err=%v", ok, err)
	}
	var out bytes.Buffer
	if ok, err := Confirm(strings.NewReader("n\n"), &out, true, false); !ok || err != nil || out.Len() != 0 {
		t.Fatalf("--yes: ok=%v err=%v asked %q", ok, err, out.String())
	}
}
