package clipboard

import (
	"context"
	"errors"
	"testing"
)

func TestPasteboardRunsTheAbsoluteTools(t *testing.T) {
	var ran []string
	p := Pasteboard{Run: func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		if len(stdin) != 0 || len(args) != 0 {
			t.Errorf("%s ran with stdin %q args %v", name, stdin, args)
		}
		ran = append(ran, name)
		if name == pbcopy {
			return nil, errors.New("denied")
		}
		return []byte("copied\n"), nil
	}}
	if got, err := p.Read(context.Background()); err != nil || string(got) != "copied\n" {
		t.Errorf("read %q %v", got, err)
	}
	if err := p.Clear(context.Background()); err == nil {
		t.Error("a failed clear was hidden")
	}
	if len(ran) != 2 || ran[0] != "/usr/bin/pbpaste" || ran[1] != "/usr/bin/pbcopy" || p.Caveat() != "" {
		t.Errorf("ran %v", ran)
	}
}
