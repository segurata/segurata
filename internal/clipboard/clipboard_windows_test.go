//go:build windows

package clipboard

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/segurata/segurata/internal/winsys"
)

// copyText puts text on the clipboard as CF_UNICODETEXT, as a paste source would.
func copyText(t *testing.T, text string) {
	t.Helper()
	u := append(utf16.Encode([]rune(text)), 0)
	err := withClipboard(context.Background(), func() error {
		if err := winsys.EmptyClipboard(); err != nil {
			return err
		}
		h, err := winsys.GlobalAlloc(winsys.GmemMoveable, uintptr(2*len(u)))
		if err != nil {
			return err
		}
		p, err := winsys.GlobalLock(h)
		if err != nil {
			return err
		}
		copy(unsafe.Slice((*uint16)(unsafe.Add(nil, p)), len(u)), u)
		winsys.GlobalUnlock(h)
		return winsys.SetClipboardData(winsys.CFUnicodeText, h)
	})
	if err != nil {
		t.Skipf("no clipboard in this session: %v", err)
	}
}

func TestWindowsClipboardReadsUnicodeTextAndClears(t *testing.T) {
	ctx := context.Background()
	value := "synthetic-ñ-€-" + rand.Text()
	copyText(t, value)
	got, err := Default().Read(ctx)
	if err != nil || string(got) != value {
		t.Fatalf("read %q, %v", got, err)
	}
	if err := Default().Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := Default().Read(ctx); err != nil || len(got) != 0 {
		t.Errorf("after clear: %q, %v", got, err)
	}
	if c := Default().Caveat(); !strings.Contains(c, "Clipboard history") {
		t.Errorf("caveat %q", c)
	}
}
