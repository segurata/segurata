//go:build windows

package clipboard

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"
)

var (
	setClipboardData = user32.NewProc("SetClipboardData")
	globalAlloc      = kernel32.NewProc("GlobalAlloc")
)

// copyText puts text on the clipboard as CF_UNICODETEXT, as a paste source would.
func copyText(t *testing.T, text string) {
	t.Helper()
	u := append(utf16.Encode([]rune(text)), 0)
	err := withClipboard(context.Background(), func() error {
		if r, _, e := emptyClipboard.Call(); r == 0 {
			return e
		}
		h, _, e := globalAlloc.Call(0x0002, uintptr(2*len(u))) // GMEM_MOVEABLE
		if h == 0 {
			return e
		}
		p, _, e := globalLock.Call(h)
		if p == 0 {
			return e
		}
		copy(unsafe.Slice((*uint16)(unsafe.Add(nil, p)), len(u)), u)
		globalUnlock.Call(h)
		if r, _, e := setClipboardData.Call(cfUnicodeText, h); r == 0 {
			return e
		}
		return nil
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
