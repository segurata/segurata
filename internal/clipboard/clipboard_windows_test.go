//go:build windows

package clipboard

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/segurata/segurata/internal/winsys"
)

// copyText puts text on the clipboard as CF_UNICODETEXT, as a paste source would.
func copyText(t *testing.T, owner uintptr, text string) {
	t.Helper()
	u := append(utf16.Encode([]rune(text)), 0)
	err := withClipboard(t.Context(), owner, func() error {
		h, err := winsys.GlobalAlloc(winsys.GmemMoveable, uintptr(2*len(u)))
		if err != nil {
			return err
		}
		defer func() {
			if h != 0 {
				winsys.GlobalFree(h)
			}
		}()
		p, err := winsys.GlobalLock(h)
		if err != nil {
			return err
		}
		copy(unsafe.Slice((*uint16)(unsafe.Add(nil, p)), len(u)), u)
		winsys.GlobalUnlock(h)
		if err := winsys.EmptyClipboard(); err != nil {
			return err
		}
		if err := winsys.SetClipboardData(winsys.CFUnicodeText, h); err != nil {
			return err
		}
		h = 0 // Windows owns the buffer after SetClipboardData succeeds.
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWindowsClipboardReadsUnicodeTextAndClears(t *testing.T) {
	if os.Getenv("SEGURATA_TEST_DISPOSABLE_CLIPBOARD") != "1" {
		t.Skip("requires a disposable Windows session: this test clears its clipboard")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	owner, destroy := clipboardOwner(t)
	defer destroy()
	ctx := t.Context()
	value := "synthetic-ñ-€-" + rand.Text()
	copyText(t, owner, value)
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

// clipboardOwner creates a hidden window on the caller's locked OS thread. EmptyClipboard
// assigns ownership to this window, which allows the fixture to call SetClipboardData.
func clipboardOwner(t *testing.T) (uintptr, func()) {
	t.Helper()
	dir, err := winsys.System32()
	if err != nil {
		t.Fatal(err)
	}
	user32 := syscall.NewLazyDLL(filepath.Join(dir, "user32.dll"))
	class := []uint16{'S', 'T', 'A', 'T', 'I', 'C', 0}
	const wsPopup = 0x80000000
	hwnd, _, err := user32.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(&class[0])), 0, wsPopup, 0, 0, 0, 0, 0, 0, 0, 0)
	if hwnd == 0 {
		t.Fatalf("creating the clipboard owner: %v", err)
	}
	return hwnd, func() {
		if ok, _, err := user32.NewProc("DestroyWindow").Call(hwnd); ok == 0 {
			t.Errorf("destroying the clipboard owner: %v", err)
		}
	}
}
