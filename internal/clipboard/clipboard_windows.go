//go:build windows

package clipboard

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	user32                     = syscall.NewLazyDLL("user32.dll")
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	openClipboard              = user32.NewProc("OpenClipboard")
	closeClipboard             = user32.NewProc("CloseClipboard")
	emptyClipboard             = user32.NewProc("EmptyClipboard")
	getClipboardData           = user32.NewProc("GetClipboardData")
	isClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	globalLock                 = kernel32.NewProc("GlobalLock")
	globalUnlock               = kernel32.NewProc("GlobalUnlock")
	globalSize                 = kernel32.NewProc("GlobalSize")
)

const cfUnicodeText = 13 // CF_UNICODETEXT

func Default() Clipboard { return Windows{} }

// Windows is the clipboard of this desktop session.
type Windows struct{}

// Read returns no text, not an error, when the clipboard holds none.
func (Windows) Read(ctx context.Context) ([]byte, error) {
	var out []byte
	err := withClipboard(ctx, func() error {
		if r, _, _ := isClipboardFormatAvailable.Call(cfUnicodeText); r == 0 {
			return nil
		}
		h, _, e := getClipboardData.Call(cfUnicodeText)
		if h == 0 {
			return e
		}
		p, _, e := globalLock.Call(h)
		if p == 0 {
			return e
		}
		defer globalUnlock.Call(h)
		size, _, _ := globalSize.Call(h)
		text := unsafe.Slice((*uint16)(unsafe.Add(nil, p)), size/2)
		for i, c := range text {
			if c == 0 {
				text = text[:i]
				break
			}
		}
		u := append([]uint16(nil), text...)
		defer clear(u)
		r := utf16.Decode(u)
		defer clear(r)
		out = []byte(string(r))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading the clipboard: %w", err)
	}
	return out, nil
}

func (Windows) Clear(ctx context.Context) error {
	err := withClipboard(ctx, func() error {
		if r, _, e := emptyClipboard.Call(); r == 0 {
			return e
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("clearing the clipboard: %w", err)
	}
	return nil
}

func (Windows) Caveat() string {
	return "Windows may keep a copy in Clipboard history (Win+V) or sync it to your other devices (cloud clipboard): delete it there, or clear all in Settings > System > Clipboard"
}

// withClipboard runs f with the clipboard open on this OS thread, retrying while another
// application holds it.
func withClipboard(ctx context.Context, f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for try := 0; ; try++ {
		r, _, e := openClipboard.Call(0)
		if r != 0 {
			break
		}
		if try == 20 {
			return errors.Join(errors.New("another application holds the clipboard"), e)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	defer closeClipboard.Call()
	return f()
}
