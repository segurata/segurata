//go:build windows

package clipboard

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/segurata/segurata/internal/winsys"
)

func Default() Clipboard { return Windows{} }

// Windows is the clipboard of this desktop session.
type Windows struct{}

// Read returns no text, not an error, when the clipboard holds none.
func (Windows) Read(ctx context.Context) ([]byte, error) {
	var out []byte
	err := withClipboard(ctx, 0, func() error {
		if !winsys.IsClipboardFormatAvailable(winsys.CFUnicodeText) {
			return nil
		}
		h, err := winsys.GetClipboardData(winsys.CFUnicodeText)
		if err != nil {
			return err
		}
		p, err := winsys.GlobalLock(h)
		if err != nil {
			return err
		}
		defer winsys.GlobalUnlock(h)
		text := unsafe.Slice((*uint16)(unsafe.Add(nil, p)), winsys.GlobalSize(h)/2)
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
	err := withClipboard(ctx, 0, func() error {
		return winsys.EmptyClipboard()
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
func withClipboard(ctx context.Context, owner uintptr, f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for try := 0; ; try++ {
		e := winsys.OpenClipboard(owner)
		if e == nil {
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
	defer winsys.CloseClipboard()
	return f()
}
