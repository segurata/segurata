//go:build windows

package winsys

// CF_UNICODETEXT and GMEM_MOVEABLE.
const (
	CFUnicodeText = 13
	GmemMoveable  = 0x2
)

var (
	procOpenClipboard              = newProc(user32, "OpenClipboard")
	procCloseClipboard             = newProc(user32, "CloseClipboard")
	procEmptyClipboard             = newProc(user32, "EmptyClipboard")
	procGetClipboardData           = newProc(user32, "GetClipboardData")
	procSetClipboardData           = newProc(user32, "SetClipboardData")
	procIsClipboardFormatAvailable = newProc(user32, "IsClipboardFormatAvailable")
	procGlobalAlloc                = newProc(kernel32, "GlobalAlloc")
	procGlobalFree                 = newProc(kernel32, "GlobalFree")
	procGlobalLock                 = newProc(kernel32, "GlobalLock")
	procGlobalUnlock               = newProc(kernel32, "GlobalUnlock")
	procGlobalSize                 = newProc(kernel32, "GlobalSize")
)

// The clipboard calls work on the calling OS thread; callers lock it.

func OpenClipboard(owner uintptr) error { return procOpenClipboard.bool(owner) }
func CloseClipboard() error             { return procCloseClipboard.bool() }
func EmptyClipboard() error             { return procEmptyClipboard.bool() }

func IsClipboardFormatAvailable(format uint32) bool {
	r, _ := procIsClipboardFormatAvailable.call(uintptr(format))
	return r != 0
}

func GetClipboardData(format uint32) (uintptr, error) {
	h, err := procGetClipboardData.call(uintptr(format))
	if h == 0 {
		return 0, err
	}
	return h, nil
}

func SetClipboardData(format uint32, h uintptr) error {
	r, err := procSetClipboardData.call(uintptr(format), h)
	if r == 0 {
		return err
	}
	return nil
}

func GlobalAlloc(flags uint32, size uintptr) (uintptr, error) {
	h, err := procGlobalAlloc.call(uintptr(flags), size)
	if h == 0 {
		return 0, err
	}
	return h, nil
}

func GlobalFree(h uintptr) { procGlobalFree.call(h) }

func GlobalLock(h uintptr) (uintptr, error) {
	p, err := procGlobalLock.call(h)
	if p == 0 {
		return 0, err
	}
	return p, nil
}

func GlobalUnlock(h uintptr) { procGlobalUnlock.call(h) }

func GlobalSize(h uintptr) uintptr {
	n, _ := procGlobalSize.call(h)
	return n
}
