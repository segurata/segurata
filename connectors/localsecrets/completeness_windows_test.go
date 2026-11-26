package localsecrets

import (
	"syscall"
	"testing"
)

// A file another process holds open without sharing, as Windows holds NTUSER.DAT or a browser its
// databases, is skipped as unreadable by the real ripgrep: the rest of the search stays complete.
func TestRealRipgrepSkipsAFileInUse(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, "[]")
	held := fx.write(t, ".config/inuse.env", "TOKEN="+fx.stripe+"\n", 0o600)
	name, err := syscall.UTF16PtrFromString(held)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(h)
	assertOnlySkipped(t, c, "~/.config/inuse.env")
}
