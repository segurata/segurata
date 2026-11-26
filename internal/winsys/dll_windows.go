//go:build windows

package winsys

import (
	"errors"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

// kernel32 is a KnownDLL, mapped from System32 whatever the search order, so it alone is loaded by
// name: it is what finds System32 for the others.
var kernel32ByName = syscall.NewLazyDLL("kernel32.dll")

var system32 = sync.OnceValues(func() (string, error) {
	get := kernel32ByName.NewProc("GetSystemDirectoryW")
	buf := make([]uint16, syscall.MAX_PATH)
	for {
		n, _, e := get.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		switch {
		case n == 0:
			return "", errnoOf(e)
		case int(n) < len(buf):
			return syscall.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n)
	}
})

// System32 is the Windows system directory, where segurata takes the tools it runs by absolute
// path.
func System32() (string, error) { return system32() }

type systemDLL struct {
	name string
	load func() (*syscall.LazyDLL, error)
}

func newDLL(name string) *systemDLL {
	return &systemDLL{name: name, load: sync.OnceValues(func() (*syscall.LazyDLL, error) {
		dir, err := System32()
		if err != nil {
			return nil, err
		}
		return syscall.NewLazyDLL(filepath.Join(dir, name)), nil
	})}
}

var (
	advapi32 = newDLL("advapi32.dll")
	kernel32 = newDLL("kernel32.dll")
	user32   = newDLL("user32.dll")
	rstrtmgr = newDLL("rstrtmgr.dll")
)

type proc struct {
	find func() (*syscall.LazyProc, error)
}

func newProc(d *systemDLL, name string) *proc {
	return &proc{find: sync.OnceValues(func() (*syscall.LazyProc, error) {
		l, err := d.load()
		if err != nil {
			return nil, err
		}
		p := l.NewProc(name)
		if err := p.Find(); err != nil {
			return nil, err
		}
		return p, nil
	})}
}

// call returns the procedure's result and the thread's last error, which means something only when
// the result says the call failed.
//
//go:uintptrescapes
func (p *proc) call(args ...uintptr) (uintptr, error) {
	f, err := p.find()
	if err != nil {
		return 0, err
	}
	r, _, e := f.Call(args...)
	return r, errnoOf(e)
}

// bool calls a procedure returning BOOL.
//
//go:uintptrescapes
func (p *proc) bool(args ...uintptr) error {
	if r, err := p.call(args...); r == 0 {
		return err
	}
	return nil
}

// status calls a procedure that returns its Win32 error code.
//
//go:uintptrescapes
func (p *proc) status(args ...uintptr) error {
	f, err := p.find()
	if err != nil {
		return err
	}
	if r, _, _ := f.Call(args...); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// errnoOf keeps a failure a failure when the call left no last error.
func errnoOf(e error) error {
	var errno syscall.Errno
	if !errors.As(e, &errno) || errno == 0 {
		return syscall.EINVAL
	}
	return errno
}

// utf16Ptr reads a NUL-terminated UTF-16 string the API allocated.
func utf16Ptr(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	for *(*uint16)(unsafe.Add(unsafe.Pointer(p), 2*n)) != 0 {
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}
