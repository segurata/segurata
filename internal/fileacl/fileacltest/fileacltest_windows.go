//go:build windows

package fileacltest

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/winsys"
)

func notPrivate(path string, _ fs.FileInfo) string {
	ok, err := fileacl.HasPrivateDescriptor(path)
	switch {
	case err != nil:
		return err.Error()
	case !ok:
		s, _ := fileacl.Fingerprint(path)
		return "descriptor " + s
	}
	return ""
}

// expose replaces the DACL with an unprotected one granting the user full access and Users read.
func expose(path string, dir bool) error {
	user, err := winsys.CurrentUserSID()
	if err != nil {
		return err
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	h, err := open(path, winsys.WriteDAC)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	return winsys.SetSecurityDescriptor(h, "D:(A;"+inherit+";FA;;;"+user+")(A;"+inherit+";FR;;;BU)", winsys.DaclSecurityInformation)
}

// giveAway names BUILTIN\Users as the owner. A token may only name itself or a group it holds
// the owner's rights through, which fileacl counts as the user, so naming another account takes
// SeRestorePrivilege: an elevated administrator holds it, disabled. It is enabled on an
// impersonation token of a thread of its own, which ends with the goroutine, so neither the
// privilege nor the impersonation outlives the call.
func giveAway(path string) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
		done <- asRestorer(func() error {
			h, err := open(path, winsys.WriteOwner)
			if err != nil {
				return err
			}
			defer syscall.CloseHandle(h)
			return winsys.SetSecurityDescriptor(h, "O:BU", winsys.OwnerSecurityInformation)
		})
	}()
	return <-done
}

const (
	securityImpersonation  = 2
	tokenAdjustPrivileges  = 0x20
	tokenQuery             = 0x8
	sePrivilegeEnabled     = 0x2
	errorNotAllAssigned    = syscall.Errno(1300)
	currentThreadPseudoHnd = ^uintptr(1) // GetCurrentThread()
)

// asRestorer runs f on the calling thread while it impersonates this process with
// SeRestorePrivilege enabled. The caller has locked the thread and lets it exit afterwards.
func asRestorer(f func() error) error {
	sys, err := winsys.System32()
	if err != nil {
		return err
	}
	advapi32 := syscall.NewLazyDLL(filepath.Join(sys, "advapi32.dll"))
	call := func(name string, args ...uintptr) error {
		if r, _, e := advapi32.NewProc(name).Call(args...); r == 0 {
			return fmt.Errorf("%s: %w", name, e)
		}
		return nil
	}
	if err := call("ImpersonateSelf", securityImpersonation); err != nil {
		return err
	}
	var tok syscall.Token
	if err := call("OpenThreadToken", currentThreadPseudoHnd, tokenAdjustPrivileges|tokenQuery, 1, uintptr(unsafe.Pointer(&tok))); err != nil {
		return err
	}
	defer tok.Close()
	name, err := syscall.UTF16PtrFromString("SeRestorePrivilege")
	if err != nil {
		return err
	}
	var tp struct {
		count uint32
		luid  [2]uint32
		attrs uint32
	}
	tp.count, tp.attrs = 1, sePrivilegeEnabled
	if err := call("LookupPrivilegeValueW", 0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&tp.luid))); err != nil {
		return err
	}
	r, _, e := advapi32.NewProc("AdjustTokenPrivileges").Call(uintptr(tok), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	switch {
	case r == 0:
		return fmt.Errorf("AdjustTokenPrivileges: %w", e)
	case e == errorNotAllAssigned:
		return errors.New("the token lacks SeRestorePrivilege")
	}
	return f()
}

func access(path string) (string, error) {
	h, err := open(path, readControl)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)
	return winsys.SecurityDescriptor(h, winsys.DaclSecurityInformation)
}

const readControl = 0x20000

func open(path string, rights uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return syscall.CreateFile(p, readControl|rights, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
}
