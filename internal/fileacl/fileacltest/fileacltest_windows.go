//go:build windows

package fileacltest

import (
	"io/fs"
	"syscall"

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
