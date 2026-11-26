//go:build windows

package fileacl

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/segurata/segurata/internal/winsys"
)

const (
	readControl  = 0x20000
	ownerAndDACL = winsys.OwnerSecurityInformation | winsys.DaclSecurityInformation
)

// resolveAlias expands the domain-relative SDDL aliases (LA, DA, ...) the way Windows does.
func resolveAlias(alias string) (string, bool) {
	sid, err := syscall.StringToSid(alias)
	if err != nil {
		return "", false
	}
	s, err := sid.String()
	return s, err == nil
}

func open(path string, follow bool, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(syscall.FILE_FLAG_BACKUP_SEMANTICS)
	if !follow {
		flags |= syscall.FILE_FLAG_OPEN_REPARSE_POINT
	}
	h, err := syscall.CreateFile(p, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return h, nil
}

func sddlOf(path string, follow bool) (string, error) {
	h, err := open(path, follow, readControl)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)
	s, err := winsys.SecurityDescriptor(h, ownerAndDACL)
	if err != nil {
		return "", &fs.PathError{Op: "read the access list of", Path: path, Err: err}
	}
	return s, nil
}

func read(path string, follow bool) (descriptor, string, error) {
	user, err := winsys.CurrentUserSID()
	if err != nil {
		return descriptor{}, "", err
	}
	s, err := sddlOf(path, follow)
	if err != nil {
		return descriptor{}, "", err
	}
	d, err := parseSDDL(s, resolveAlias)
	if err != nil {
		return descriptor{}, "", fmt.Errorf("%s: %w", path, err)
	}
	return d, user, nil
}

func isDir(path string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return st.IsDir(), nil
}

// OwnedByMe reports whether path's owner SID is the current user's. A symbolic link, as fi from
// Lstat shows it, is judged itself and not its target.
func OwnedByMe(path string, fi fs.FileInfo) (bool, error) {
	d, user, err := read(path, fi == nil || fi.Mode()&fs.ModeSymlink == 0)
	if err != nil {
		return false, err
	}
	return d.owner == user, nil
}

// Exposure maps the file's DACL onto permission bits.
func Exposure(path string) (fs.FileMode, error) {
	dir, err := isDir(path)
	if err != nil {
		return 0, err
	}
	d, user, err := read(path, true)
	if err != nil {
		return 0, err
	}
	return d.exposure(user, dir), nil
}

// Effective is Exposure: parent folders never close a file on Windows, because every account holds
// the right to traverse folders it cannot list.
func Effective(path, _ string) (fs.FileMode, error) { return Exposure(path) }

// ChangeableByOthers reports whether an account other than the user, SYSTEM and Administrators
// owns dir or may add, delete or re-permission its entries.
func ChangeableByOthers(dir string) (bool, error) {
	d, user, err := read(dir, true)
	if err != nil {
		return false, err
	}
	return d.changeable(user), nil
}

// MakePrivate gives a file the descriptor segurata creates its own files with. It refuses a file
// another account owns.
func MakePrivate(path string) error {
	dir, err := isDir(path)
	if err != nil {
		return err
	}
	d, user, err := read(path, true)
	if err != nil {
		return err
	}
	if d.owner != user {
		return &fs.PathError{Op: "make private", Path: path, Err: errors.New("the file is owned by another account")}
	}
	h, err := open(path, true, readControl|winsys.WriteDAC)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	if err := winsys.SetSecurityDescriptor(h, privateSDDL(user, dir), winsys.DaclSecurityInformation|winsys.ProtectedDaclSecurityInformation); err != nil {
		return &fs.PathError{Op: "make private", Path: path, Err: err}
	}
	return nil
}

func privateAttributes(dir bool) (*syscall.SecurityAttributes, func(), error) {
	user, err := winsys.CurrentUserSID()
	if err != nil {
		return nil, nil, err
	}
	return winsys.SecurityAttributes(privateSDDL(user, dir))
}

// CreatePrivate is os.CreateTemp with the private descriptor set as the file is created, so it is
// never reachable through an inherited DACL.
func CreatePrivate(dir, pattern string) (*os.File, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	if strings.ContainsAny(pattern, `/\`) {
		return nil, &fs.PathError{Op: "createtemp", Path: pattern, Err: errors.New("pattern contains path separator")}
	}
	prefix, suffix := pattern, ""
	if i := strings.LastIndexByte(pattern, '*'); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}
	sa, free, err := privateAttributes(false)
	if err != nil {
		return nil, err
	}
	defer free()
	for range 10000 {
		name := filepath.Join(dir, prefix+strconv.FormatUint(uint64(rand.Uint32()), 10)+suffix)
		f, err := createPrivateAt(name, sa)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, &fs.PathError{Op: "createtemp", Path: filepath.Join(dir, pattern), Err: fs.ErrExist}
}

// CreatePrivateAt exclusively creates path with the private descriptor in effect from creation.
func CreatePrivateAt(path string) (*os.File, error) {
	sa, free, err := privateAttributes(false)
	if err != nil {
		return nil, err
	}
	defer free()
	return createPrivateAt(path, sa)
}

func createPrivateAt(path string, sa *syscall.SecurityAttributes) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "create", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		sa, syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// MkdirPrivate creates dir and any missing parents with the private descriptor, leaving existing
// ones as they are.
func MkdirPrivate(dir string) error {
	if st, err := os.Stat(dir); err == nil {
		if st.IsDir() {
			return nil
		}
		return &fs.PathError{Op: "mkdir", Path: dir, Err: syscall.ENOTDIR}
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := MkdirPrivate(parent); err != nil {
			return err
		}
	}
	sa, free, err := privateAttributes(true)
	if err != nil {
		return err
	}
	defer free()
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := syscall.CreateDirectory(p, sa); err != nil {
		if st, e := os.Lstat(dir); e == nil && st.IsDir() {
			return nil
		}
		return &fs.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	return nil
}

// Describe names who else reaches the file, for messages; accounts outside the well-known ones
// show as "another account".
func Describe(path string) (string, error) {
	dir, err := isDir(path)
	if err != nil {
		return "", err
	}
	d, user, err := read(path, true)
	if err != nil {
		return "", err
	}
	return d.describe(user, dir), nil
}

// Fingerprint changes whenever the file's access does: its owner and DACL as SDDL.
func Fingerprint(path string) (string, error) { return sddlOf(path, true) }

// CopyAccess gives a temporary file the destination's DACL before renaming it into place.
func CopyAccess(from, to string) error {
	sddl, err := sddlOf(from, false)
	if err != nil {
		return err
	}
	current, err := sddlOf(to, false)
	if err != nil || sddl == current {
		return err
	}
	dacl, ok := sections(sddl)['D']
	if !ok || strings.Contains(dacl, "NO_ACCESS_CONTROL") {
		return &fs.PathError{Op: "copy access list", Path: from, Err: errors.New("no access list to preserve")}
	}
	flags, _, _ := strings.Cut(dacl, "(")
	info := uint32(winsys.DaclSecurityInformation | winsys.UnprotectedDaclSecurityInformation)
	if strings.Contains(flags, "P") {
		info = winsys.DaclSecurityInformation | winsys.ProtectedDaclSecurityInformation
	}
	h, err := open(to, false, winsys.WriteDAC)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	if err := winsys.SetSecurityDescriptor(h, sddl, info); err != nil {
		return &fs.PathError{Op: "copy access list", Path: to, Err: err}
	}
	return nil
}

// HasPrivateDescriptor reports whether path carries exactly the descriptor MakePrivate writes.
func HasPrivateDescriptor(path string) (bool, error) {
	d, user, err := read(path, true)
	if err != nil {
		return false, err
	}
	return d.isPrivate(user), nil
}
