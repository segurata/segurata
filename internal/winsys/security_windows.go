//go:build windows

package winsys

import (
	"sync"
	"syscall"
	"unsafe"
)

// SECURITY_INFORMATION flags.
const (
	OwnerSecurityInformation         = 0x1
	DaclSecurityInformation          = 0x4
	ProtectedDaclSecurityInformation = 0x80000000
)

const (
	seFileObject = 1 // SE_FILE_OBJECT
	sddlRevision = 1 // SDDL_REVISION_1
)

var (
	procGetSecurityInfo  = newProc(advapi32, "GetSecurityInfo")
	procSetSecurityInfo  = newProc(advapi32, "SetSecurityInfo")
	procSDToString       = newProc(advapi32, "ConvertSecurityDescriptorToStringSecurityDescriptorW")
	procStringToSD       = newProc(advapi32, "ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSDOwner       = newProc(advapi32, "GetSecurityDescriptorOwner")
	procGetSDDacl        = newProc(advapi32, "GetSecurityDescriptorDacl")
	currentUserSIDString = sync.OnceValues(func() (string, error) {
		tok, err := syscall.OpenCurrentProcessToken()
		if err != nil {
			return "", err
		}
		defer tok.Close()
		u, err := tok.GetTokenUser()
		if err != nil {
			return "", err
		}
		return u.User.Sid.String()
	})
)

// CurrentUserSID is the SID of the account this process runs as, in its S-1-... form.
func CurrentUserSID() (string, error) { return currentUserSIDString() }

// SecurityDescriptor returns the parts of a file's security descriptor named by info, as SDDL.
// The handle needs READ_CONTROL.
func SecurityDescriptor(h syscall.Handle, info uint32) (string, error) {
	var sd uintptr
	if err := procGetSecurityInfo.status(uintptr(h), seFileObject, uintptr(info), 0, 0, 0, 0, uintptr(unsafe.Pointer(&sd))); err != nil {
		return "", err
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	var s *uint16
	if err := procSDToString.bool(sd, sddlRevision, uintptr(info), uintptr(unsafe.Pointer(&s)), 0); err != nil {
		return "", err
	}
	defer syscall.LocalFree(syscall.Handle(unsafe.Pointer(s)))
	return utf16Ptr(s), nil
}

// SetSecurityDescriptor writes the parts of sddl named by info to a file. The handle needs
// WRITE_DAC for the DACL and WRITE_OWNER for the owner.
func SetSecurityDescriptor(h syscall.Handle, sddl string, info uint32) error {
	sd, err := fromSDDL(sddl)
	if err != nil {
		return err
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	var owner, dacl uintptr
	var present, defaulted int32
	if info&OwnerSecurityInformation != 0 {
		if err := procGetSDOwner.bool(sd, uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&defaulted))); err != nil {
			return err
		}
	}
	if info&DaclSecurityInformation != 0 {
		if err := procGetSDDacl.bool(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); err != nil {
			return err
		}
		if present == 0 || dacl == 0 {
			// A missing DACL here would be written as a NULL DACL: access for everyone.
			return syscall.EINVAL
		}
	}
	return procSetSecurityInfo.status(uintptr(h), seFileObject, uintptr(info), owner, 0, dacl, 0)
}

// SecurityAttributes carries sddl into CreateFile or CreateDirectory, so the object never exists
// with an inherited descriptor. free releases it after the call.
func SecurityAttributes(sddl string) (sa *syscall.SecurityAttributes, free func(), err error) {
	sd, err := fromSDDL(sddl)
	if err != nil {
		return nil, nil, err
	}
	sa = &syscall.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, func() { syscall.LocalFree(syscall.Handle(sd)) }, nil
}

func fromSDDL(sddl string) (uintptr, error) {
	p, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return 0, err
	}
	var sd uintptr
	if err := procStringToSD.bool(uintptr(unsafe.Pointer(p)), sddlRevision, uintptr(unsafe.Pointer(&sd)), 0); err != nil {
		return 0, err
	}
	return sd, nil
}

// WriteDAC is the access right to change a DACL.
const WriteDAC = 0x40000
