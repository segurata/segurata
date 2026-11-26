//go:build windows

package winsys

import (
	"syscall"
	"unsafe"
)

// Credential is CREDENTIALW.
type Credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	procCredWriteW  = newProc(advapi32, "CredWriteW")
	procCredReadW   = newProc(advapi32, "CredReadW")
	procCredDeleteW = newProc(advapi32, "CredDeleteW")
	procCredFree    = newProc(advapi32, "CredFree")
)

// CredWrite creates or replaces a credential.
func CredWrite(c *Credential) error {
	return procCredWriteW.bool(uintptr(unsafe.Pointer(c)), 0)
}

// CredRead returns the API's copy of a credential, which the caller releases with CredFree.
func CredRead(target string, typ uint32) (*Credential, error) {
	t, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return nil, err
	}
	var c *Credential
	if err := procCredReadW.bool(uintptr(unsafe.Pointer(t)), uintptr(typ), 0, uintptr(unsafe.Pointer(&c))); err != nil {
		return nil, err
	}
	return c, nil
}

// CredDelete removes a credential.
func CredDelete(target string, typ uint32) error {
	t, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return procCredDeleteW.bool(uintptr(unsafe.Pointer(t)), uintptr(typ), 0)
}

// CredFree releases what CredRead returned.
func CredFree(c *Credential) { procCredFree.call(uintptr(unsafe.Pointer(c))) }

// UTF16PtrToString reads a NUL-terminated string from an API buffer.
func UTF16PtrToString(p *uint16) string { return utf16Ptr(p) }
