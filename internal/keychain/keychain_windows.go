//go:build windows

package keychain

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/segurata/segurata/internal/winsys"
)

const (
	credTypeGeneric         = 1    // CRED_TYPE_GENERIC
	credPersistLocalMachine = 2    // CRED_PERSIST_LOCAL_MACHINE: this user on this machine, never roaming
	maxBlob                 = 2560 // CRED_MAX_CREDENTIAL_BLOB_SIZE

	errorNotFound           syscall.Errno = 1168 // ERROR_NOT_FOUND
	errorNoSuchLogonSession syscall.Errno = 1312 // ERROR_NO_SUCH_LOGON_SESSION
)

var errNoLogonSession = errors.New("Credential Manager is not available in this logon session (a scheduled task must run as the logged-on user)")

// Default is the Windows Credential Manager, storing generic credentials under account.
func Default(account string) Store { return CredentialManager{Account: account} }

// CredentialManager keeps each value as a generic credential whose target name is the service and
// whose blob is UTF-16LE text without a terminator, as `cmdkey /generic` and PowerShell store it.
type CredentialManager struct{ Account string }

func (m CredentialManager) Store(_ context.Context, service, value string) error {
	if value == "" {
		return fmt.Errorf("storing %s in Credential Manager: the value is empty", service)
	}
	blob := encodeUTF16LE(value)
	defer clear(blob)
	if len(blob) > maxBlob {
		return fmt.Errorf("storing %s in Credential Manager: the value is longer than the %d bytes it holds", service, maxBlob)
	}
	if err := writeBlob(service, m.Account, blob); err != nil {
		return fmt.Errorf("storing %s in Credential Manager: %w", service, err)
	}
	return nil
}

func (CredentialManager) Read(_ context.Context, service string) (string, error) {
	c, err := readCredential(service)
	switch {
	case errors.Is(err, ErrNotFound):
		return "", fmt.Errorf("%w: %s", ErrNotFound, service)
	case err != nil:
		return "", fmt.Errorf("reading %s from Credential Manager: %w", service, err)
	}
	defer clear(c.blob)
	if len(c.blob)%2 != 0 {
		return "", fmt.Errorf("reading %s from Credential Manager: the item is not UTF-16 text (odd length)", service)
	}
	u := make([]uint16, len(c.blob)/2)
	defer clear(u)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(c.blob[2*i:])
	}
	return string(utf16.Decode(u)), nil
}

func (CredentialManager) Hint(service string) string {
	return "add it with: cmdkey /generic:" + service + " /user:%USERNAME% /pass (in cmd.exe; it prompts for the value)"
}

func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	defer clear(u)
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func writeBlob(target, account string, blob []byte) error {
	t, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	c := winsys.Credential{Type: credTypeGeneric, TargetName: t, Persist: credPersistLocalMachine, CredentialBlobSize: uint32(len(blob))}
	if len(blob) > 0 {
		c.CredentialBlob = &blob[0]
	}
	if account != "" {
		if c.UserName, err = syscall.UTF16PtrFromString(account); err != nil {
			return err
		}
	}
	err = winsys.CredWrite(&c)
	runtime.KeepAlive(blob)
	if err != nil {
		return winError(err)
	}
	return nil
}

// stored is what CredReadW returned, copied out of its buffer.
type stored struct {
	blob         []byte
	typ, persist uint32
	user         string
}

// readCredential copies the item and zeroes the API's buffer before freeing it.
func readCredential(target string) (stored, error) {
	p, err := winsys.CredRead(target, credTypeGeneric)
	if err != nil {
		return stored{}, winError(err)
	}
	defer winsys.CredFree(p)
	n := p.CredentialBlobSize
	var src []byte
	if n > 0 && p.CredentialBlob != nil {
		src = unsafe.Slice(p.CredentialBlob, n)
		defer clear(src)
	}
	if n > maxBlob {
		return stored{}, fmt.Errorf("the item is %d bytes, more than the %d Credential Manager allows", n, maxBlob)
	}
	s := stored{blob: append([]byte(nil), src...), typ: p.Type, persist: p.Persist}
	if p.UserName != nil {
		s.user = winsys.UTF16PtrToString(p.UserName)
	}
	return s, nil
}

func winError(e error) error {
	var errno syscall.Errno
	if !errors.As(e, &errno) || errno == 0 {
		return syscall.EINVAL
	}
	switch errno {
	case errorNotFound:
		return ErrNotFound
	case errorNoSuchLogonSession:
		return errNoLogonSession
	}
	return errno
}
