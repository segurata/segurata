//go:build windows

package windows

import (
	"encoding/binary"
	"strconv"
	"syscall"
	"unsafe"
)

// keyWOW64_64Key reads the native view of HKLM\SOFTWARE whatever the binary's architecture.
const keyWOW64_64Key = 0x0100

// sysRegistry reads the live registry through the syscall package, never writing.
type sysRegistry struct{}

func openKey(hive Hive, path string) (syscall.Handle, error) {
	root := syscall.Handle(syscall.HKEY_LOCAL_MACHINE)
	if hive == HKCU {
		root = syscall.HKEY_CURRENT_USER
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var k syscall.Handle
	if err := syscall.RegOpenKeyEx(root, p, 0, syscall.KEY_QUERY_VALUE|keyWOW64_64Key, &k); err != nil {
		return 0, err
	}
	return k, nil
}

func (sysRegistry) Has(hive Hive, path, name string) (bool, error) {
	k, err := openKey(hive, path)
	if err != nil {
		return false, err
	}
	defer syscall.RegCloseKey(k)
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	// No data buffer: the call reports the value's type and size and copies nothing.
	var typ, size uint32
	switch err := syscall.RegQueryValueEx(k, n, nil, &typ, nil, &size); err {
	case nil:
		return true, nil
	case syscall.ERROR_FILE_NOT_FOUND:
		return false, nil
	default:
		return false, err
	}
}

func (sysRegistry) Read(hive Hive, path string, names ...string) (map[string]RegValue, error) {
	k, err := openKey(hive, path)
	if err != nil {
		return nil, err
	}
	defer syscall.RegCloseKey(k)
	out := map[string]RegValue{}
	for _, name := range names {
		v, ok, err := queryValue(k, name)
		if err != nil {
			return nil, err
		}
		if ok {
			out[name] = v
		}
	}
	return out, nil
}

func queryValue(k syscall.Handle, name string) (RegValue, bool, error) {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return RegValue{}, false, err
	}
	var typ, size uint32
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, nil, &size); err == syscall.ERROR_FILE_NOT_FOUND {
		return RegValue{}, false, nil
	} else if err != nil {
		return RegValue{}, false, err
	}
	buf := make([]byte, size+2)
	size = uint32(len(buf))
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, &buf[0], &size); err != nil {
		return RegValue{}, false, err
	}
	buf = buf[:size]
	v := RegValue{Type: typ}
	switch typ {
	case regSZ, regExpandSZ:
		if len(buf) < 2 {
			break
		}
		u := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), len(buf)/2)
		v.Text = syscall.UTF16ToString(u)
	case regDWORD:
		if len(buf) >= 4 {
			v.Text = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(buf)), 10)
		}
	case regQWORD:
		if len(buf) >= 8 {
			v.Text = strconv.FormatUint(binary.LittleEndian.Uint64(buf), 10)
		}
	}
	return v, true, nil
}
