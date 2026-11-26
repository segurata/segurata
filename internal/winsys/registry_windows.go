//go:build windows

package winsys

import (
	"syscall"
	"unsafe"
)

const errorNoMoreItems syscall.Errno = 259

var procRegEnumValueW = newProc(advapi32, "RegEnumValueW")

// RegValue is one value of a registry key, its data as stored.
type RegValue struct {
	Name string
	Type uint32
	Data []byte
}

// RegValues reads every value of the key at path under root, opened for reading only.
func RegValues(root syscall.Handle, path string) ([]RegValue, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(root, p, 0, syscall.KEY_QUERY_VALUE, &key); err != nil {
		return nil, err
	}
	defer syscall.RegCloseKey(key)
	var maxName, maxData uint32
	if err := syscall.RegQueryInfoKey(key, nil, nil, nil, nil, nil, nil, nil, &maxName, &maxData, nil, nil); err != nil {
		return nil, err
	}
	var out []RegValue
	for i := uint32(0); ; i++ {
		name := make([]uint16, maxName+1)
		data := make([]byte, maxData+2)
		nameLen, dataLen := uint32(len(name)), uint32(len(data))
		var typ uint32
		err := procRegEnumValueW.status(uintptr(key), uintptr(i), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)),
			0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&dataLen)))
		if err == errorNoMoreItems {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, RegValue{Name: syscall.UTF16ToString(name[:nameLen]), Type: typ, Data: data[:dataLen]})
	}
}
