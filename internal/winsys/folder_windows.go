//go:build windows

package winsys

import (
	"syscall"
	"unsafe"
)

// FolderIDDocuments is FOLDERID_Documents, the user's Documents folder wherever it was redirected.
var FolderIDDocuments = syscall.GUID{Data1: 0xFDD39AD0, Data2: 0x238F, Data3: 0x46AF, Data4: [8]byte{0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7}}

// FolderIDLocalAppData is FOLDERID_LocalAppData, the user's local application data folder.
var FolderIDLocalAppData = syscall.GUID{Data1: 0xF1B32785, Data2: 0x6FBA, Data3: 0x4FCF, Data4: [8]byte{0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91}}

var (
	procSHGetKnownFolderPath = newProc(shell32, "SHGetKnownFolderPath")
	procCoTaskMemFree        = newProc(ole32, "CoTaskMemFree")
)

// KnownFolderPath is the current user's path of a known folder.
func KnownFolderPath(id *syscall.GUID) (string, error) {
	var p *uint16
	err := procSHGetKnownFolderPath.status(uintptr(unsafe.Pointer(id)), 0, 0, uintptr(unsafe.Pointer(&p)))
	// The buffer is the caller's to free, even when the call fails.
	defer procCoTaskMemFree.call(uintptr(unsafe.Pointer(p)))
	if err != nil {
		return "", err
	}
	return utf16Ptr(p), nil
}
