//go:build windows

package winsys

import (
	"syscall"
	"unsafe"
)

const (
	cchRMSessionKey = 32 // CCH_RM_SESSION_KEY
	errorMoreData   = syscall.Errno(234)
)

var (
	procRmStartSession      = newProc(rstrtmgr, "RmStartSession")
	procRmRegisterResources = newProc(rstrtmgr, "RmRegisterResources")
	procRmGetList           = newProc(rstrtmgr, "RmGetList")
	procRmEndSession        = newProc(rstrtmgr, "RmEndSession")
)

// rmProcessInfo is RM_PROCESS_INFO.
type rmProcessInfo struct {
	ProcessID        uint32
	ProcessStartTime syscall.Filetime
	AppName          [256]uint16
	ServiceShortName [64]uint16
	ApplicationType  int32
	AppStatus        uint32
	TSSessionID      uint32
	Restartable      int32
}

// Holder is a process the Restart Manager reports holding one of the files asked about.
type Holder struct {
	PID     uint32
	AppName string
}

// FileHolders asks the Restart Manager which processes hold any of paths open. It answers for the
// set, not per file.
func FileHolders(paths []string) ([]Holder, error) {
	var session uint32
	var key [cchRMSessionKey + 1]uint16
	if err := procRmStartSession.status(uintptr(unsafe.Pointer(&session)), 0, uintptr(unsafe.Pointer(&key[0]))); err != nil {
		return nil, err
	}
	defer procRmEndSession.status(uintptr(session))
	if len(paths) == 0 {
		return nil, nil
	}
	names := make([]*uint16, len(paths))
	for i, p := range paths {
		u, err := syscall.UTF16PtrFromString(p)
		if err != nil {
			return nil, err
		}
		names[i] = u
	}
	if err := procRmRegisterResources.status(uintptr(session), uintptr(len(names)), uintptr(unsafe.Pointer(&names[0])), 0, 0, 0, 0); err != nil {
		return nil, err
	}
	var infos []rmProcessInfo
	for {
		var needed, n uint32
		var reasons uint32
		n = uint32(len(infos))
		var first uintptr
		if n > 0 {
			first = uintptr(unsafe.Pointer(&infos[0]))
		}
		err := procRmGetList.status(uintptr(session), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&n)), first, uintptr(unsafe.Pointer(&reasons)))
		if err == errorMoreData {
			infos = make([]rmProcessInfo, needed)
			continue
		}
		if err != nil {
			return nil, err
		}
		out := make([]Holder, 0, n)
		for _, i := range infos[:n] {
			out = append(out, Holder{PID: i.ProcessID, AppName: syscall.UTF16ToString(i.AppName[:])})
		}
		return out, nil
	}
}
