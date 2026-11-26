//go:build windows

package winsys

import (
	"syscall"
	"unsafe"
)

const (
	CtrlBreakEvent  = 1   // CTRL_BREAK_EVENT
	CreateSuspended = 0x4 // CREATE_SUSPENDED

	processSetQuota = 0x100

	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x2000
	th32csSnapThread                  = 0x4
	threadSuspendResume               = 0x2
)

var (
	procCreateJobObjectW         = newProc(kernel32, "CreateJobObjectW")
	procSetInformationJobObject  = newProc(kernel32, "SetInformationJobObject")
	procAssignProcessToJobObject = newProc(kernel32, "AssignProcessToJobObject")
	procTerminateJobObject       = newProc(kernel32, "TerminateJobObject")
	procThread32First            = newProc(kernel32, "Thread32First")
	procThread32Next             = newProc(kernel32, "Thread32Next")
	procOpenThread               = newProc(kernel32, "OpenThread")
	procResumeThread             = newProc(kernel32, "ResumeThread")
	procGenerateConsoleCtrlEvent = newProc(kernel32, "GenerateConsoleCtrlEvent")
)

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobBasicLimits struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

// jobExtendedLimits is JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
type jobExtendedLimits struct {
	Basic                 jobBasicLimits
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// threadEntry is THREADENTRY32.
type threadEntry struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// NewKillOnCloseJob creates an anonymous job object whose processes all end when its last handle
// closes.
func NewKillOnCloseJob() (syscall.Handle, error) {
	h, err := procCreateJobObjectW.call(0, 0)
	if h == 0 {
		return 0, err
	}
	var info jobExtendedLimits
	info.Basic.LimitFlags = jobObjectLimitKillOnJobClose
	if err := procSetInformationJobObject.bool(h, jobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); err != nil {
		syscall.CloseHandle(syscall.Handle(h))
		return 0, err
	}
	return syscall.Handle(h), nil
}

// OpenForJob opens a process with the rights AssignToJob needs.
func OpenForJob(pid uint32) (syscall.Handle, error) {
	return syscall.OpenProcess(processSetQuota|syscall.PROCESS_TERMINATE, false, pid)
}

// AssignToJob puts a process, opened with OpenForJob, in a job.
func AssignToJob(job, process syscall.Handle) error {
	return procAssignProcessToJobObject.bool(uintptr(job), uintptr(process))
}

// TerminateJob ends every process in the job.
func TerminateJob(job syscall.Handle, code uint32) error {
	return procTerminateJobObject.bool(uintptr(job), uintptr(code))
}

// Threads lists the IDs of a process's threads.
func Threads(pid uint32) ([]uint32, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(th32csSnapThread, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)
	var ids []uint32
	e := threadEntry{}
	e.Size = uint32(unsafe.Sizeof(e))
	for err := procThread32First.bool(uintptr(snap), uintptr(unsafe.Pointer(&e))); err == nil; err = procThread32Next.bool(uintptr(snap), uintptr(unsafe.Pointer(&e))) {
		if e.OwnerProcessID == pid {
			ids = append(ids, e.ThreadID)
		}
	}
	return ids, nil
}

// ResumeThread resumes a suspended thread.
func ResumeThread(tid uint32) error {
	h, err := procOpenThread.call(threadSuspendResume, 0, uintptr(tid))
	if h == 0 {
		return err
	}
	defer syscall.CloseHandle(syscall.Handle(h))
	if r, err := procResumeThread.call(h); r == uintptr(0xffffffff) {
		return err
	}
	return nil
}

// GenerateConsoleCtrlEvent sends event to the process group group on this console.
func GenerateConsoleCtrlEvent(event, group uint32) error {
	return procGenerateConsoleCtrlEvent.bool(uintptr(event), uintptr(group))
}
