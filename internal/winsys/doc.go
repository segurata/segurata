// Package winsys holds the Win32 calls segurata needs and the syscall package lacks. Every DLL is
// loaded by its absolute System32 path, never through the LoadLibrary search order, and every
// wrapper only marshals: the logic that decides anything lives in its caller.
package winsys
