//go:build !unix

package proc

import "os/exec"

// ownGroup does nothing: Windows has no process groups to kill.
func ownGroup(*exec.Cmd) {}
